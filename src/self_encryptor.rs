// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{SelfEncryptionError, Storage, COMPRESSION_QUALITY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use crate::{
    data_map::{ChunkDetails, DataMap},
    encryption::{self, IV_SIZE, KEY_SIZE},
    sequencer::Sequencer,
    sequential::{Iv, Key},
};
use brotli::{self, enc::BrotliEncoderParams};
use futures::{future::join_all, lock::Mutex, Future};
use std::{
    cmp,
    fmt::{self, Debug, Formatter},
    io::Cursor,
    iter,
    pin::Pin,
    sync::Arc,
};

const HASH_SIZE: usize = 32;
const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

struct Pad(pub [u8; PAD_SIZE]);

// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
fn xor(data: &[u8], &Pad(pad): &Pad) -> Vec<u8> {
    data.iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect()
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum ChunkStatus {
    ToBeHashed,
    ToBeEncrypted,
    AlreadyEncrypted,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct Chunk {
    status: ChunkStatus,
    in_sequencer: bool,
}

impl Chunk {
    fn flag_for_encryption(&mut self) {
        if self.status == ChunkStatus::AlreadyEncrypted {
            self.status = ChunkStatus::ToBeEncrypted;
        }
    }
}

/// This is the encryption object and all file handling should be done using this object as the low
/// level mechanism to read and write *content*.  This library has no knowledge of file metadata.
#[derive(Debug)]
pub struct SelfEncryptor<S: Storage + Send + Sync + Clone + 'static>(Arc<Mutex<State<S>>>);

impl<S> SelfEncryptor<S>
where
    S: Storage + Send + Sync + Clone + 'static,
{
    /// This is the only constructor for an encryptor object.  Each `SelfEncryptor` is used for a
    /// single file.  The parameters are a `Storage` object and a `DataMap`.  For a file which has
    /// not previously been self_encrypted, use `DataMap::None`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(storage: S, data_map: DataMap) -> Result<SelfEncryptor<S>, SelfEncryptionError> {
        let file_size = data_map.len();
        let mut sequencer = Sequencer::new();
        let sorted_map;
        let chunks;
        match data_map {
            DataMap::Content(content) => {
                sequencer.extend_from_slice(&content);
                sorted_map = vec![];
                chunks = vec![];
            }
            DataMap::Chunks(mut sorted_chunks) => {
                DataMap::chunks_sort(&mut sorted_chunks);
                let c = Chunk {
                    status: ChunkStatus::AlreadyEncrypted,
                    in_sequencer: false,
                };
                chunks = vec![c; sorted_chunks.len()];
                sorted_map = sorted_chunks;
            }
            DataMap::None => {
                sorted_map = vec![];
                chunks = vec![];
            }
        }

        Ok(SelfEncryptor(Arc::new(Mutex::new(State {
            storage,
            sorted_map,
            chunks,
            sequencer,
            file_size,
        }))))
    }

    /// Write method mirrors a POSIX type write mechanism.  It loosely mimics a filesystem interface
    /// for easy connection to FUSE-like programs as well as fine grained access to system level
    /// libraries for developers.  The input `data` will be written from the specified `position`
    /// (starts from 0).
    pub async fn write(&self, data: &[u8], position: usize) -> Result<(), SelfEncryptionError> {
        prepare_window_for_writing(Arc::clone(&self.0), position, data.len()).await?;

        {
            let mut state = self.0.lock().await;
            for (p, byte) in state.sequencer.iter_mut().skip(position).zip(data.to_vec()) {
                *p = byte;
            }
        }

        flush_after_write(Arc::clone(&self.0), position, data.len()).await?;
        Ok(())
    }

    /// The returned content is read from the specified `position` with specified `length`.  Trying
    /// to read beyond the file size will cause the encryptor to return content filled with `0u8`s
    /// in the gap (file size isn't affected).  Any other unwritten gaps will also be filled with
    /// '0u8's.
    pub async fn read(
        &self,
        position: usize,
        length: usize,
    ) -> Result<Vec<u8>, SelfEncryptionError> {
        prepare_window_for_reading(Arc::clone(&self.0), position, length).await?;

        let state = self.0.lock().await;
        Ok(state
            .sequencer
            .iter()
            .skip(position)
            .take(length)
            .cloned()
            .collect())
    }

    /// Delete all the chunks from the storage
    pub async fn delete(self) -> Result<S, SelfEncryptionError> {
        let state = self.take().await;
        let mut storage = state.storage;

        for chunk in &state.sorted_map {
            storage.delete(&chunk.hash).await?;
        }

        Ok(storage)
    }

    /// This function returns a `DataMap`, which is the info required to recover encrypted content
    /// from data storage location.  Content temporarily held in the encryptor will only get flushed
    /// into storage when this function gets called.
    pub async fn close(self) -> Result<(DataMap, S), SelfEncryptionError> {
        let file_size = {
            let state = self.0.lock().await;
            state.file_size
        };
        let num_chunks = get_num_chunks(file_size);

        if file_size == 0 {
            let storage = self.into_storage().await;
            return Ok((DataMap::None, storage));
        }

        if file_size < 3 * MIN_CHUNK_SIZE {
            let state = self.take().await;
            let content = (*state.sequencer)[..state.file_size].to_vec();
            let storage = state.storage;

            return Ok((DataMap::Content(content), storage));
        }

        for i in 0..num_chunks {
            let prepare = {
                let state = self.0.lock().await;
                !state.chunks[i].in_sequencer
                    && state.chunks[i].status != ChunkStatus::AlreadyEncrypted
            };
            if prepare {
                prepare_chunk_for_reading(Arc::clone(&self.0), i).await?;
            }
        }
        // create data map
        let the_data_map = {
            let mut state = self.0.lock().await;
            state.create_data_map().await?
        };

        let storage = self.into_storage().await;
        Ok((the_data_map, storage))
    }

    /// Current file size as is known by encryptor.
    pub async fn len(&self) -> usize {
        self.0.lock().await.file_size
    }

    /// Returns true if file size as is known by encryptor == 0.
    pub async fn is_empty(&self) -> bool {
        self.0.lock().await.file_size == 0
    }

    /// Consume this encryptor and return its storage.
    pub async fn into_storage(self) -> S {
        Arc::try_unwrap(self.0).unwrap().into_inner().storage
    }

    /// Consume this encryptor and return its State.
    async fn take(self) -> State<S> {
        Arc::try_unwrap(self.0).unwrap().into_inner()
    }
}

struct State<S: Storage + Send + Sync + Clone> {
    storage: S,
    sorted_map: Vec<ChunkDetails>, // the original data_map, sorted
    chunks: Vec<Chunk>,            // this is sorted as well
    sequencer: Sequencer,
    file_size: usize,
}

impl<S> State<S>
where
    S: Storage + 'static + Send + Sync + Clone,
{
    fn extend_sequencer_up_to(&mut self, new_len: usize) {
        let old_len = self.sequencer.len();
        if new_len > old_len {
            self.sequencer
                .extend(iter::repeat(0).take(new_len - old_len));
        }
    }

    #[allow(clippy::needless_range_loop)]
    async fn create_data_map(&mut self) -> Result<DataMap, SelfEncryptionError> {
        let num_chunks = get_num_chunks(self.file_size);
        let mut new_map = vec![ChunkDetails::new(); num_chunks];

        for i in 0..num_chunks {
            if self.chunks[i].status != ChunkStatus::ToBeHashed {
                new_map[i].chunk_num = i;
                new_map[i].hash.clear();
                new_map[i].pre_hash = self.sorted_map[i].pre_hash.clone();
                new_map[i].source_size = self.sorted_map[i].source_size;
            } else {
                let this_size = get_chunk_size(self.file_size, i);
                let pos = get_start_end_positions(self.file_size, i).0;
                assert!(this_size > 0);
                let name = self
                    .storage
                    .generate_address(&(*self.sequencer)[pos..pos + this_size])
                    .await?;
                new_map[i].chunk_num = i;
                new_map[i].hash.clear();
                new_map[i].pre_hash = name.to_vec();
                new_map[i].source_size = this_size;
            }
        }

        // let mut network_storage_futures = vec![];
        for i in 0..num_chunks {
            if self.chunks[i].status == ChunkStatus::AlreadyEncrypted {
                new_map[i].hash = self.sorted_map[i].hash.clone();
            } else {
                let this_size = get_chunk_size(self.file_size, i);
                let pos = get_start_end_positions(self.file_size, i).0;

                assert!(this_size > 0);
                let pki = get_pad_key_and_iv(i, &new_map, self.file_size);
                let content = match encrypt_chunk(&(*self.sequencer)[pos..pos + this_size], pki) {
                    Ok(content) => content,
                    Err(error) => return Err(error),
                };
                let name = self.storage.generate_address(&content).await?;

                new_map[i].hash = name.to_vec();
                self.storage.put(name.to_vec(), content).await?;
                // let mut storage = self.storage.clone();
                // network_storage_futures.push(async move { storage.put(name.to_vec(), content).await });
            }
        }
        // let results = join_all(network_storage_futures.into_iter()).await;
        // for result in results {
        //     result?;
        // }
        Ok(DataMap::Chunks(new_map))
    }
}

impl<S: Storage + Send + Sync + Clone> Debug for State<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SelfEncryptor internal state")
    }
}

async fn prepare_window_for_writing<S>(
    state: Arc<Mutex<State<S>>>,
    position: usize,
    length: usize,
) -> Result<(), SelfEncryptionError>
where
    S: Storage + 'static + Send + Sync + Clone,
{
    let (chunks_start, chunks_end, next_two) = {
        let mut state = state.lock().await;

        let current_num_chunks = get_num_chunks(state.file_size);

        let (chunks_start, chunks_end) = overlapped_chunks(state.file_size, position, length);
        if chunks_start == chunks_end {
            state.extend_sequencer_up_to(position + length);
            return Ok(());
        }

        // Two more chunks need to be decrypted for re-encryption.
        let next_two = [
            chunks_end % current_num_chunks,
            (chunks_end + 1) % current_num_chunks,
        ];

        let required_len = {
            let mut end = get_start_end_positions(state.file_size, chunks_end - 1).1;
            end = cmp::max(end, get_start_end_positions(state.file_size, next_two[0]).1);
            end = cmp::max(end, get_start_end_positions(state.file_size, next_two[1]).1);
            cmp::max(position + length, end)
        };

        state.extend_sequencer_up_to(required_len);

        (chunks_start, chunks_end, next_two)
    };

    // Middle chunks don't need decrypting since they'll get overwritten.
    // TODO If first/last chunk gets completely overwritten, no need to decrypt.
    let mut decryption_futures = Vec::new();
    let mut positions = Vec::new();
    let mut decrypted_chunks = Vec::new();
    {
        let mut state = state.lock().await;
        for &i in [chunks_start, chunks_end - 1].iter().chain(&next_two) {
            if state.chunks[i].in_sequencer {
                continue;
            }
            state.chunks[i].in_sequencer = true;
            positions.push(get_start_end_positions(state.file_size, i).0);
            decryption_futures.push(decrypt_chunk(&mut *state, i).await);
        }
    }
    let decrypted_data = join_all(decryption_futures).await;
    let mut pos_iter = positions.into_iter();
    for chunk in decrypted_data {
        decrypted_chunks.push((chunk?, pos_iter.next().unwrap_or(0)))
    }

    let mut state = state.lock().await;
    for (vec, pos) in decrypted_chunks {
        for (p, byte) in state.sequencer.iter_mut().skip(pos).zip(vec) {
            *p = byte;
        }
    }

    for chunk in &mut state.chunks[chunks_start..chunks_end] {
        chunk.status = ChunkStatus::ToBeHashed;
        chunk.in_sequencer = true;
    }

    for &i in &next_two {
        state.chunks[i].flag_for_encryption();
    }

    Ok(())
}

async fn flush_after_write<S>(
    state: Arc<Mutex<State<S>>>,
    position: usize,
    length: usize,
) -> Result<(), SelfEncryptionError>
where
    S: Storage + 'static + Send + Sync + Clone,
{
    let old_size = {
        let state = state.lock().await;
        state.file_size
    };

    let new_size = cmp::max(old_size, position + length);

    // When the updated size is more less than minimum size, we don't convert into chunks
    if new_size < 3 * MIN_CHUNK_SIZE {
        let mut state = state.lock().await;
        state.file_size = new_size;
        return Ok(());
    }

    // If the updated size is more than original size, the first two chunks need to be decrypted
    // and re-encrypted.
    if new_size > old_size && old_size >= 3 * MIN_CHUNK_SIZE {
        prepare_chunk_for_reading(Arc::clone(&state), 0).await?;
        prepare_chunk_for_reading(Arc::clone(&state), 1).await?;
        let mut state = state.lock().await;
        state.chunks[0].flag_for_encryption();
        state.chunks[1].flag_for_encryption();
    }

    // Among the existing chunks, get the start and end index of chunks which got resized due
    // to chunk resizing because of our chunk sizing
    let (resized_start, resized_end) = resized_chunks(old_size, new_size);

    if resized_start != resized_end {
        let byte_start = get_start_end_positions(old_size, resized_start).0;
        prepare_window_for_reading(Arc::clone(&state), byte_start, old_size - byte_start).await?;
        {
            let mut state = state.lock().await;
            for i in resized_start..resized_end {
                state.chunks[i].status = ChunkStatus::ToBeHashed;
            }
        }
    }

    let current_num_chunks = get_num_chunks(old_size);
    let new_num_chunks = get_num_chunks(new_size);

    // Push empty chunk descriptors if the number of chunks required increase.
    if new_num_chunks > current_num_chunks {
        let mut state = state.lock().await;
        for i in current_num_chunks..new_num_chunks {
            state.chunks.push(Chunk {
                status: ChunkStatus::ToBeHashed,
                in_sequencer: true,
            });
            state.sorted_map.push(ChunkDetails {
                chunk_num: i,
                hash: vec![],
                pre_hash: vec![],
                source_size: 0,
            });
        }
    }

    let mut state = state.lock().await;
    state.file_size = new_size;

    // Hash all the chunks that need to be hashed (this generates keys for the next chunks)
    for i in 0..new_num_chunks {
        let chunk_size = get_chunk_size(new_size, i);
        let pos = get_start_end_positions(new_size, i).0;
        if state.chunks[i].status == ChunkStatus::ToBeHashed {
            let name = state
                .storage
                .generate_address(&(*state.sequencer)[pos..pos + chunk_size])
                .await?;
            state.sorted_map[i].pre_hash = name.to_vec();
            state.sorted_map[i].source_size = chunk_size;
        }
    }

    // Encrypt and flush all the chunks, except the first and last two, to the network
    for i in 0..new_num_chunks {
        if state.chunks[i].status == ChunkStatus::AlreadyEncrypted
            || i < 2
            || i >= new_num_chunks - 2
        {
            continue;
        }

        let chunk_size = get_chunk_size(new_size, i);
        let pos = get_start_end_positions(new_size, i).0;

        state.sorted_map[i].chunk_num = i;
        state.sorted_map[i].hash.clear();

        let pki = get_pad_key_and_iv(i, &state.sorted_map, state.file_size);
        let content = encrypt_chunk(&(*state.sequencer)[pos..pos + chunk_size], pki)?;
        let name = state.storage.generate_address(&content).await?;

        state.storage.put(name.to_vec(), content).await?;

        state.sorted_map[i].hash = name.to_vec();
        state.chunks[i].status = ChunkStatus::AlreadyEncrypted;
    }

    Ok(())
}

async fn prepare_window_for_reading<S>(
    state: Arc<Mutex<State<S>>>,
    position: usize,
    length: usize,
) -> Result<(), SelfEncryptionError>
where
    S: Storage + 'static + Send + Sync + Clone,
{
    let (chunks_start, chunks_end) = {
        let state = state.lock().await;
        overlapped_chunks(state.file_size, position, length)
    };

    if chunks_start == chunks_end {
        let mut state = state.lock().await;
        state.extend_sequencer_up_to(position + length);
        return Ok(());
    }

    {
        let mut state = state.lock().await;
        let required_len = {
            let end = get_start_end_positions(state.file_size, chunks_end - 1).1;
            cmp::max(position + length, end)
        };

        state.extend_sequencer_up_to(required_len);
    }
    let mut decryption_futures = Vec::new();
    let mut positions = Vec::new();
    let mut decrypted_chunks = Vec::new();
    let mut state = state.lock().await;
    for i in chunks_start..chunks_end {
        if state.chunks[i].in_sequencer {
            continue;
        }
        state.chunks[i].in_sequencer = true;
        positions.push(get_start_end_positions(state.file_size, i).0);
        decryption_futures.push(decrypt_chunk(&mut *state, i).await);
    }

    let chunks = join_all(decryption_futures.into_iter()).await;
    let mut pos_iter = positions.into_iter();
    for chunk in chunks {
        decrypted_chunks.push((chunk.unwrap(), pos_iter.next().unwrap_or(0)))
    }

    for (vec, pos) in &decrypted_chunks {
        for (p, byte) in state.sequencer.iter_mut().skip(*pos).zip(vec) {
            *p = *byte
        }
    }

    Ok(())
}

async fn prepare_chunk_for_reading<S>(
    state: Arc<Mutex<State<S>>>,
    index: usize,
) -> Result<(), SelfEncryptionError>
where
    S: Storage + 'static + Send + Sync + Clone,
{
    let mut state = state.lock().await;
    if state.chunks[index].in_sequencer {
        return Ok(());
    }
    state.chunks[index].in_sequencer = true;
    let (pos, end) = get_start_end_positions(state.file_size, index);
    state.extend_sequencer_up_to(end);
    let chunk_data = decrypt_chunk(&mut *state, index).await.await?;

    for (p, byte) in state.sequencer.iter_mut().skip(pos).zip(chunk_data) {
        *p = byte;
    }

    Ok(())
}

async fn decrypt_chunk<S>(
    state: &mut State<S>,
    chunk_number: usize,
) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SelfEncryptionError>>>>
where
    S: Storage + 'static + Send + Sync + Clone,
{
    let name = state.sorted_map[chunk_number].hash.clone();
    let (pad, key, iv) = get_pad_key_and_iv(chunk_number, &state.sorted_map, state.file_size);

    let mut storage = state.storage.clone();

    Box::pin(async move {
        match storage.get(&name).await {
            Err(err) => Err(SelfEncryptionError::Storage(format!("{}", err))),
            Ok(content) => {
                let xor_result = xor(&content, &pad);
                let decrypted = encryption::decrypt(&xor_result, &key, &iv)?;
                let mut decompressed = vec![];
                brotli::BrotliDecompress(&mut Cursor::new(decrypted), &mut decompressed)
                    .map(|_| decompressed)
                    .map_err(|_| SelfEncryptionError::Compression)
            }
        }
    })
}

fn encrypt_chunk(content: &[u8], pki: (Pad, Key, Iv)) -> Result<Vec<u8>, SelfEncryptionError> {
    let (pad, key, iv) = pki;
    let mut compressed = vec![];
    let enc_params = BrotliEncoderParams {
        quality: COMPRESSION_QUALITY,
        ..Default::default()
    };
    let result = brotli::BrotliCompress(&mut Cursor::new(content), &mut compressed, &enc_params);
    if result.is_err() {
        return Err(SelfEncryptionError::Compression);
    }
    let encrypted = encryption::encrypt(&compressed, &key, &iv)?;
    Ok(xor(&encrypted, &pad))
}

fn get_pad_key_and_iv(
    chunk_number: usize,
    sorted_map: &[ChunkDetails],
    map_size: usize,
) -> (Pad, Key, Iv) {
    let n_1 = get_previous_chunk_number(map_size, chunk_number);
    let n_2 = get_previous_chunk_number(map_size, n_1);
    let this_pre_hash = &sorted_map[chunk_number].pre_hash;
    let n_1_pre_hash = &sorted_map[n_1].pre_hash;
    let n_2_pre_hash = &sorted_map[n_2].pre_hash;
    assert_eq!(n_1_pre_hash.len(), HASH_SIZE);
    assert_eq!(n_2_pre_hash.len(), HASH_SIZE);

    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in pad
        .iter_mut()
        .zip(this_pre_hash.iter().chain(n_2_pre_hash.iter()))
    {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().chain(iv.iter_mut()).zip(n_1_pre_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

// Returns the chunk range [start, end) that is overlapped by the byte range defined by `position`
// and `length`.  Returns empty range if file_size is so small that there are no chunks.
fn overlapped_chunks(file_size: usize, position: usize, length: usize) -> (usize, usize) {
    if file_size < (3 * MIN_CHUNK_SIZE) || position >= file_size || length == 0 {
        return (0, 0);
    }
    let start = get_chunk_number(file_size, position);
    let end_pos = position + length - 1; // inclusive
    let end = if end_pos < file_size {
        get_chunk_number(file_size, end_pos) + 1
    } else {
        get_num_chunks(file_size)
    };
    (start, end)
}

// Returns a chunk range [start, end) whose sizes are affected by a change in file size.
fn resized_chunks(old_size: usize, new_size: usize) -> (usize, usize) {
    if old_size == new_size || old_size < (3 * MIN_CHUNK_SIZE) {
        return (0, 0);
    }
    if old_size < (3 * MAX_CHUNK_SIZE) {
        return (0, 3);
    }
    if new_size > old_size {
        let remainder = old_size % MAX_CHUNK_SIZE;
        if remainder == 0 {
            return (0, 0);
        } else if remainder >= MIN_CHUNK_SIZE {
            let last = get_num_chunks(old_size) - 1;
            return (last, last + 1);
        } else {
            let last = get_num_chunks(old_size) - 1;
            return (last - 1, last + 1);
        }
    }

    // new_size is less than old_size, old_size is at least 3 * MAX_CHUNK_SIZE

    if new_size >= (3 * MAX_CHUNK_SIZE) {
        let remainder = new_size % MAX_CHUNK_SIZE;
        if remainder == 0 {
            return (0, 0);
        } else if remainder >= MIN_CHUNK_SIZE {
            let last = get_chunk_number(old_size, new_size - 1);
            return (last, last + 1);
        } else {
            let last = get_chunk_number(old_size, new_size - 1);
            return (last - 1, last + 1);
        }
    }
    if new_size > 0 {
        return (0, get_chunk_number(old_size, new_size - 1) + 1);
    }
    (0, 0)
}

// Returns the number of chunks according to file size.
fn get_num_chunks(file_size: usize) -> usize {
    if file_size < (3 * MIN_CHUNK_SIZE) {
        return 0;
    }
    if file_size < (3 * MAX_CHUNK_SIZE) {
        return 3;
    }
    if file_size % MAX_CHUNK_SIZE == 0 {
        file_size / MAX_CHUNK_SIZE
    } else {
        (file_size / MAX_CHUNK_SIZE) + 1
    }
}

// Returns the size of a chunk according to file size.
fn get_chunk_size(file_size: usize, chunk_number: usize) -> usize {
    if file_size < 3 * MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE {
        if chunk_number < 2 {
            return file_size / 3;
        } else {
            return file_size - (2 * (file_size / 3));
        }
    }
    if chunk_number < get_num_chunks(file_size) - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = file_size % MAX_CHUNK_SIZE;
    let penultimate = (get_num_chunks(file_size) - 2) == chunk_number;
    if remainder == 0 {
        return MAX_CHUNK_SIZE;
    }
    if remainder < MIN_CHUNK_SIZE {
        if penultimate {
            MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        } else {
            MIN_CHUNK_SIZE + remainder
        }
    } else if penultimate {
        MAX_CHUNK_SIZE
    } else {
        remainder
    }
}

// Returns the [start, end) half-open byte range of a chunk.
fn get_start_end_positions(file_size: usize, chunk_number: usize) -> (usize, usize) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start;
    let last = (get_num_chunks(file_size) - 1) == chunk_number;
    if last {
        start = get_chunk_size(file_size, 0) * (chunk_number - 1)
            + get_chunk_size(file_size, chunk_number - 1);
    } else {
        start = get_chunk_size(file_size, 0) * chunk_number;
    }
    (start, start + get_chunk_size(file_size, chunk_number))
}

fn get_previous_chunk_number(file_size: usize, chunk_number: usize) -> usize {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }
    (get_num_chunks(file_size) + chunk_number - 1) % get_num_chunks(file_size)
}

fn get_chunk_number(file_size: usize, position: usize) -> usize {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }

    let remainder = file_size % get_chunk_size(file_size, 0);
    if remainder == 0
        || remainder >= MIN_CHUNK_SIZE
        || position < file_size - remainder - MIN_CHUNK_SIZE
    {
        return position / get_chunk_size(file_size, 0);
    }
    get_num_chunks(file_size) - 1
}

#[cfg(test)]
mod tests {
    use super::{
        super::{DataMap, Storage, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE},
        get_chunk_number, get_chunk_size, get_num_chunks, get_previous_chunk_number,
        get_start_end_positions, SelfEncryptionError, SelfEncryptor,
    };
    use crate::test_helpers::{self, new_test_rng, random_bytes, SimpleStorage};

    use rand::{self, Rng};

    #[test]
    // Sorry
    #[allow(clippy::cognitive_complexity)]
    fn helper_functions() {
        let mut file_size = MIN_CHUNK_SIZE * 3;
        assert_eq!(get_num_chunks(file_size), 3);
        assert_eq!(get_chunk_size(file_size, 0), 1024);
        assert_eq!(get_chunk_size(file_size, 1), 1024);
        assert_eq!(get_chunk_size(file_size, 2), 1024);
        assert_eq!(get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0);
        assert_eq!(get_start_end_positions(file_size, 0).1, MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).0, MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).1, 2 * MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).0, 2 * MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).1, 3 * MIN_CHUNK_SIZE);

        file_size = (MIN_CHUNK_SIZE * 3) + 1;
        assert_eq!(get_num_chunks(file_size), 3);
        assert_eq!(get_chunk_size(file_size, 0), 1024);
        assert_eq!(get_chunk_size(file_size, 1), 1024);
        assert_eq!(get_chunk_size(file_size, 2), 1025);
        assert_eq!(get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0);
        assert_eq!(get_start_end_positions(file_size, 0).1, MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).0, MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).1, 2 * MIN_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).0, 2 * MIN_CHUNK_SIZE);
        assert_eq!(
            get_start_end_positions(file_size, 2).1,
            1 + 3 * MIN_CHUNK_SIZE
        );

        file_size = MAX_CHUNK_SIZE * 3;
        assert_eq!(get_num_chunks(file_size), 3);
        assert_eq!(get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 2), MAX_CHUNK_SIZE);
        assert_eq!(get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0);
        assert_eq!(get_start_end_positions(file_size, 0).1, MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).0, MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).1, 2 * MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).0, 2 * MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).1, 3 * MAX_CHUNK_SIZE);

        file_size = MAX_CHUNK_SIZE * 3 + 1;
        assert_eq!(get_num_chunks(file_size), 4);
        assert_eq!(get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(
            get_chunk_size(file_size, 2),
            MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        );
        assert_eq!(get_chunk_size(file_size, 3), MIN_CHUNK_SIZE + 1);
        assert_eq!(get_previous_chunk_number(file_size, 0), 3);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_previous_chunk_number(file_size, 3), 2);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0);
        assert_eq!(get_start_end_positions(file_size, 0).1, MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).0, MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).1, 2 * MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).0, 2 * MAX_CHUNK_SIZE);
        assert_eq!(
            get_start_end_positions(file_size, 2).1,
            ((3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE)
        );
        assert_eq!(
            get_start_end_positions(file_size, 3).0,
            get_start_end_positions(file_size, 2).1
        );
        assert_eq!(get_start_end_positions(file_size, 3).1, file_size);

        file_size = (MAX_CHUNK_SIZE * 7) + 1024;
        assert_eq!(get_num_chunks(file_size), 8);
        assert_eq!(get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 2), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 3), MAX_CHUNK_SIZE);
        assert_eq!(get_previous_chunk_number(file_size, 0), 7);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_previous_chunk_number(file_size, 3), 2);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0);
        assert_eq!(get_start_end_positions(file_size, 0).1, MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).0, MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 1).1, 2 * MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).0, 2 * MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 2).1, 3 * MAX_CHUNK_SIZE);
        assert_eq!(get_start_end_positions(file_size, 3).0, 3 * MAX_CHUNK_SIZE);
        assert_eq!(
            get_start_end_positions(file_size, 7).1,
            ((7 * MAX_CHUNK_SIZE) + 1024)
        );

        file_size = (MAX_CHUNK_SIZE * 11) - 1;
        assert_eq!(get_num_chunks(file_size), 11);
        assert_eq!(get_previous_chunk_number(file_size, 11), 10);

        file_size = (MAX_CHUNK_SIZE * 11) + 1;
        assert_eq!(get_num_chunks(file_size), 11 + 1);
        assert_eq!(get_previous_chunk_number(file_size, 11), 10);

        let mut number_of_chunks: usize = 11;
        file_size = (MAX_CHUNK_SIZE * number_of_chunks) + 1024;
        assert_eq!(get_num_chunks(file_size), number_of_chunks + 1);
        for i in 0..number_of_chunks {
            // preceding and next index, wrapped around
            let h = (i + number_of_chunks) % (number_of_chunks + 1);
            let j = (i + 1) % (number_of_chunks + 1);
            assert_eq!(get_chunk_size(file_size, i), MAX_CHUNK_SIZE);
            assert_eq!(get_previous_chunk_number(file_size, i), h);
            assert_eq!(get_start_end_positions(file_size, i).0, i * MAX_CHUNK_SIZE);
            assert_eq!(get_start_end_positions(file_size, i).1, j * MAX_CHUNK_SIZE);
        }
        assert_eq!(get_chunk_size(file_size, number_of_chunks), MIN_CHUNK_SIZE);
        assert_eq!(
            get_previous_chunk_number(file_size, number_of_chunks),
            number_of_chunks - 1
        );
        assert_eq!(
            get_start_end_positions(file_size, number_of_chunks).0,
            number_of_chunks * MAX_CHUNK_SIZE
        );
        assert_eq!(
            get_start_end_positions(file_size, number_of_chunks).1,
            ((number_of_chunks * MAX_CHUNK_SIZE) + 1024)
        );

        number_of_chunks = 100;
        file_size = MAX_CHUNK_SIZE * number_of_chunks;
        assert_eq!(get_num_chunks(file_size), number_of_chunks);
        for i in 0..number_of_chunks - 1 {
            // preceding and next index, wrapped around
            let h = (i + number_of_chunks - 1) % number_of_chunks;
            let j = (i + 1) % number_of_chunks;
            assert_eq!(get_chunk_size(file_size, i), MAX_CHUNK_SIZE);
            assert_eq!(get_previous_chunk_number(file_size, i), h);
            assert_eq!(get_start_end_positions(file_size, i).0, i * MAX_CHUNK_SIZE);
            assert_eq!(get_start_end_positions(file_size, i).1, j * MAX_CHUNK_SIZE);
        }
        assert_eq!(
            get_previous_chunk_number(file_size, number_of_chunks),
            number_of_chunks - 1
        );
        assert_eq!(
            get_start_end_positions(file_size, number_of_chunks).0,
            number_of_chunks * MAX_CHUNK_SIZE
        );
        assert_eq!(
            get_start_end_positions(file_size, number_of_chunks - 1).1,
            number_of_chunks * MAX_CHUNK_SIZE
        );
    }

    async fn check_file_size<S: Storage + Send + Sync + Clone>(
        se: &SelfEncryptor<S>,
        expected_file_size: usize,
    ) {
        let state = se.0.lock().await;
        assert_eq!(state.file_size, expected_file_size);
        if !state.sorted_map.is_empty() {
            let chunks_cumulated_size = state
                .sorted_map
                .iter()
                .fold(0, |acc, chunk| acc + chunk.source_size);
            assert_eq!(chunks_cumulated_size, expected_file_size);
        }
    }

    #[test]
    fn xor() {
        let mut data: Vec<u8> = vec![];
        let mut pad = [0u8; super::PAD_SIZE];
        for _ in 0..800 {
            data.push(rand::random::<u8>());
        }
        for ch in pad.iter_mut() {
            *ch = rand::random::<u8>();
        }
        assert_eq!(
            data,
            super::xor(&super::xor(&data, &super::Pad(pad)), &super::Pad(pad))
        );
    }

    #[tokio::test]
    async fn write() -> Result<(), SelfEncryptionError> {
        let storage = SimpleStorage::new();
        let se = SelfEncryptor::new(storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        let size = 3;
        let offset = 5;
        let mut rng: rand_chacha::ChaCha20Rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, size);
        se.write(&the_bytes, offset)
            .await
            .expect("Writing to encryptor shouldn't fail.");
        check_file_size(&se, size + offset).await;
        Ok(())
    }

    #[tokio::test]
    async fn delete() -> Result<(), SelfEncryptionError> {
        let storage = SimpleStorage::new();
        let se = SelfEncryptor::new(storage, DataMap::None)?;
        let size = 4000;
        let mut rng: rand_chacha::ChaCha20Rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, size);
        se.write(&the_bytes, 0).await?;

        let (data_map, mut storage) = se.close().await?;
        let reference_data_map = data_map.clone();

        match &reference_data_map {
            DataMap::Chunks(chunks) => {
                for chunk in chunks {
                    if storage.get(&chunk.hash).await.is_err() {
                        return Err(SelfEncryptionError::Generic("Missing Chunk".to_string()));
                    }
                }
            }
            DataMap::None | DataMap::Content(_) => {
                return Err(SelfEncryptionError::Generic(
                    "shall return DataMap::Chunks".to_string(),
                ));
            }
        }

        let se = SelfEncryptor::new(storage, data_map)?;

        let mut storage = se.delete().await?;

        match &reference_data_map {
            DataMap::Chunks(chunks) => {
                for chunk in chunks {
                    if storage.get(&chunk.hash).await.is_ok() {
                        return Err(SelfEncryptionError::Generic("Unexpected Chunk".to_string()));
                    }
                }
            }
            DataMap::None | DataMap::Content(_) => {
                return Err(SelfEncryptionError::Generic(
                    "shall return DataMap::Chunks".to_string(),
                ));
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn multiple_writes() -> Result<(), SelfEncryptionError> {
        let size1 = 3;
        let size2 = 4;
        let mut rng = new_test_rng()?;
        let part1 = random_bytes(&mut rng, size1);
        let part2 = random_bytes(&mut rng, size2);
        let data_map;

        {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            // Just testing multiple subsequent write calls
            se.write(&part1, 0).await?;
            se.write(&part2, size1).await?;
            // Let's also test an overwrite.. over middle bytes of part2
            se.write(&[4u8, 2], size1 + 1).await?;
            check_file_size(&se, size1 + size2).await;
            data_map = se.close().await?.0;
        }

        let storage = SimpleStorage::new();
        let se = SelfEncryptor::new(storage, data_map)?;
        let fetched = se.read(0, size1 + size2).await?;
        assert_eq!(&fetched[..size1], &part1[..]);
        assert_eq!(fetched[size1], part2[0]);
        assert_eq!(&fetched[size1 + 1..size1 + 3], &[4u8, 2][..]);
        assert_eq!(&fetched[size1 + 3..], &part2[3..]);
        Ok(())
    }

    #[tokio::test]
    async fn three_min_chunks_minus_one() -> Result<(), SelfEncryptionError> {
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE * 3) - 1;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);

        {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;

            {
                let state = se.0.lock().await;
                assert_eq!(state.sorted_map.len(), 0);
                assert_eq!(state.sequencer.len(), bytes_len);
            }
            check_file_size(&se, bytes_len).await;
            // check close
            data_map = se.close().await?.0;
        }
        match data_map {
            DataMap::Chunks(_) => panic!("shall not return DataMap::Chunks"),
            DataMap::Content(ref content) => assert_eq!(content.len(), bytes_len),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let storage = SimpleStorage::new();
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, bytes_len).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn three_min_chunks() -> Result<(), SelfEncryptionError> {
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, MIN_CHUNK_SIZE * 3);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;
            check_file_size(&se, MIN_CHUNK_SIZE * 3).await;
            let fetched = se.read(0, MIN_CHUNK_SIZE * 3).await?;
            assert_eq!(fetched, the_bytes);
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries().await?, 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, MIN_CHUNK_SIZE * 3).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn three_min_chunks_plus_one() -> Result<(), SelfEncryptionError> {
        let bytes_len = (MIN_CHUNK_SIZE * 3) + 1;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;
            check_file_size(&se, bytes_len).await;
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries().await?, 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, bytes_len).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn three_max_chunks() -> Result<(), SelfEncryptionError> {
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;
            check_file_size(&se, bytes_len).await;
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries().await?, 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, bytes_len).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn three_max_chunks_plus_one() -> Result<(), SelfEncryptionError> {
        let bytes_len = (MAX_CHUNK_SIZE * 3) + 1;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;
            check_file_size(&se, bytes_len).await;
            // check close
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                assert_eq!(storage.num_entries().await?, 4);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, bytes_len).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn seven_and_a_bit_max_chunks() -> Result<(), SelfEncryptionError> {
        let bytes_len = (MAX_CHUNK_SIZE * 7) + 1024;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;
            check_file_size(&se, bytes_len).await;
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 8);
                assert_eq!(storage.num_entries().await?, 8);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, bytes_len).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn large_file_one_byte_under_eleven_chunks() -> Result<(), SelfEncryptionError> {
        let number_of_chunks = 11;
        let bytes_len = (MAX_CHUNK_SIZE * number_of_chunks) - 1;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)?;
            se.write(&the_bytes, 0).await?;
            check_file_size(&se, bytes_len).await;
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks);
                assert_eq!(storage.num_entries().await?, number_of_chunks);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let new_se = SelfEncryptor::new(storage, data_map)?;
        let fetched = new_se.read(0, bytes_len).await?;
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn large_file_one_byte_over_eleven_chunks() -> Result<(), SelfEncryptionError> {
        let number_of_chunks = 11;
        let bytes_len = (MAX_CHUNK_SIZE * number_of_chunks) + 1;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .await
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len).await;
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks + 1);
                assert_eq!(storage.num_entries().await?, number_of_chunks + 1);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let new_se = SelfEncryptor::new(storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len)
            .await
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn large_file_size_1024_over_eleven_chunks() -> Result<(), SelfEncryptionError> {
        // has been tested for 50 chunks
        let number_of_chunks = 11;
        let bytes_len = (MAX_CHUNK_SIZE * number_of_chunks) + 1024;
        let mut rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .await
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len).await;
            // check close
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks + 1);
                assert_eq!(storage.num_entries().await?, number_of_chunks + 1);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let new_se = SelfEncryptor::new(storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len)
            .await
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn large_100mb_file() -> Result<(), SelfEncryptionError> {
        let number_of_chunks = 100;
        let bytes_len = MAX_CHUNK_SIZE * number_of_chunks;
        let mut rng = new_test_rng()?;
        let bytes = random_bytes(&mut rng, bytes_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&bytes, 0)
                .await
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len).await;
            se.close().await?
        };

        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks);
                assert_eq!(storage.num_entries().await?, number_of_chunks);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let new_se = SelfEncryptor::new(storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len)
            .await
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, bytes);
        Ok(())
    }

    #[tokio::test]
    async fn write_starting_with_existing_data_map() -> Result<(), SelfEncryptionError> {
        let part1_len = MIN_CHUNK_SIZE * 3;
        let mut rng = new_test_rng()?;
        let part1_bytes = random_bytes(&mut rng, part1_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&part1_bytes, 0)
                .await
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, part1_len).await;
            se.close().await?
        };

        let part2_len = 1024;
        let part2_bytes = random_bytes(&mut rng, part2_len);
        let full_len = part1_len + part2_len;
        let (data_map2, storage) = {
            // Start with an existing data_map.
            let se = SelfEncryptor::new(storage, data_map)?;
            se.write(&part2_bytes, part1_len).await?;
            // check_file_size(&se, full_len).await;
            se.close().await?
        };

        assert_eq!(data_map2.len(), full_len);

        let se = SelfEncryptor::new(storage, data_map2)?;
        let fetched = se.read(0, full_len).await?;
        assert_eq!(&part1_bytes[..], &fetched[..part1_len]);
        assert_eq!(&part2_bytes[..], &fetched[part1_len..]);
        Ok(())
    }

    #[tokio::test]
    async fn write_starting_with_existing_data_map2() -> Result<(), SelfEncryptionError> {
        let part1_len = MAX_CHUNK_SIZE * 3 - 24;
        let mut rng = new_test_rng()?;
        let part1_bytes = random_bytes(&mut rng, part1_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&part1_bytes, 0)
                .await
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, part1_len).await;
            se.close().await?
        };

        let part2_len = 1024;
        let part2_bytes = random_bytes(&mut rng, part2_len);
        let full_len = part1_len + part2_len;
        let (data_map2, storage) = {
            // Start with an existing data_map.
            let se = SelfEncryptor::new(storage, data_map)?;
            se.write(&part2_bytes, part1_len).await?;
            se.close().await?
        };

        assert_eq!(data_map2.len(), full_len);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                assert_eq!(storage.num_entries().await?, 7); // old ones + new ones
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash).await?);
                }
            }
            _ => panic!("data_map should be DataMap::Chunks"),
        }

        let se = SelfEncryptor::new(storage, data_map2)?;
        let fetched = se
            .read(0, full_len)
            .await
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&part1_bytes[..], &fetched[..part1_len]);
        assert_eq!(&part2_bytes[..], &fetched[part1_len..]);
        Ok(())
    }

    #[tokio::test]
    async fn overwrite_data_map_aligned() -> Result<(), SelfEncryptionError> {
        let mut rng = new_test_rng()?;
        let len = MAX_CHUNK_SIZE * 10;
        let content = random_bytes(&mut rng, len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&content, 0)
                .await
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, len).await;
            se.close().await?
        };
        let part2_len = MAX_CHUNK_SIZE * 3;
        let part2_bytes = random_bytes(&mut rng, part2_len);
        let (data_map2, storage) = {
            // Start with an existing data_map.
            let se = SelfEncryptor::new(storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            se.write(&part2_bytes, len)
                .await
                .expect("Writing part two to encryptor shouldn't fail.");
            se.close().await?
        };

        assert_eq!(data_map2.len(), (len + part2_len));

        let se = SelfEncryptor::new(storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se
            .read(0, len + part2_len)
            .await
            .expect("Reading from encryptor shouldn't fail.");

        assert_eq!(fetched[..len], content);
        assert_eq!(fetched[len..], part2_bytes);

        Ok(())
    }

    #[tokio::test]
    async fn overwrite_starting_with_existing_data_map() -> Result<(), SelfEncryptionError> {
        let part1_len = MAX_CHUNK_SIZE * 4;
        let mut rng = new_test_rng()?;
        let part1_bytes = random_bytes(&mut rng, part1_len);
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&part1_bytes, 0)
                .await
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, part1_len).await;
            se.close().await?
        };

        let part2_len = 2;
        let part2_bytes = random_bytes(&mut rng, part2_len);
        let (data_map2, storage) = {
            // Start with an existing data_map.
            let se = SelfEncryptor::new(storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            // Overwrite. This and next two chunks will have to be re-encrypted.
            se.write(&part2_bytes, 2)
                .await
                .expect("Writing part two to encryptor shouldn't fail.");
            se.close().await?
        };

        assert_eq!(data_map2.len(), part1_len);

        let se = SelfEncryptor::new(storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se
            .read(0, part1_len)
            .await
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&part1_bytes[..2], &fetched[..2]);
        assert_eq!(&part2_bytes[..], &fetched[2..2 + part2_len]);
        assert_eq!(&part1_bytes[2 + part2_len..], &fetched[2 + part2_len..]);
        Ok(())
    }

    async fn create_vector_data_map(
        vec_len: usize,
    ) -> Result<(DataMap, SimpleStorage), SelfEncryptionError> {
        let data: Vec<usize> = (0..vec_len).collect();
        let serialised_data: Vec<u8> = test_helpers::serialise(&data)?;
        let storage = SimpleStorage::new();
        let self_encryptor = SelfEncryptor::new(storage, DataMap::None)?;
        self_encryptor.write(&serialised_data, 0).await?;
        check_file_size(&self_encryptor, serialised_data.len()).await;

        Ok(self_encryptor.close().await?)
    }

    async fn check_vector_data_map(
        storage: SimpleStorage,
        vec_len: usize,
        data_map: &DataMap,
    ) -> Result<(), SelfEncryptionError> {
        let self_encryptor = SelfEncryptor::new(storage, data_map.clone())?;
        let length = self_encryptor.len().await;
        let data_to_deserialise = self_encryptor.read(0, length).await?;
        let data: Vec<usize> = test_helpers::deserialise(&data_to_deserialise)?;
        assert_eq!(data.len(), vec_len);
        for (index, data_char) in data.iter().enumerate() {
            assert_eq!(*data_char, index);
        }
        Ok(())
    }

    #[tokio::test]
    async fn serialised_vectors() -> Result<(), SelfEncryptionError> {
        for vec_len in &[1000, 2000, 5000, 10_000, 20_000, 50_000, 100_000, 200_000] {
            let (data_map, storage) = create_vector_data_map(*vec_len).await?;
            check_vector_data_map(storage, *vec_len, &data_map).await?;
        }
        Ok(())
    }

    #[test]
    fn chunk_number() -> Result<(), SelfEncryptionError> {
        const CHUNK_0_START: usize = 0;
        const CHUNK_0_END: usize = MAX_CHUNK_SIZE - 1;
        const CHUNK_1_START: usize = MAX_CHUNK_SIZE;
        const CHUNK_1_END: usize = (2 * MAX_CHUNK_SIZE) - 1;
        const CHUNK_2_START: usize = 2 * MAX_CHUNK_SIZE;

        // Test chunk_number for files up to 3 * MIN_CHUNK_SIZE - 1.  Should be 0 for all bytes.
        let mut min_test_size = 0;
        let mut max_test_size = 3 * MIN_CHUNK_SIZE;
        for file_size in min_test_size..max_test_size {
            for byte_index in 0..file_size {
                assert_eq!(get_chunk_number(file_size, byte_index), 0);
            }
        }

        // Test chunk_number for files up to 3 * MAX_CHUNK_SIZE.  File should be thirded with any
        // extra bytes appended to last chunk.
        min_test_size = max_test_size;
        max_test_size = (3 * MAX_CHUNK_SIZE) + 1;
        let mut rng = new_test_rng()?;
        let step = rng.gen_range(90_000, 100_000);
        for file_size in (min_test_size..max_test_size).filter(|&elt| elt % step == 0) {
            assert_eq!(get_num_chunks(file_size), 3);
            let mut index_start;
            let mut index_end = 0;
            for chunk_index in 0..3 {
                index_start = index_end;
                index_end += get_chunk_size(file_size, chunk_index);
                for byte_index in index_start..index_end {
                    assert_eq!(get_chunk_number(file_size, byte_index), chunk_index);
                }
            }
        }

        // Test chunk_number for files up to (3 * MAX_CHUNK_SIZE) + MIN_CHUNK_SIZE - 1.  First two
        // chunks should each have MAX_CHUNK_SIZE bytes, third chunk should have
        // (MAX_CHUNK_SIZE - MIN_CHUNK_SIZE) bytes, with final chunk containing remainder.
        min_test_size = max_test_size;
        max_test_size = (3 * MAX_CHUNK_SIZE) + MIN_CHUNK_SIZE;
        for file_size in min_test_size..max_test_size {
            const CHUNK_2_END: usize = (3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE - 1;
            assert_eq!(get_num_chunks(file_size), 4);
            let mut test_indices = vec![
                CHUNK_0_START,
                CHUNK_0_END,
                CHUNK_1_START,
                CHUNK_1_END,
                CHUNK_2_START,
                CHUNK_2_END,
            ];
            test_indices.append(&mut ((CHUNK_2_END + 1)..(file_size - 1)).collect::<Vec<_>>());
            for byte_index in test_indices {
                let expected_number = match byte_index {
                    CHUNK_0_START..=CHUNK_0_END => 0,
                    CHUNK_1_START..=CHUNK_1_END => 1,
                    CHUNK_2_START..=CHUNK_2_END => 2,
                    _ => 3,
                };
                assert_eq!(get_chunk_number(file_size, byte_index), expected_number);
            }
        }

        // Test chunk_number for files up to 4 * MAX_CHUNK_SIZE.  First three chunks should each
        // have MAX_CHUNK_SIZE bytes, fourth chunk containing remainder.
        min_test_size = max_test_size;
        max_test_size = 4 * MAX_CHUNK_SIZE;
        for file_size in (min_test_size..max_test_size).filter(|&elt| elt % step == 0) {
            const CHUNK_2_END: usize = (3 * MAX_CHUNK_SIZE) - 1;
            assert_eq!(get_num_chunks(file_size), 4);
            let mut test_indices = vec![
                CHUNK_0_START,
                CHUNK_0_END,
                CHUNK_1_START,
                CHUNK_1_END,
                CHUNK_2_START,
                CHUNK_2_END,
            ];
            test_indices.append(&mut ((CHUNK_2_END + 1)..(file_size - 1)).collect::<Vec<_>>());
            for byte_index in test_indices {
                let expected_number = match byte_index {
                    CHUNK_0_START..=CHUNK_0_END => 0,
                    CHUNK_1_START..=CHUNK_1_END => 1,
                    CHUNK_2_START..=CHUNK_2_END => 2,
                    _ => 3,
                };
                assert_eq!(get_chunk_number(file_size, byte_index), expected_number);
            }
        }
        Ok(())
    }
}
