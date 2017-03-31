// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{COMPRESSION_QUALITY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, SelfEncryptionError, Storage,
            StorageError};
use brotli2::write::{BrotliDecoder, BrotliEncoder};
use data_map::{ChunkDetails, DataMap};
use encryption::{self, IV_SIZE, Iv, KEY_SIZE, Key};
use rust_sodium;
use rust_sodium::crypto::hash::sha256;
use sequencer::{MAX_IN_MEMORY_SIZE, Sequencer};
use std::cmp;
use std::fmt::{self, Debug, Formatter};
use std::io::Write;
use std::iter;
use std::marker::PhantomData;
use std::sync::{ONCE_INIT, Once};

const HASH_SIZE: usize = sha256::DIGESTBYTES;
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
pub struct SelfEncryptor<'a, E: StorageError, S: 'a + Storage<E>> {
    storage: &'a mut S,
    sorted_map: Vec<ChunkDetails>, // the original data_map, sorted
    chunks: Vec<Chunk>, // this is sorted as well
    map_size: u64, // original file size of the data_map
    sequencer: Sequencer,
    file_size: u64,
    phantom: PhantomData<E>, // to allow `E` to be used
}

impl<'a, E: StorageError, S: Storage<E>> SelfEncryptor<'a, E, S> {
    /// This is the only constructor for an encryptor object.  Each `SelfEncryptor` is used for a
    /// single file.  The parameters are a `Storage` object and a `DataMap`.  For a file which has
    /// not previously been self-encrypted, use `DataMap::None`.
    pub fn new(storage: &'a mut S,
               data_map: DataMap)
               -> Result<SelfEncryptor<'a, E, S>, SelfEncryptionError<E>> {
        initialise_rust_sodium();
        let file_size = data_map.len();
        let mut sequencer = if file_size <= MAX_IN_MEMORY_SIZE as u64 {
            Sequencer::new_as_vector()
        } else {
            Sequencer::new_as_mmap()?
        };

        let sorted_map;
        let chunks;
        let map_size;
        match data_map {
            DataMap::Content(content) => {
                sequencer.init(&content);
                sorted_map = vec![];
                chunks = vec![];
                map_size = 0;
            }
            DataMap::Chunks(mut sorted_chunks) => {
                DataMap::chunks_sort(&mut sorted_chunks);
                let c = Chunk {
                    status: ChunkStatus::AlreadyEncrypted,
                    in_sequencer: false,
                };
                chunks = vec![c; sorted_chunks.len()];
                sorted_map = sorted_chunks;
                map_size = file_size;
            }
            DataMap::None => {
                sorted_map = vec![];
                chunks = vec![];
                map_size = 0;
            }
        }

        Ok(SelfEncryptor {
               storage: storage,
               sorted_map: sorted_map,
               chunks: chunks,
               sequencer: sequencer,
               file_size: file_size,
               map_size: map_size,
               phantom: PhantomData,
           })
    }

    /// Write method mirrors a POSIX type write mechanism.  It loosely mimics a filesystem interface
    /// for easy connection to FUSE-like programs as well as fine grained access to system level
    /// libraries for developers.  The input `data` will be written from the specified `position`
    /// (starts from 0).
    pub fn write(&mut self, data: &[u8], position: u64) -> Result<(), SelfEncryptionError<E>> {
        self.prepare_window_for_writing(position, data.len() as u64)?;
        for (p, byte) in self.sequencer
                .iter_mut()
                .skip(position as usize)
                .zip(data) {
            *p = *byte;
        }
        Ok(())
    }

    /// The returned content is read from the specified `position` with specified `length`.  Trying
    /// to read beyond the file size will cause the encryptor to return content filled with `0u8`s
    /// in the gap (file size isn't affected).  Any other unwritten gaps will also be filled with
    /// '0u8's.
    pub fn read(&mut self, position: u64, length: u64) -> Result<Vec<u8>, SelfEncryptionError<E>> {
        self.prepare_window_for_reading(position, length)?;
        Ok(self.sequencer
               .iter()
               .skip(position as usize)
               .take(length as usize)
               .cloned()
               .collect())
    }

    /// This function returns a `DataMap`, which is the info required to recover encrypted content
    /// from data storage location.  Content temporarily held in the encryptor will only get flushed
    /// into storage when this function gets called.
    #[cfg_attr(feature="cargo-clippy", allow(needless_range_loop))]
    pub fn close(mut self) -> Result<DataMap, SelfEncryptionError<E>> {
        if self.file_size == 0 {
            return Ok(DataMap::None);
        }
        if self.file_size < 3 * MIN_CHUNK_SIZE as u64 {
            let content = (*self.sequencer)[..self.file_size as usize].to_vec();
            return Ok(DataMap::Content(content));
        }

        // Decrypt:
        // - first two chunks if last chunks size has changed
        // - chunks whose size is out of date
        let possibly_reusable_end; // end of range of possibly reusable chunks
        let (resized_start, resized_end) = resized_chunks(self.map_size, self.file_size);
        if resized_start == resized_end {
            possibly_reusable_end = get_num_chunks(self.map_size) as usize;
        } else {
            self.chunks[0].flag_for_encryption();
            self.chunks[1].flag_for_encryption();
            let mut byte_end = get_start_end_positions(self.map_size, 1).1;
            self.prepare_window_for_reading(0, byte_end)?;

            let byte_start = get_start_end_positions(self.map_size, resized_start).0;
            byte_end = self.map_size;
            self.prepare_window_for_reading(byte_start, byte_end - byte_start)?;
            possibly_reusable_end = resized_start as usize;
        }

        let num_new_chunks = get_num_chunks(self.file_size) as usize;
        let mut new_map = vec![ChunkDetails::new(); num_new_chunks];

        for (i, mut new_chunk) in new_map.iter_mut().enumerate() {
            if i < possibly_reusable_end && self.chunks[i].status != ChunkStatus::ToBeHashed {
                new_chunk.chunk_num = i as u32;
                new_chunk.hash.clear();
                new_chunk.pre_hash = self.sorted_map[i].pre_hash.clone();
                new_chunk.source_size = self.sorted_map[i].source_size;
            } else {
                let this_size = get_chunk_size(self.file_size, i as u32) as usize;
                let pos = get_start_end_positions(self.file_size, i as u32).0 as usize;
                assert!(this_size > 0);
                let sha256::Digest(name) = sha256::hash(&(*self.sequencer)[pos..pos + this_size]);
                new_chunk.chunk_num = i as u32;
                new_chunk.hash.clear();
                new_chunk.pre_hash = name.to_vec();
                new_chunk.source_size = this_size as u64;
            }
        }

        for i in 0..num_new_chunks {
            if i < possibly_reusable_end && self.chunks[i].status == ChunkStatus::AlreadyEncrypted {
                new_map[i].hash = self.sorted_map[i].hash.clone();
            } else {
                let this_size = get_chunk_size(self.file_size, i as u32) as usize;
                let pos = get_start_end_positions(self.file_size, i as u32).0 as usize;

                assert!(this_size > 0);

                let pki = get_pad_key_and_iv(i as u32, &new_map, self.file_size);
                let content = encrypt_chunk(&(*self.sequencer)[pos..pos + this_size], pki)?;
                let sha256::Digest(name) = sha256::hash(&content);
                self.storage.put(name.to_vec(), content)?;
                new_map[i].hash = name.to_vec();
            }
        }
        Ok(DataMap::Chunks(new_map))
    }

    /// Truncate the self_encryptor to the specified size (if extended, filled with `0u8`s).
    pub fn truncate(&mut self, new_size: u64) -> Result<(), SelfEncryptionError<E>> {
        if self.file_size == new_size {
            return Ok(());
        }
        if new_size < self.file_size {
            let (chunks_start, chunks_end) =
                overlapped_chunks(self.map_size, new_size, self.file_size - new_size);
            if chunks_start != chunks_end {
                // One chunk might need to be decrypted + the first two for re-encryption.
                if !self.chunks[chunks_start].in_sequencer {
                    let byte_start = get_start_end_positions(self.map_size, chunks_start as u32).0;
                    if byte_start < new_size {
                        self.prepare_window_for_reading(byte_start, new_size - byte_start)?;
                    }
                    self.chunks[0].flag_for_encryption();
                    self.chunks[1].flag_for_encryption();
                    let byte_end = get_start_end_positions(self.map_size, 1).1;
                    self.prepare_window_for_reading(0, byte_end)?;
                }
                for chunk in &mut self.chunks[chunks_start..chunks_end] {
                    chunk.status = ChunkStatus::ToBeHashed;
                    chunk.in_sequencer = true;
                }
            }
            self.sequencer.truncate(new_size as usize);
        } else {
            self.extend_sequencer_up_to(new_size)?;
        }
        self.file_size = new_size;
        Ok(())
    }

    /// Current file size as is known by encryptor.
    pub fn len(&self) -> u64 {
        self.file_size
    }

    /// Returns true if file size as is known by encryptor == 0.
    pub fn is_empty(&self) -> bool {
        self.file_size == 0
    }

    fn prepare_window_for_writing(&mut self,
                                  position: u64,
                                  length: u64)
                                  -> Result<(), SelfEncryptionError<E>> {
        self.file_size = cmp::max(self.file_size, position + length);

        let (chunks_start, chunks_end) = overlapped_chunks(self.map_size, position, length);
        if chunks_start == chunks_end {
            self.extend_sequencer_up_to(position + length)?;
            return Ok(());
        }

        // Two more chunks need to be decrypted for re-encryption.
        let next_two = [chunks_end % get_num_chunks(self.map_size) as usize,
                        (chunks_end + 1) % get_num_chunks(self.map_size) as usize];

        let required_len = {
            let mut end = get_start_end_positions(self.map_size, chunks_end as u32 - 1).1;
            end = cmp::max(end,
                           get_start_end_positions(self.map_size, next_two[0] as u32).1);
            end = cmp::max(end,
                           get_start_end_positions(self.map_size, next_two[1] as u32).1);
            cmp::max(position + length, end)
        };
        self.extend_sequencer_up_to(required_len)?;

        // Middle chunks don't need decrypting since they'll get overwritten.
        // TODO If first/last chunk gets completely overwritten, no need to decrypt.
        for &i in [chunks_start, chunks_end - 1].iter().chain(&next_two) {
            if self.chunks[i].in_sequencer {
                continue;
            }
            self.chunks[i].in_sequencer = true;
            let pos = get_start_end_positions(self.map_size, i as u32).0 as usize;
            let vec = self.decrypt_chunk(i as u32)?;
            for (p, byte) in self.sequencer.iter_mut().skip(pos).zip(vec) {
                *p = byte;
            }
        }
        for chunk in &mut self.chunks[chunks_start..chunks_end] {
            chunk.status = ChunkStatus::ToBeHashed;
            chunk.in_sequencer = true;
        }
        for &i in &next_two {
            self.chunks[i].flag_for_encryption();
        }
        Ok(())
    }

    fn prepare_window_for_reading(&mut self,
                                  position: u64,
                                  length: u64)
                                  -> Result<(), SelfEncryptionError<E>> {
        let (chunks_start, chunks_end) = overlapped_chunks(self.map_size, position, length);

        if chunks_start == chunks_end {
            self.extend_sequencer_up_to(position + length)?;
            return Ok(());
        }

        let required_len = {
            let end = get_start_end_positions(self.map_size, chunks_end as u32 - 1).1;
            cmp::max(position + length, end)
        };
        self.extend_sequencer_up_to(required_len)?;

        for i in chunks_start..chunks_end {
            if self.chunks[i].in_sequencer {
                continue;
            }
            self.chunks[i].in_sequencer = true;
            let pos = get_start_end_positions(self.map_size, i as u32).0 as usize;
            let vec = self.decrypt_chunk(i as u32)?;
            for (p, byte) in self.sequencer.iter_mut().skip(pos).zip(vec) {
                *p = byte
            }
        }
        Ok(())
    }

    fn extend_sequencer_up_to(&mut self, new_len: u64) -> Result<(), SelfEncryptionError<E>> {
        let old_len = self.sequencer.len() as u64;
        if new_len > old_len {
            if new_len > MAX_IN_MEMORY_SIZE as u64 {
                self.sequencer.create_mapping()?;
            } else {
                self.sequencer
                    .extend(iter::repeat(0).take((new_len - old_len) as usize));
            }
        }
        Ok(())
    }

    fn decrypt_chunk(&self, chunk_number: u32) -> Result<Vec<u8>, SelfEncryptionError<E>> {
        let name = &self.sorted_map[chunk_number as usize].hash;
        let content = self.storage.get(name)?;
        let (pad, key, iv) = get_pad_key_and_iv(chunk_number, &self.sorted_map, self.map_size);
        let xor_result = xor(&content, &pad);
        let decrypted = encryption::decrypt(&xor_result, &key, &iv)?;
        let mut decompressor = BrotliDecoder::new(vec![]);
        if decompressor.write_all(&decrypted).is_err() {
            return Err(SelfEncryptionError::Compression);
        }
        decompressor
            .finish()
            .map_err(|_| SelfEncryptionError::Compression)
    }
}

fn encrypt_chunk<E: StorageError>(content: &[u8],
                                  pki: (Pad, Key, Iv))
                                  -> Result<Vec<u8>, SelfEncryptionError<E>> {
    let (pad, key, iv) = pki;
    let mut compressor = BrotliEncoder::new(vec![], COMPRESSION_QUALITY);
    if compressor.write_all(content).is_err() {
        return Err(SelfEncryptionError::Compression);
    }
    let compressed = match compressor.finish() {
        Ok(data) => data,
        Err(_) => return Err(SelfEncryptionError::Compression),
    };
    let encrypted = encryption::encrypt(&compressed, &key, &iv);
    Ok(xor(&encrypted, &pad))
}

fn get_pad_key_and_iv(chunk_number: u32,
                      sorted_map: &[ChunkDetails],
                      map_size: u64)
                      -> (Pad, Key, Iv) {
    let n_1 = get_previous_chunk_number(map_size, chunk_number);
    let n_2 = get_previous_chunk_number(map_size, n_1);
    let this_pre_hash = &sorted_map[chunk_number as usize].pre_hash;
    let n_1_pre_hash = &sorted_map[n_1 as usize].pre_hash;
    let n_2_pre_hash = &sorted_map[n_2 as usize].pre_hash;

    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in
        pad.iter_mut()
            .chain(iv.iter_mut())
            .zip(this_pre_hash.iter().chain(n_2_pre_hash.iter())) {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().zip(n_1_pre_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

// Returns the chunk range [start, end) that is overlapped by the byte range defined by `position`
// and `length`.  Returns empty range if file_size is so small that there are no chunks.
fn overlapped_chunks(file_size: u64, position: u64, length: u64) -> (usize, usize) {
    if file_size < (3 * MIN_CHUNK_SIZE as u64) || position >= file_size || length == 0 {
        return (0, 0);
    }
    let start = get_chunk_number(file_size, position);
    let end_pos = position + length - 1; // inclusive
    let end = if end_pos < file_size {
        get_chunk_number(file_size, end_pos) + 1
    } else {
        get_num_chunks(file_size)
    };
    (start as usize, end as usize)
}

// Returns a chunk range [start, end) whose sizes are affected by a change in file size.
fn resized_chunks(old_size: u64, new_size: u64) -> (u32, u32) {
    if old_size == new_size || old_size < (3 * MIN_CHUNK_SIZE as u64) {
        return (0, 0);
    }
    if old_size < (3 * MAX_CHUNK_SIZE as u64) {
        return (0, 3);
    }
    if new_size > old_size {
        let remainder = (old_size % MAX_CHUNK_SIZE as u64) as u32;
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

    if new_size >= (3 * MAX_CHUNK_SIZE as u64) {
        let remainder = (new_size % MAX_CHUNK_SIZE as u64) as u32;
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
fn get_num_chunks(file_size: u64) -> u32 {
    if file_size < (3 * MIN_CHUNK_SIZE as u64) {
        return 0;
    }
    if file_size < (3 * MAX_CHUNK_SIZE as u64) {
        return 3;
    }
    if file_size % MAX_CHUNK_SIZE as u64 == 0 {
        (file_size / MAX_CHUNK_SIZE as u64) as u32
    } else {
        ((file_size / MAX_CHUNK_SIZE as u64) + 1) as u32
    }
}

// Returns the size of a chunk according to file size.
fn get_chunk_size(file_size: u64, chunk_number: u32) -> u32 {
    if file_size < 3 * MIN_CHUNK_SIZE as u64 {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE as u64 {
        if chunk_number < 2 {
            return (file_size / 3) as u32;
        } else {
            return (file_size - (2 * (file_size / 3))) as u32;
        }
    }
    if chunk_number < get_num_chunks(file_size) - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = (file_size % MAX_CHUNK_SIZE as u64) as u32;
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
fn get_start_end_positions(file_size: u64, chunk_number: u32) -> (u64, u64) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start;
    let last = (get_num_chunks(file_size) - 1) == chunk_number;
    if last {
        start = get_chunk_size(file_size, 0) as u64 * (chunk_number as u64 - 1) +
                get_chunk_size(file_size, chunk_number - 1) as u64;
    } else {
        start = get_chunk_size(file_size, 0) as u64 * chunk_number as u64;
    }
    (start, start + get_chunk_size(file_size, chunk_number) as u64)
}

fn get_previous_chunk_number(file_size: u64, chunk_number: u32) -> u32 {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }
    (get_num_chunks(file_size) + chunk_number - 1) % get_num_chunks(file_size)
}

fn get_chunk_number(file_size: u64, position: u64) -> u32 {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }

    let remainder = file_size % get_chunk_size(file_size, 0) as u64;
    if remainder == 0 || remainder >= MIN_CHUNK_SIZE as u64 ||
       position < file_size - remainder - MIN_CHUNK_SIZE as u64 {
        return (position / get_chunk_size(file_size, 0) as u64) as u32;
    }
    get_num_chunks(file_size) - 1
}

impl<'a, E: StorageError, S: Storage<E>> Debug for SelfEncryptor<'a, E, S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SelfEncryptor {{\n    chunks:\n")?;
        for (i, chunk) in self.chunks.iter().enumerate() {
            write!(formatter,
                   "        {:?}   {:?}\n",
                   self.sorted_map[i],
                   chunk)?
        }
        write!(formatter, "    map_size: {}\n", self.map_size)?;
        write!(formatter, "    file_size: {}\n}}", self.file_size)
    }
}

fn initialise_rust_sodium() {
    static INITIALISE_SODIUMOXIDE: Once = ONCE_INIT;
    INITIALISE_SODIUMOXIDE.call_once(|| assert!(rust_sodium::init()));
}

#[cfg(test)]
mod tests {
    use super::{SelfEncryptor, get_chunk_number, get_chunk_size, get_num_chunks,
                get_previous_chunk_number, get_start_end_positions};
    use super::super::{DataMap, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, Storage, StorageError};
    use maidsafe_utilities::serialisation;
    use rand::{self, Rng};
    use rand::distributions::{Range, Sample};
    use test_helpers::SimpleStorage;

    fn random_bytes(size: usize) -> Vec<u8> {
        rand::thread_rng().gen_iter().take(size).collect()
    }

    #[test]
    fn helper_functions() {
        let mut file_size = MIN_CHUNK_SIZE as u64 * 3;
        assert_eq!(get_num_chunks(file_size), 3);
        assert_eq!(get_chunk_size(file_size, 0), 1024);
        assert_eq!(get_chunk_size(file_size, 1), 1024);
        assert_eq!(get_chunk_size(file_size, 2), 1024);
        assert_eq!(get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(get_start_end_positions(file_size, 0).1,
                   MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).0,
                   MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).1,
                   2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).0,
                   2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).1,
                   3 * MIN_CHUNK_SIZE as u64);

        file_size = (MIN_CHUNK_SIZE as u64 * 3) + 1;
        assert_eq!(get_num_chunks(file_size), 3);
        assert_eq!(get_chunk_size(file_size, 0), 1024);
        assert_eq!(get_chunk_size(file_size, 1), 1024);
        assert_eq!(get_chunk_size(file_size, 2), 1025);
        assert_eq!(get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(get_start_end_positions(file_size, 0).1,
                   MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).0,
                   MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).1,
                   2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).0,
                   2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).1,
                   1 + 3 * MIN_CHUNK_SIZE as u64);

        file_size = MAX_CHUNK_SIZE as u64 * 3;
        assert_eq!(get_num_chunks(file_size), 3);
        assert_eq!(get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 2), MAX_CHUNK_SIZE);
        assert_eq!(get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(get_start_end_positions(file_size, 0).1,
                   MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).0,
                   MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).1,
                   2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).0,
                   2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).1,
                   3 * MAX_CHUNK_SIZE as u64);

        file_size = MAX_CHUNK_SIZE as u64 * 3 + 1;
        assert_eq!(get_num_chunks(file_size), 4);
        assert_eq!(get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 2),
                   MAX_CHUNK_SIZE - MIN_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 3), MIN_CHUNK_SIZE + 1);
        assert_eq!(get_previous_chunk_number(file_size, 0), 3);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_previous_chunk_number(file_size, 3), 2);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(get_start_end_positions(file_size, 0).1,
                   MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).0,
                   MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).1,
                   2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).0,
                   2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).1,
                   ((3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE) as u64);
        assert_eq!(get_start_end_positions(file_size, 3).0,
                   get_start_end_positions(file_size, 2).1);
        assert_eq!(get_start_end_positions(file_size, 3).1, file_size);

        file_size = (MAX_CHUNK_SIZE * 7) as u64 + 1024;
        assert_eq!(get_num_chunks(file_size), 8);
        assert_eq!(get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 2), MAX_CHUNK_SIZE);
        assert_eq!(get_chunk_size(file_size, 3), MAX_CHUNK_SIZE);
        assert_eq!(get_previous_chunk_number(file_size, 0), 7);
        assert_eq!(get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(get_previous_chunk_number(file_size, 3), 2);
        assert_eq!(get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(get_start_end_positions(file_size, 0).1,
                   MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).0,
                   MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 1).1,
                   2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).0,
                   2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 2).1,
                   3 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 3).0,
                   3 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, 7).1,
                   ((7 * MAX_CHUNK_SIZE) as u64 + 1024));

        file_size = (MAX_CHUNK_SIZE * 11) as u64 - 1;
        assert_eq!(get_num_chunks(file_size), 11);
        assert_eq!(get_previous_chunk_number(file_size, 11), 10);

        file_size = (MAX_CHUNK_SIZE * 11) as u64 + 1;
        assert_eq!(get_num_chunks(file_size), 11 + 1);
        assert_eq!(get_previous_chunk_number(file_size, 11), 10);

        let mut number_of_chunks: u32 = 11;
        file_size = (MAX_CHUNK_SIZE as u64 * number_of_chunks as u64) + 1024;
        assert_eq!(get_num_chunks(file_size), number_of_chunks + 1);
        for i in 0..number_of_chunks {
            // preceding and next index, wrapped around
            let h = (i + number_of_chunks) % (number_of_chunks + 1);
            let j = (i + 1) % (number_of_chunks + 1);
            assert_eq!(get_chunk_size(file_size, i), MAX_CHUNK_SIZE);
            assert_eq!(get_previous_chunk_number(file_size, i), h);
            assert_eq!(get_start_end_positions(file_size, i).0,
                       i as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(get_start_end_positions(file_size, i).1,
                       j as u64 * MAX_CHUNK_SIZE as u64);
        }
        assert_eq!(get_chunk_size(file_size, number_of_chunks), MIN_CHUNK_SIZE);
        assert_eq!(get_previous_chunk_number(file_size, number_of_chunks),
                   number_of_chunks - 1);
        assert_eq!(get_start_end_positions(file_size, number_of_chunks).0,
                   number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, number_of_chunks).1,
                   ((number_of_chunks * MAX_CHUNK_SIZE) as u64 + 1024));

        number_of_chunks = 100;
        file_size = MAX_CHUNK_SIZE as u64 * number_of_chunks as u64;
        assert_eq!(get_num_chunks(file_size), number_of_chunks);
        for i in 0..number_of_chunks - 1 {
            // preceding and next index, wrapped around
            let h = (i + number_of_chunks - 1) % number_of_chunks;
            let j = (i + 1) % number_of_chunks;
            assert_eq!(get_chunk_size(file_size, i), MAX_CHUNK_SIZE);
            assert_eq!(get_previous_chunk_number(file_size, i), h);
            assert_eq!(get_start_end_positions(file_size, i).0,
                       i as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(get_start_end_positions(file_size, i).1,
                       j as u64 * MAX_CHUNK_SIZE as u64);
        }
        assert_eq!(get_previous_chunk_number(file_size, number_of_chunks),
                   number_of_chunks - 1);
        assert_eq!(get_start_end_positions(file_size, number_of_chunks).0,
                   number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
        assert_eq!(get_start_end_positions(file_size, number_of_chunks - 1).1,
                   ((number_of_chunks * MAX_CHUNK_SIZE) as u64));
    }

    fn check_file_size<E: StorageError, S: Storage<E>>(se: &SelfEncryptor<E, S>,
                                                       expected_file_size: u64) {
        assert_eq!(se.file_size, expected_file_size);
        if !se.sorted_map.is_empty() {
            let chunks_cumulated_size = se.sorted_map
                .iter()
                .fold(0u64, |acc, chunk| acc + chunk.source_size);
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
        assert_eq!(data,
                   super::xor(&super::xor(&data, &super::Pad(pad)), &super::Pad(pad)));
    }

    #[test]
    fn write() {
        let mut storage = SimpleStorage::new();
        let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        let size = 3;
        let offset = 5u32;
        let the_bytes = random_bytes(size);
        se.write(&the_bytes, offset as u64)
            .expect("Writing to encryptor shouldn't fail.");
        check_file_size(&se, (size + offset as usize) as u64);
    }

    #[test]
    fn multiple_writes() {
        let mut storage = SimpleStorage::new();
        let size1 = 3;
        let size2 = 4;
        let part1 = random_bytes(size1);
        let part2 = random_bytes(size2);
        let data_map;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            // Just testing multiple subsequent write calls
            se.write(&part1, 0)
                .expect("Writing part one to encryptor shouldn't fail.");
            se.write(&part2, size1 as u64)
                .expect("Writing part two to encryptor shouldn't fail.");
            // Let's also test an overwrite.. over middle bytes of part2
            se.write(&[4u8, 2], size1 as u64 + 1)
                .expect("Overwriting on encryptor shouldn't fail.");
            check_file_size(&se, (size1 + size2) as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        let mut se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = se.read(0, (size1 + size2) as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&fetched[..size1], &part1[..]);
        assert_eq!(fetched[size1], part2[0]);
        assert_eq!(&fetched[size1 + 1..size1 + 3], &[4u8, 2][..]);
        assert_eq!(&fetched[size1 + 3..], &part2[3..]);
    }

    #[test]
    fn three_min_chunks_minus_one() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE * 3) - 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            assert_eq!(se.sorted_map.len(), 0);
            assert_eq!(se.sequencer.len(), bytes_len as usize);
            check_file_size(&se, bytes_len as u64);
            // check close
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(_) => panic!("shall not return DataMap::Chunks"),
            DataMap::Content(ref content) => assert_eq!(content.len(), bytes_len as usize),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn three_min_chunks() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let the_bytes = random_bytes(MIN_CHUNK_SIZE as usize * 3);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, MIN_CHUNK_SIZE as u64 * 3);
            let fetched = se.read(0, MIN_CHUNK_SIZE as u64 * 3)
                .expect("Reading from encryptor shouldn't fail.");
            assert_eq!(fetched, the_bytes);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, MIN_CHUNK_SIZE as u64 * 3)
            .expect("Reading again from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn three_min_chunks_plus_one() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn three_max_chunks() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn three_max_chunks_plus_one() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = (MAX_CHUNK_SIZE * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            // check close
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                assert_eq!(storage.num_entries(), 4);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn seven_and_a_bit_max_chunks() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = (MAX_CHUNK_SIZE * 7) + 1024;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 8);
                assert_eq!(storage.num_entries(), 8);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn large_file_one_byte_under_eleven_chunks() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) - 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize);
                assert_eq!(storage.num_entries(), number_of_chunks as usize);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn large_file_one_byte_over_eleven_chunks() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize + 1);
                assert_eq!(storage.num_entries(), number_of_chunks as usize + 1);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn large_file_size_1024_over_eleven_chunks() {
        // has been tested for 50 chunks
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1024;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            // check close
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize + 1);
                assert_eq!(storage.num_entries(), number_of_chunks as usize + 1);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn five_and_extend_to_seven_plus_one() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE * 5;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("Encryptor construction shouldn't fail.");
            se.write(&the_bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            se.truncate((7 * MAX_CHUNK_SIZE + 1) as u64)
                .expect("Truncating encryptor shouldn't fail.");
            check_file_size(&se, (7 * MAX_CHUNK_SIZE + 1) as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 8);
                assert_eq!(storage.num_entries(), 8);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
    }

    #[test]
    fn truncate_three_max_chunks() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            se.truncate(bytes_len as u64 - 24)
                .expect("Truncating encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64 - 24);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        assert_eq!(data_map.len(), bytes_len as u64 - 24);
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("data_map should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = se.read(0, bytes_len as u64 - 24)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&fetched[..], &bytes[..(bytes_len - 24) as usize]);
    }

    #[test]
    fn truncate_from_data_map() {
        let mut storage = SimpleStorage::new();
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let bytes = random_bytes(bytes_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close()
                .expect("Closing first encryptor shouldn't fail.");
        }
        let data_map2: DataMap;
        {
            // Start with an existing data_map.
            let mut se = SelfEncryptor::new(&mut storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            se.truncate(bytes_len as u64 - 24)
                .expect("Truncating encryptor shouldn't fail.");
            data_map2 = se.close()
                .expect("Closing second encryptor shouldn't fail.");
        }
        assert_eq!(data_map2.len(), bytes_len as u64 - 24);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                // old ones + new ones
                assert_eq!(storage.num_entries(), 6);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("data_map should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(&mut storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se.read(0, bytes_len as u64 - 24)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&fetched[..], &bytes[..(bytes_len - 24) as usize]);
    }

    #[test]
    fn truncate_from_data_map2() {
        let mut storage = SimpleStorage::new();
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let bytes = random_bytes(bytes_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close()
                .expect("Closing first encryptor shouldn't fail.");
        }
        let data_map2: DataMap;
        {
            // Start with an existing data_map.
            let mut se = SelfEncryptor::new(&mut storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            se.truncate(bytes_len as u64 - 1)
                .expect("Truncating encryptor once shouldn't fail.");
            se.truncate(bytes_len as u64)
                .expect("Truncating encryptor a second time shouldn't fail.");
            data_map2 = se.close()
                .expect("Closing second encryptor shouldn't fail.");
        }
        assert_eq!(data_map2.len(), bytes_len as u64);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                // old ones + new ones
                assert_eq!(storage.num_entries(), 6);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("data_map should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(&mut storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se.read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        let matching_bytes = bytes_len as usize - 1;
        assert_eq!(&fetched[..matching_bytes], &bytes[..matching_bytes]);
        assert_eq!(fetched[matching_bytes], 0u8);
    }

    #[test]
    fn truncate_to_extend_from_data_map() {
        let mut storage = SimpleStorage::new();
        let bytes_len = MAX_CHUNK_SIZE * 3 - 24;
        let bytes = random_bytes(bytes_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close()
                .expect("Closing first encryptor shouldn't fail.");
        }
        let data_map2: DataMap;
        {
            // Start with an existing data_map.
            let mut se = SelfEncryptor::new(&mut storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            se.truncate(bytes_len as u64 + 24)
                .expect("Truncating encryptor shouldn't fail.");
            data_map2 = se.close()
                .expect("Closing second encryptor shouldn't fail.");
        }
        assert_eq!(data_map2.len(), bytes_len as u64 + 24);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                // old ones + new ones
                assert_eq!(storage.num_entries(), 6);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("data_map should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(&mut storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se.read(0, bytes_len as u64 + 24)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&fetched[..bytes_len as usize], &bytes[..]);
        assert_eq!(&fetched[bytes_len as usize..], &[0u8; 24]);
    }

    #[test]
    fn large_100mb_file() {
        let mut storage = SimpleStorage::new();
        let data_map: DataMap;
        let number_of_chunks: u32 = 100;
        let bytes_len = MAX_CHUNK_SIZE as usize * number_of_chunks as usize;
        let bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&bytes, 0)
                .expect("Writing to encryptor shouldn't fail.");
            check_file_size(&se, bytes_len as u64);
            data_map = se.close().expect("Closing encryptor shouldn't fail.");
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize);
                assert_eq!(storage.num_entries(), number_of_chunks as usize);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(&mut storage, data_map)
            .expect("Second encryptor construction shouldn't fail.");
        let fetched = new_se
            .read(0, bytes_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(fetched, bytes);
    }

    #[test]
    fn write_starting_with_existing_data_map() {
        let mut storage = SimpleStorage::new();
        let part1_len = MIN_CHUNK_SIZE * 3;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&part1_bytes, 0)
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, part1_len as u64);
            data_map = se.close()
                .expect("Closing first encryptor shouldn't fail.");
        }
        let part2_len = 1024;
        let part2_bytes = random_bytes(part2_len as usize);
        let full_len = part1_len + part2_len;
        let data_map2: DataMap;
        {
            // Start with an existing data_map.
            let mut se = SelfEncryptor::new(&mut storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            se.write(&part2_bytes, part1_len as u64)
                .expect("Writing part two to encryptor shouldn't fail.");
            // check_file_size(&se, full_len);
            data_map2 = se.close()
                .expect("Closing second encryptor shouldn't fail.");
        }
        assert_eq!(data_map2.len(), full_len as u64);

        let mut se = SelfEncryptor::new(&mut storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se.read(0, full_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&part1_bytes[..], &fetched[..part1_len as usize]);
        assert_eq!(&part2_bytes[..], &fetched[part1_len as usize..]);
    }

    #[test]
    fn write_starting_with_existing_data_map2() {
        let mut storage = SimpleStorage::new();
        let part1_len = MAX_CHUNK_SIZE * 3 - 24;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&part1_bytes, 0)
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, part1_len as u64);
            data_map = se.close()
                .expect("Closing first encryptor shouldn't fail.");
        }
        let part2_len = 1024;
        let part2_bytes = random_bytes(part2_len as usize);
        let full_len = part1_len + part2_len;
        let data_map2: DataMap;
        {
            // Start with an existing data_map.
            let mut se = SelfEncryptor::new(&mut storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            se.write(&part2_bytes, part1_len as u64)
                .expect("Writing part two to encryptor shouldn't fail.");
            data_map2 = se.close()
                .expect("Closing second encryptor shouldn't fail.");
        }
        assert_eq!(data_map2.len(), full_len as u64);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                // old ones + new ones
                assert_eq!(storage.num_entries(), 7);
                for chunk_detail in chunks.iter() {
                    assert!(storage.has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("data_map should be DataMap::Chunks"),
        }

        let mut se = SelfEncryptor::new(&mut storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se.read(0, full_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&part1_bytes[..], &fetched[..part1_len as usize]);
        assert_eq!(&part2_bytes[..], &fetched[part1_len as usize..]);
    }

    #[test]
    fn overwrite_starting_with_existing_data_map() {
        let mut storage = SimpleStorage::new();
        let part1_len = MAX_CHUNK_SIZE * 4;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(&mut storage, DataMap::None)
                .expect("First encryptor construction shouldn't fail.");
            se.write(&part1_bytes, 0)
                .expect("Writing part one to encryptor shouldn't fail.");
            check_file_size(&se, part1_len as u64);
            data_map = se.close()
                .expect("Closing first encryptor shouldn't fail.");
        }
        let part2_len = 2;
        let part2_bytes = random_bytes(part2_len);
        let data_map2: DataMap;
        {
            // Start with an existing data_map.
            let mut se = SelfEncryptor::new(&mut storage, data_map)
                .expect("Second encryptor construction shouldn't fail.");
            // Overwrite. This and next two chunks will have to be re-encrypted.
            se.write(&part2_bytes, 2)
                .expect("Writing part two to encryptor shouldn't fail.");
            data_map2 = se.close()
                .expect("Closing second encryptor shouldn't fail.");
        }
        assert_eq!(data_map2.len(), part1_len as u64);

        let mut se = SelfEncryptor::new(&mut storage, data_map2)
            .expect("Third encryptor construction shouldn't fail.");
        let fetched = se.read(0, part1_len as u64)
            .expect("Reading from encryptor shouldn't fail.");
        assert_eq!(&part1_bytes[..2], &fetched[..2]);
        assert_eq!(&part2_bytes[..], &fetched[2..2 + part2_len]);
        assert_eq!(&part1_bytes[2 + part2_len..], &fetched[2 + part2_len..]);
    }

    fn create_vector_data_map(storage: &mut SimpleStorage, vec_len: usize) -> DataMap {
        let data: Vec<usize> = (0..vec_len).collect();
        let serialised_data: Vec<u8> =
            serialisation::serialise(&data).expect("failed to serialise Vec<usize>");
        let mut self_encryptor = SelfEncryptor::new(storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        self_encryptor
            .write(&serialised_data, 0)
            .expect("Writing to encryptor shouldn't fail.");
        check_file_size(&self_encryptor, serialised_data.len() as u64);
        self_encryptor
            .close()
            .expect("Closing encryptor shouldn't fail.")
    }

    fn check_vector_data_map(storage: &mut SimpleStorage, vec_len: usize, data_map: &DataMap) {
        let mut self_encryptor = SelfEncryptor::new(storage, data_map.clone())
            .expect("Encryptor construction shouldn't fail.");
        let length = self_encryptor.len();
        let data_to_deserialise: Vec<u8> = self_encryptor
            .read(0, length)
            .expect("Reading from encryptor shouldn't fail.");
        let data: Vec<usize> = serialisation::deserialise(&data_to_deserialise)
            .expect("failed to deserialise Vec<usize>");
        assert_eq!(data.len(), vec_len);
        for (index, data_char) in data.iter().enumerate() {
            assert_eq!(*data_char, index);
        }
    }

    #[test]
    fn serialised_vectors() {
        for vec_len in &[1000, 2000, 5000, 10_000, 20_000, 50_000, 100_000, 200_000] {
            let mut storage = SimpleStorage::new();
            let data_map: DataMap = create_vector_data_map(&mut storage, *vec_len);
            check_vector_data_map(&mut storage, *vec_len, &data_map);
        }
    }

    #[test]
    fn chunk_number() {
        const CHUNK_0_START: u32 = 0;
        const CHUNK_0_END: u32 = MAX_CHUNK_SIZE - 1;
        const CHUNK_1_START: u32 = MAX_CHUNK_SIZE;
        const CHUNK_1_END: u32 = (2 * MAX_CHUNK_SIZE) - 1;
        const CHUNK_2_START: u32 = 2 * MAX_CHUNK_SIZE;

        // Test chunk_number for files up to 3 * MIN_CHUNK_SIZE - 1.  Should be 0 for all bytes.
        let mut min_test_size = 0;
        let mut max_test_size = 3 * MIN_CHUNK_SIZE;
        for file_size in min_test_size..max_test_size {
            for byte_index in 0..file_size {
                assert_eq!(get_chunk_number(file_size as u64, byte_index as u64), 0);
            }
        }

        // Test chunk_number for files up to 3 * MAX_CHUNK_SIZE.  File should be thirded with any
        // extra bytes appended to last chunk.
        min_test_size = max_test_size;
        max_test_size = (3 * MAX_CHUNK_SIZE) + 1;
        let mut range = Range::new(90000, 100000);
        let mut rng = rand::thread_rng();
        let step = range.sample(&mut rng);
        for file_size in (min_test_size..max_test_size).filter(|&elt| elt % step == 0) {
            assert_eq!(get_num_chunks(file_size as u64), 3);
            let mut index_start;
            let mut index_end = 0;
            for chunk_index in 0..3 {
                index_start = index_end;
                index_end += get_chunk_size(file_size as u64, chunk_index);
                for byte_index in index_start..index_end {
                    assert_eq!(get_chunk_number(file_size as u64, byte_index as u64),
                               chunk_index);
                }
            }
        }

        // Test chunk_number for files up to (3 * MAX_CHUNK_SIZE) + MIN_CHUNK_SIZE - 1.  First two
        // chunks should each have MAX_CHUNK_SIZE bytes, third chunk should have
        // (MAX_CHUNK_SIZE - MIN_CHUNK_SIZE) bytes, with final chunk containing remainder.
        min_test_size = max_test_size;
        max_test_size = (3 * MAX_CHUNK_SIZE) + MIN_CHUNK_SIZE;
        for file_size in min_test_size..max_test_size {
            const CHUNK_2_END: u32 = (3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE - 1;
            assert_eq!(get_num_chunks(file_size as u64), 4);
            let mut test_indices = vec![CHUNK_0_START,
                                        CHUNK_0_END,
                                        CHUNK_1_START,
                                        CHUNK_1_END,
                                        CHUNK_2_START,
                                        CHUNK_2_END];
            test_indices.append(&mut ((CHUNK_2_END + 1)..(file_size - 1)).collect::<Vec<_>>());
            for byte_index in test_indices {
                let expected_number = match byte_index {
                    CHUNK_0_START...CHUNK_0_END => 0,
                    CHUNK_1_START...CHUNK_1_END => 1,
                    CHUNK_2_START...CHUNK_2_END => 2,
                    _ => 3,
                };
                assert_eq!(get_chunk_number(file_size as u64, byte_index as u64),
                           expected_number);
            }
        }

        // Test chunk_number for files up to 4 * MAX_CHUNK_SIZE.  First three chunks should each
        // have MAX_CHUNK_SIZE bytes, fourth chunk containing remainder.
        min_test_size = max_test_size;
        max_test_size = 4 * MAX_CHUNK_SIZE;
        for file_size in (min_test_size..max_test_size).filter(|&elt| elt % step == 0) {
            const CHUNK_2_END: u32 = (3 * MAX_CHUNK_SIZE) - 1;
            assert_eq!(get_num_chunks(file_size as u64), 4);
            let mut test_indices = vec![CHUNK_0_START,
                                        CHUNK_0_END,
                                        CHUNK_1_START,
                                        CHUNK_1_END,
                                        CHUNK_2_START,
                                        CHUNK_2_END];
            test_indices.append(&mut ((CHUNK_2_END + 1)..(file_size - 1)).collect::<Vec<_>>());
            for byte_index in test_indices {
                let expected_number = match byte_index {
                    CHUNK_0_START...CHUNK_0_END => 0,
                    CHUNK_1_START...CHUNK_1_END => 1,
                    CHUNK_2_START...CHUNK_2_END => 2,
                    _ => 3,
                };
                assert_eq!(get_chunk_number(file_size as u64, byte_index as u64),
                           expected_number);
            }
        }
    }
}
