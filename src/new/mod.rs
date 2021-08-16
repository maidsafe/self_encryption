// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod data_map;
mod decrypt;
mod encrypt;
mod encryption;
mod error;
mod hash;
mod sequential;
mod storage;
pub mod test_helpers;
#[cfg(test)]
mod tests;

pub use self::{
    data_map::{ChunkDetails, DataMap},
    error::{Error, Result},
    storage::Storage,
};
use self::{
    decrypt::decrypt,
    encryption::{IV_SIZE, KEY_SIZE},
    sequential::{Iv, Key, Pad, PAD_SIZE},
};
use super::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use bytes::Bytes;
use data_map::ChunkInfo;

///
pub trait AddressGen: Send + Sync + 'static + Clone {
    ///
    fn generate(&self, data: Bytes) -> Bytes;
}

///
pub trait DataReader: Send + Sync + 'static + Clone {
    ///
    fn size(&self) -> usize;
    ///
    fn read(&self, start: usize, end: usize) -> Bytes;
}

///
#[derive(Clone)]
pub struct EncryptionBatch<R: DataReader, G: AddressGen> {
    file: R,
    address_gen: G,
    file_size: usize,
    chunk_infos: Vec<ChunkInfo>,
}

/// The actual encrypted content
/// of the chunk, and its details for
/// insertion into a data map.
#[derive(Clone)]
pub struct ChunkContent {
    /// Details, used to find the chunk and decrypt it.
    pub details: ChunkDetails,
    /// The encrypted contents of the chunk.
    pub encrypted_content: Bytes,
}

///
pub fn to_chunks<R: DataReader, G: AddressGen>(
    data_reader: R,
    address_gen: G,
) -> Result<Vec<ChunkContent>> {
    let batches = hash::hashes(data_reader, address_gen);
    let chunks = encrypt::encrypt(batches);
    let count = chunks.len();
    let chunks: Vec<_> = chunks.into_iter().flatten().collect();
    if count > chunks.len() {
        return Err(Error::Encryption);
    }
    Ok(chunks)
}

///
pub fn from_chunks(encrypted_chunks: &[ChunkContent]) -> Result<Bytes> {
    decrypt(encrypted_chunks)
}

fn get_pad_key_and_iv(
    chunk_index: usize,
    chunk_hashes: &[Bytes],
    file_size: usize,
) -> (Pad, Key, Iv) {
    let n_1 = get_previous_chunk_index(file_size, chunk_index);
    let n_2 = get_previous_chunk_index(file_size, n_1);
    let src_hash = &chunk_hashes[chunk_index];
    let n_1_src_hash = &chunk_hashes[n_1];
    let n_2_src_hash = &chunk_hashes[n_2];
    //assert_eq!(n_1_src_hash.len(), HASH_SIZE);
    //assert_eq!(n_2_src_hash.len(), HASH_SIZE);

    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in pad
        .iter_mut()
        .zip(src_hash.iter().chain(n_2_src_hash.iter()))
    {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().chain(iv.iter_mut()).zip(n_1_src_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
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
fn get_chunk_size(file_size: usize, chunk_index: usize) -> usize {
    if file_size < 3 * MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE {
        if chunk_index < 2 {
            return file_size / 3;
        } else {
            return file_size - (2 * (file_size / 3));
        }
    }
    if chunk_index < get_num_chunks(file_size) - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = file_size % MAX_CHUNK_SIZE;
    let penultimate = (get_num_chunks(file_size) - 2) == chunk_index;
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
fn get_start_end_positions(file_size: usize, chunk_index: usize) -> (usize, usize) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start;
    let last = (get_num_chunks(file_size) - 1) == chunk_index;
    if last {
        start = get_chunk_size(file_size, 0) * (chunk_index - 1)
            + get_chunk_size(file_size, chunk_index - 1);
    } else {
        start = get_chunk_size(file_size, 0) * chunk_index;
    }
    (start, start + get_chunk_size(file_size, chunk_index))
}

fn get_previous_chunk_index(file_size: usize, chunk_index: usize) -> usize {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }
    (get_num_chunks(file_size) + chunk_index - 1) % get_num_chunks(file_size)
}

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub(crate) fn xor(data: Bytes, &Pad(pad): &Pad) -> Bytes {
    let vec: Vec<_> = data
        .iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect();
    Bytes::from(vec)
}

use tiny_keccak::{Hasher, Sha3};

///
#[derive(Clone)]
pub struct Generator {}

impl AddressGen for Generator {
    fn generate(&self, data: Bytes) -> Bytes {
        let mut hasher = Sha3::v256();
        let mut output = [0; 32];
        hasher.update(data.as_ref());
        hasher.finalize(&mut output);
        Bytes::from(output.to_vec())
    }
}

///
#[derive(Clone)]
pub struct MemFileReader {
    data: Bytes,
}

impl MemFileReader {
    ///
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl DataReader for MemFileReader {
    fn size(&self) -> usize {
        self.data.len()
    }

    fn read(&self, start: usize, end: usize) -> Bytes {
        self.data.slice(start..end)
    }
}

///
#[derive(Clone)]
pub struct FileReader {
    size: usize,
    path: std::path::PathBuf,
}

impl FileReader {
    ///
    pub fn new(path: std::path::PathBuf) -> Self {
        use std::fs;
        let metadata = fs::metadata(path.as_path()).unwrap();
        Self {
            path,
            size: metadata.len() as usize,
        }
    }
}

use positioned_io_preview as positioned_io;

impl DataReader for FileReader {
    fn size(&self) -> usize {
        self.size
    }

    fn read(&self, start: usize, end: usize) -> Bytes {
        use positioned_io::{RandomAccessFile, ReadAt};
        let raf = RandomAccessFile::open(self.path.as_path()).unwrap();
        let mut buf = vec![0; end]; // This line creates a vector of size `end` where every element is initialized to 0.
        let _bytes_read = raf.read_at(start as u64, &mut buf).unwrap();
        Bytes::from(buf)
    }
}
