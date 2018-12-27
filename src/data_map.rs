// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::fmt::{Debug, Error, Formatter, Write};

/// Holds pre- and post-encryption hashes as well as the original (pre-compression) size for a given
/// chunk.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct ChunkDetails {
    /// Index number (starts at 0)
    pub chunk_num: u32,
    /// Post-encryption hash of chunk
    pub hash: Vec<u8>,
    /// Pre-encryption hash of chunk
    pub pre_hash: Vec<u8>,
    /// Size before encryption (compression alters this as well as any possible padding depending
    /// on cipher used)
    pub source_size: u64,
}

fn debug_bytes<V: AsRef<[u8]>>(input: V) -> String {
    let input_ref = input.as_ref();
    if input_ref.is_empty() {
        return "<empty>".to_owned();
    }
    if input_ref.len() <= 6 {
        let mut ret = String::new();
        for byte in input_ref.iter() {
            write!(ret, "{:02x}", byte).unwrap_or(());
        }
        return ret;
    }
    format!(
        "{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
        input_ref[0],
        input_ref[1],
        input_ref[2],
        input_ref[input_ref.len() - 3],
        input_ref[input_ref.len() - 2],
        input_ref[input_ref.len() - 1]
    )
}

impl ChunkDetails {
    /// Holds information required for successful recovery of a chunk, as well as for the
    /// encryption/decryption of it's two immediate successors, modulo the number of chunks in the
    /// corresponding DataMap.
    pub fn new() -> ChunkDetails {
        ChunkDetails {
            chunk_num: 0,
            hash: vec![],
            pre_hash: vec![],
            source_size: 0,
        }
    }
}

impl Debug for ChunkDetails {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        write!(
            formatter,
            "ChunkDetails {{ chunk_num: {}, hash: {}, pre_hash: {}, source_size: {} }}",
            self.chunk_num,
            debug_bytes(&self.hash),
            debug_bytes(&self.pre_hash),
            self.source_size
        )
    }
}

/// Holds the information that is required to recover the content of the encrypted file.  Depending
/// on the file size, this is held as a vector of `ChunkDetails`, or as raw data.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum DataMap {
    /// If the file is large enough (larger than 3072 bytes, 3 * MIN_CHUNK_SIZE), this algorithm
    /// holds the list of the file's chunks and corresponding hashes.
    Chunks(Vec<ChunkDetails>),
    /// Very small files (less than 3072 bytes, 3 * MIN_CHUNK_SIZE) are not split into chunks and
    /// are put in here in their entirety.
    Content(Vec<u8>),
    /// empty datamap
    None,
}

#[allow(clippy::len_without_is_empty)]
impl DataMap {
    /// Original (pre-encryption) size of file in DataMap.
    pub fn len(&self) -> u64 {
        match *self {
            DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks),
            DataMap::Content(ref content) => content.len() as u64,
            DataMap::None => 0,
        }
    }

    /// Returns the list of chunks pre and post encryption hashes if present.
    pub fn get_chunks(&self) -> Vec<ChunkDetails> {
        match *self {
            DataMap::Chunks(ref chunks) => chunks.to_vec(),
            _ => panic!("no chunks"),
        }
    }

    /// The algorithm requires this to be a sorted list to allow get_pad_iv_key to obtain the
    /// correct pre-encryption hashes for decryption/encryption.
    pub fn get_sorted_chunks(&self) -> Vec<ChunkDetails> {
        match *self {
            DataMap::Chunks(ref chunks) => {
                let mut result = chunks.to_vec();
                DataMap::chunks_sort(&mut result);
                result
            }
            _ => panic!("no chunks"),
        }
    }

    /// Whether the content is stored as chunks or as raw data.
    pub fn has_chunks(&self) -> bool {
        match *self {
            DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks) > 0,
            _ => false,
        }
    }

    /// Sorts list of chunks using quicksort
    pub fn chunks_sort(chunks: &mut [ChunkDetails]) {
        chunks.sort_by(|a, b| a.chunk_num.cmp(&b.chunk_num));
    }

    /// Iterates through the chunks to figure out the total size, i.e. the file size
    fn chunks_size(chunks: &[ChunkDetails]) -> u64 {
        chunks.iter().fold(0, |acc, chunk| acc + chunk.source_size)
    }
}

impl Debug for DataMap {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        match *self {
            DataMap::Chunks(ref chunks) => {
                writeln!(formatter, "DataMap::Chunks:")?;
                let len = chunks.len();
                for (index, chunk) in chunks.iter().enumerate() {
                    if index + 1 == len {
                        write!(formatter, "        {:?}", chunk)?
                    } else {
                        writeln!(formatter, "        {:?}", chunk)?
                    }
                }
                Ok(())
            }
            DataMap::Content(ref content) => {
                write!(formatter, "DataMap::Content({})", debug_bytes(content))
            }
            DataMap::None => write!(formatter, "DataMap::None"),
        }
    }
}
