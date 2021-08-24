// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Error, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter, Write};
use xor_name::XorName;

/// Holds the information that is required to recover the content of the encrypted file.  Depending
/// on the file size, this is held as a vector of `ChunkKey`, or as raw data.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum DataMap {
    /// If the file is large enough (larger than 3072 bytes, 3 * MIN_CHUNK_SIZE), this algorithm
    /// holds the list of the file's chunks and corresponding hashes.
    Chunks(Vec<ChunkKey>),
    /// Very small files (less than 3072 bytes, 3 * MIN_CHUNK_SIZE) are not split into chunks and
    /// are put in here in their entirety.
    Content(Bytes),
}

#[allow(clippy::len_without_is_empty)]
impl DataMap {
    /// Original (pre-encryption) size of file in DataMap.
    pub fn file_size(&self) -> usize {
        match *self {
            DataMap::Chunks(ref chunks) => DataMap::total_size(chunks),
            DataMap::Content(ref content) => content.len(),
        }
    }

    /// Returns the list of chunks pre and post encryption hashes if present.
    pub fn keys(&self) -> Result<Vec<ChunkKey>> {
        match *self {
            DataMap::Chunks(ref keys) => Ok(keys.to_vec()),
            _ => Err(Error::Generic("no keys".to_string())),
        }
    }

    /// The algorithm requires this to be a sorted list to allow get_pad_iv_key to obtain the
    /// correct pre-encryption hashes for decryption/encryption.
    pub fn sorted_keys(&self) -> Result<Vec<ChunkKey>> {
        match *self {
            DataMap::Chunks(ref keys) => {
                let mut to_return = keys.to_vec();
                DataMap::sort_keys(&mut to_return);
                Ok(to_return)
            }
            _ => Err(Error::Generic("no keys".to_string())),
        }
    }

    /// Whether the content is stored as chunks or as raw data.
    pub fn is_chunked(&self) -> bool {
        matches!(self, DataMap::Chunks(_))
    }

    /// Sorts list of chunk keys using quicksort
    pub fn sort_keys(keys: &mut [ChunkKey]) {
        keys.sort_by(|a, b| a.index.cmp(&b.index));
    }

    /// Iterates through the keys to figure out the total size of the data, i.e. the file size.
    fn total_size(keys: &[ChunkKey]) -> usize {
        keys.iter().fold(0, |acc, chunk| acc + chunk.src_size)
    }
}

impl Debug for DataMap {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), std::fmt::Error> {
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
        }
    }
}

/// The clear text bytes of a chunk
/// from a larger piece of data,
/// and its index in the set of chunks.
#[derive(Clone)]
pub struct RawChunk {
    /// The index of this chunk, in the set of chunks
    /// obtained from a larger piece of data.
    pub index: usize,
    /// The raw data.
    pub data: Bytes,
    /// The hash of the raw data in this chunk.
    pub hash: XorName,
}

/// This is - in effect - a partial decryption key for an encrypted chunk of data.
///
/// It holds pre- and post-encryption hashes as well as the original
/// (pre-compression) size for a given chunk.
/// This information is required for successful recovery of a chunk, as well as for the
/// encryption/decryption of it's two immediate successors, modulo the number of chunks in the
/// corresponding DataMap.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct ChunkKey {
    /// Index number (zero-based)
    pub index: usize,
    /// Post-encryption hash of chunk
    pub dst_hash: XorName,
    /// Pre-encryption hash of chunk
    pub src_hash: XorName,
    /// Size before encryption and compression (any possible padding depending
    /// on cipher used alters this)
    pub src_size: usize,
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

impl Debug for ChunkKey {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            formatter,
            "ChunkKey {{ index: {}, dst_hash: {}, src_hash: {}, src_size: {} }}",
            self.index,
            debug_bytes(&self.dst_hash),
            debug_bytes(&self.src_hash),
            self.src_size
        )
    }
}
