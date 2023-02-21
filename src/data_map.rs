// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Result;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter, Write};
use xor_name::XorName;

/// Holds the information that is required to recover the content of the encrypted file.
/// This is held as a vector of `ChunkInfo`, i.e. a list of the file's chunk hashes.
/// Only files larger than 3072 bytes (3 * MIN_CHUNK_SIZE) can be self-encrypted.
/// Smaller files will have to be batched together.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DataMap(Vec<ChunkInfo>);

#[allow(clippy::len_without_is_empty)]
impl DataMap {
    /// A new instance from a vec of partial keys.
    ///
    /// Sorts on instantiation.
    /// The algorithm requires this to be a sorted list to allow get_pad_iv_key to obtain the
    /// correct pre-encryption hashes for decryption/encryption.
    pub fn new(mut keys: Vec<ChunkInfo>) -> Self {
        keys.sort_by(|a, b| a.index.cmp(&b.index));
        Self(keys)
    }

    /// Original (pre-encryption) size of the file.
    pub fn file_size(&self) -> usize {
        DataMap::total_size(&self.0)
    }

    /// Returns the list of chunks pre and post encryption hashes if present.
    pub fn infos(&self) -> Vec<ChunkInfo> {
        self.0.to_vec()
    }

    /// Iterates through the keys to figure out the total size of the data, i.e. the file size.
    fn total_size(keys: &[ChunkInfo]) -> usize {
        keys.iter().fold(0, |acc, chunk| acc + chunk.src_size)
    }
}

impl Debug for DataMap {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        writeln!(formatter, "DataMap:")?;
        let len = self.0.len();
        for (index, chunk) in self.0.iter().enumerate() {
            if index + 1 == len {
                write!(formatter, "        {:?}", chunk)?
            } else {
                writeln!(formatter, "        {:?}", chunk)?
            }
        }
        Ok(())
    }
}

/// This is - in effect - a partial decryption key for an encrypted chunk of data.
///
/// It holds pre- and post-encryption hashes as well as the original
/// (pre-compression) size for a given chunk.
/// This information is required for successful recovery of a chunk, as well as for the
/// encryption/decryption of it's two immediate successors, modulo the number of chunks in the
/// corresponding DataMap.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct ChunkInfo {
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

impl Debug for ChunkInfo {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            formatter,
            "ChunkInfo {{ index: {}, dst_hash: {}, src_hash: {}, src_size: {} }}",
            self.index,
            debug_bytes(self.dst_hash),
            debug_bytes(self.src_hash),
            self.src_size
        )
    }
}
