// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// Struct holds pre and post encryption hashes as well as original chunk size.
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ChunkDetails {
    /// Index number (starts at 0)
    pub chunk_num: u32,
    /// Post encryption hash of chunk
    pub hash: Vec<u8>,
    /// Pre encryption hash of chunk
    pub pre_hash: Vec<u8>,
    /// size before encryption (compression alters this as well as any possible padding depending
    /// on cipher used)
    pub source_size: u64,
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

/// Holds the information that is required to recover the content of the encrypted file.  Depending
/// on the file size, such info can be held as a vector of ChunkDetails, or as raw data.
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum DataMap {
    /// If the file is large enough (larger than 3072 bytes, 3 * MIN_CHUNK_SIZE), this algorithm
    /// holds the list of the files chunks and corresponding hashes.
    Chunks(Vec<ChunkDetails>),
    /// Very small files (less than 3072 bytes, 3 * MIN_CHUNK_SIZE) are not split into chunks and
    /// are put in here in their entirety.
    Content(Vec<u8>),
    /// empty datamap
    None,
}

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

    /// Iterates through the chunks to figure out the total size, i.e. the file size
    fn chunks_size(chunks: &[ChunkDetails]) -> u64 {
        chunks.iter().fold(0, |acc, chunk| acc + chunk.source_size)
    }

    /// Sorts list of chunks using quicksort
    fn chunks_sort(chunks: &mut [ChunkDetails]) {
        chunks.sort_by(|a, b| a.chunk_num.cmp(&b.chunk_num));
    }
}

#[test]
fn dummy() {}
