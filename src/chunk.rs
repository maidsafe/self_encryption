// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{get_num_chunks, get_start_end_positions};
use bytes::Bytes;
use rayon::prelude::*;
use xor_name::XorName;

#[derive(Clone)]
pub(crate) struct EncryptionBatch {
    pub(crate) raw_chunks: Vec<RawChunk>,
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

/// Hash all the chunks.
/// Creates [num cores] batches.
pub(crate) fn batch_chunks(bytes: Bytes) -> (usize, Vec<EncryptionBatch>) {
    let data_size = bytes.len();
    let num_chunks = get_num_chunks(data_size);

    let raw_chunks: Vec<_> = (0..num_chunks)
        .map(|index| (index, bytes.clone()))
        .par_bridge()
        .map(|(index, bytes)| {
            let (start, end) = get_start_end_positions(data_size, index);
            let data = bytes.slice(start..end);
            let hash = XorName::from_content(data.as_ref());
            RawChunk { index, data, hash }
        })
        .collect();

    let mut raw_chunks = raw_chunks.into_iter().peekable();

    let cpus = num_cpus::get();
    let chunks_per_batch = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);
    let mut batches = vec![];

    while raw_chunks.peek().is_some() {
        batches.push(EncryptionBatch {
            raw_chunks: raw_chunks.by_ref().take(chunks_per_batch).collect(),
        });
    }

    (num_chunks, batches)
}

/// Calculate (start_position, end_position) for each chunk for the input file size
pub(crate) fn batch_positions(data_size: usize) -> Vec<(usize, usize)> {
    let num_chunks = get_num_chunks(data_size);

    (0..num_chunks)
        .map(|index| get_start_end_positions(data_size, index))
        .collect()
}
