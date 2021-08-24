// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{data_map::RawChunk, get_num_chunks, get_start_end_positions, hash, EncryptionBatch};
use bytes::Bytes;
use rayon::prelude::*;

/// Hash all the chunks.
/// Creates [num cores] batches.
pub(crate) fn batch_chunks(bytes: Bytes) -> Vec<EncryptionBatch> {
    let data_size = bytes.len();
    let num_chunks = get_num_chunks(data_size);

    let chunk_infos: Vec<_> = (0..num_chunks)
        .into_iter()
        .map(|index| (index, bytes.clone()))
        .par_bridge()
        .map(|(index, bytes)| {
            let (start, end) = get_start_end_positions(data_size, index);
            let data = bytes.slice(start..end);
            let hash = hash(data.as_ref());
            RawChunk { index, data, hash }
        })
        .collect();

    let mut chunk_infos = chunk_infos.into_iter().peekable();

    let cpus = num_cpus::get();
    let chunks_per_batch = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);
    let mut batches = vec![];

    while chunk_infos.peek().is_some() {
        let _ = batches.push(EncryptionBatch {
            data_size: bytes.len(),
            chunk_infos: chunk_infos.by_ref().take(chunks_per_batch).collect(),
        });
    }

    batches
}
