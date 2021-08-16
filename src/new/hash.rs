// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AddressGen, EncryptionBatch};
use crate::new::{data_map::ChunkInfo, get_chunk_size, get_num_chunks, get_start_end_positions};
use bytes::Bytes;
use rayon::prelude::*;

/// Hash all the chunks.
/// Creates [num cores] batches.
pub(crate) fn hashes<G: AddressGen>(bytes: Bytes, address_gen: G) -> Vec<EncryptionBatch<G>> {
    let data_size = bytes.len();
    let num_chunks = get_num_chunks(data_size);

    let chunk_infos: Vec<_> = (0..num_chunks)
        .into_iter()
        .map(|index| (index, address_gen.clone(), bytes.clone()))
        .par_bridge()
        .map(|(index, address_gen, bytes)| {
            let (start, end) = get_start_end_positions(data_size, index);
            let data = bytes.slice(start..end);
            let src_hash = address_gen.generate(data.as_ref());
            let src_size = get_chunk_size(data_size, index);
            ChunkInfo {
                index,
                data,
                src_hash,
                src_size,
            }
        })
        .collect();

    let mut chunk_infos = chunk_infos.into_iter().peekable();

    let cpus = num_cpus::get();
    let chunks_per_batch = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);
    let mut batches = vec![];

    while chunk_infos.peek().is_some() {
        let _ = batches.push(EncryptionBatch {
            data_size: bytes.len(),
            address_gen: address_gen.clone(),
            chunk_infos: chunk_infos.by_ref().take(chunks_per_batch).collect(),
        });
    }

    batches
}
