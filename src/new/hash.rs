// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AddressGen, DataReader, EncryptionBatch};
use crate::new::{data_map::ChunkInfo, get_chunk_size, get_num_chunks, get_start_end_positions};
use rayon::prelude::*;

/// Hash all the chunks.
/// Creates [num cores] batches.
pub(crate) fn hashes<R: DataReader, G: AddressGen>(
    data_reader: R,
    address_gen: G,
) -> Vec<EncryptionBatch<R, G>> {
    let file_size = data_reader.size();
    let num_chunks = get_num_chunks(file_size);

    let chunk_infos: Vec<_> = (0..num_chunks)
        .into_iter()
        .map(|index| (index, address_gen.clone(), data_reader.clone()))
        .par_bridge()
        .map(|(index, address_gen, data_reader)| {
            let (start, end) = get_start_end_positions(file_size, index);
            let data = data_reader.read(start, end);
            ChunkInfo {
                index,
                src_hash: address_gen.generate(data),
                src_size: get_chunk_size(file_size, index),
            }
        })
        .collect();

    let mut chunk_infos = chunk_infos.into_iter().peekable();

    let cpus = num_cpus::get();
    let chunks_per_batch = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);
    let mut batches = vec![];

    while chunk_infos.peek().is_some() {
        let _ = batches.push(EncryptionBatch {
            file: data_reader.clone(),
            address_gen: address_gen.clone(),
            file_size,
            chunk_infos: chunk_infos.by_ref().take(chunks_per_batch).collect(),
        });
    }

    batches
}
