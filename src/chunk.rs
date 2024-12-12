// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;

/// The actual encrypted content of the chunk
#[derive(Clone, Debug)]
pub struct EncryptedChunk {
    /// The encrypted content of the chunk
    pub content: Bytes,
}

/// Calculate (start_position, end_position) for each chunk for the input file size
pub(crate) fn batch_positions(data_size: usize) -> Vec<(usize, usize)> {
    let num_chunks = crate::get_num_chunks(data_size);

    (0..num_chunks)
        .map(|index| crate::get_start_end_positions(data_size, index))
        .collect()
}
