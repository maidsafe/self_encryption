// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;

use super::{data_map::ChunkInfo, get_pad_key_and_iv};
use super::{encryption, xor, Error, Result};
use std::io::Cursor;

#[allow(unused)]
pub(crate) async fn decrypt<S>(
    chunk_number: usize,
    content: Bytes,
    chunk_hashes: &[ChunkInfo],
    file_size: usize,
) -> Result<Vec<u8>> {
    let (pad, key, iv) = get_pad_key_and_iv(chunk_number, chunk_hashes, file_size);
    let xor_result = xor(content, &pad);
    let decrypted = encryption::decrypt(xor_result, &key, &iv)?;
    let mut decompressed = vec![];
    brotli::BrotliDecompress(&mut Cursor::new(decrypted), &mut decompressed)
        .map(|_| decompressed)
        .map_err(|_| Error::Compression)
}
