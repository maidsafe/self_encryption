// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS"  BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{encryption, get_pad_key_and_iv, xor, EncryptedChunk, Error, Result};
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use std::io::Cursor;
use xor_name::XorName;

pub fn decrypt(src_hashes: Vec<XorName>, encrypted_chunks: &[&EncryptedChunk]) -> Result<Bytes> {
    let num_chunks = encrypted_chunks.len();
    let cpus = num_cpus::get();
    let batch_size = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);

    let raw_chunks: Vec<(usize, Bytes)> = encrypted_chunks
        .chunks(batch_size)
        .par_bridge()
        .map(|batch| {
            let mut decrypted_batch = Vec::with_capacity(batch.len());
            let iter = batch
                .par_iter()
                .map(|c| {
                    // we can pass &src_hashes since Rayon uses scopes under the hood which guarantees that threads are
                    // joined before src_hashes goes out of scope
                    let bytes = decrypt_chunk(c.index, &c.content, &src_hashes)?;
                    Ok::<(usize, Bytes), Error>((c.index, bytes))
                })
                .flatten();
            decrypted_batch.par_extend(iter);
            decrypted_batch
        })
        .flatten()
        .collect();

    if num_chunks > raw_chunks.len() {
        return Err(Error::Generic(format!(
            "Failed to decrypt all chunks (num_chunks: {}, raw_chunks: {}",
            num_chunks,
            raw_chunks.len()
        )));
    }

    let raw_data: Bytes = raw_chunks
        .into_iter()
        .sorted_by_key(|(index, _)| *index)
        .flat_map(|(_, bytes)| bytes)
        .collect();

    Ok(raw_data)
}

pub(crate) fn decrypt_chunk(
    chunk_number: usize,
    content: &Bytes,
    chunk_hashes: &[XorName],
) -> Result<Bytes> {
    let (pad, key, iv) = get_pad_key_and_iv(chunk_number, chunk_hashes);
    let xor_result = xor(content, &pad);
    let decrypted = encryption::decrypt(xor_result, &key, &iv)?;
    let mut decompressed = vec![];
    brotli::BrotliDecompress(&mut Cursor::new(decrypted), &mut decompressed)
        .map(|_| Bytes::from(decompressed))
        .map_err(|_| Error::Compression)
}
