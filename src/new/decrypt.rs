// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS"  BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::EncryptedChunk;

use super::get_pad_key_and_iv;
use super::{encryption, xor, Error, Result};
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use std::io::Cursor;
use std::sync::Arc;

pub fn decrypt(encrypted_chunks: &[EncryptedChunk]) -> Result<Bytes> {
    let num_chunks = encrypted_chunks.len();
    let encrypted_chunks = encrypted_chunks
        .iter()
        .sorted_by_key(|c| c.details.index)
        .cloned() // should not be needed, something is wrong here, the docs for sorted_by_key says it will return owned items...!
        .collect_vec();

    let (file_size, src_hashes) = extract(encrypted_chunks.as_slice());

    let cpus = num_cpus::get();
    let batch_size = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);

    let raw_chunks: Vec<(usize, Bytes)> = encrypted_chunks
        .chunks(batch_size)
        .par_bridge()
        .map(|batch| DecryptionBatch {
            jobs: batch
                .iter()
                .map(|c| DecryptionJob {
                    index: c.details.index,
                    encrypted_content: c.encrypted_content.clone(),
                    src_hashes: src_hashes.clone(),
                })
                .collect_vec(),
        })
        .map(|batch| {
            batch
                .jobs
                .par_iter()
                .map(|c| {
                    Ok::<(usize, Bytes), Error>((
                        c.index,
                        decrypt_chunk(
                            c.index,
                            c.encrypted_content.clone(),
                            c.src_hashes.as_ref(),
                            file_size,
                        )?,
                    ))
                })
                .collect::<Vec<_>>()
        })
        .flatten()
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

struct DecryptionBatch {
    jobs: Vec<DecryptionJob>,
}

struct DecryptionJob {
    index: usize,
    encrypted_content: Bytes,
    src_hashes: Arc<Vec<Bytes>>,
}

fn extract(chunks: &[EncryptedChunk]) -> (usize, Arc<Vec<Bytes>>) {
    let mut file_size = 0;
    let mut src_hashes = vec![];
    for c in chunks.iter() {
        file_size += c.details.src_size;
        src_hashes.push(c.details.src_hash.clone());
    }
    (file_size, Arc::new(src_hashes))
}

pub(crate) fn decrypt_chunk(
    chunk_number: usize,
    content: Bytes,
    chunk_hashes: &[Bytes],
    file_size: usize,
) -> Result<Bytes> {
    let (pad, key, iv) = get_pad_key_and_iv(chunk_number, chunk_hashes, file_size);
    let xor_result = xor(content, &pad);
    let decrypted = encryption::decrypt(xor_result, &key, &iv)?;
    let mut decompressed = vec![];
    brotli::BrotliDecompress(&mut Cursor::new(decrypted), &mut decompressed)
        .map(|_| Bytes::from(decompressed))
        .map_err(|_| Error::Compression)
}
