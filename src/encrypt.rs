// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk::{EncryptionBatch, RawChunk},
    data_map::ChunkInfo,
    encryption::{self, Iv, Key, Pad},
    error::{Error, Result},
    get_pad_key_and_iv, xor, DataMap, EncryptedChunk, COMPRESSION_QUALITY,
};
use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use std::io::Cursor;
use std::sync::Arc;
use xor_name::XorName;

/// Encrypt the chunks
pub(crate) fn encrypt(batches: Vec<EncryptionBatch>) -> (DataMap, Vec<EncryptedChunk>) {
    let src_hashes = Arc::new(
        batches
            .iter()
            .flat_map(|b| &b.raw_chunks)
            .sorted_by_key(|c| c.index)
            .map(|d| &d.hash)
            .cloned()
            .collect_vec(),
    );

    let (keys, chunks) = batches
        .into_iter()
        .map(|batch| (batch, src_hashes.clone()))
        .par_bridge()
        .map(|(batch, src_hashes)| {
            batch
                .raw_chunks
                .par_iter()
                .map(|chunk| {
                    let RawChunk { index, data, hash } = chunk.clone();

                    let src_size = data.len();
                    let pki = get_pad_key_and_iv(index, src_hashes.as_ref());
                    let encrypted_content = encrypt_chunk(data, pki)?;
                    let dst_hash = XorName::from_content(encrypted_content.as_ref());

                    Ok((
                        ChunkInfo {
                            index,
                            dst_hash,
                            src_hash: hash,
                            src_size,
                        },
                        EncryptedChunk {
                            content: encrypted_content,
                        },
                    ))
                })
                .collect::<Vec<_>>()
        })
        .flatten()
        .fold(
            || (vec![], vec![]),
            |(mut keys, mut chunks), result: Result<_, Error>| {
                if let Ok((key, chunk)) = result {
                    keys.push(key);
                    chunks.push(chunk);
                }
                (keys, chunks)
            },
        )
        .reduce(
            || (vec![], vec![]),
            |(mut keys, mut chunks), (key_subset, chunk_subset)| {
                keys.extend(key_subset);
                chunks.extend(chunk_subset);
                (keys, chunks)
            },
        );

    (DataMap::new(keys), chunks)
}

/// Encrypt the chunk
pub(crate) fn encrypt_chunk(content: Bytes, pki: (Pad, Key, Iv)) -> Result<Bytes> {
    let (pad, key, iv) = pki;
    let mut compressed = vec![];
    let enc_params = BrotliEncoderParams {
        quality: COMPRESSION_QUALITY,
        ..Default::default()
    };
    let _size = brotli::BrotliCompress(
        &mut Cursor::new(content.as_ref()),
        &mut compressed,
        &enc_params,
    )
    .map_err(|_| Error::Compression)?;
    let encrypted = encryption::encrypt(Bytes::from(compressed), &key, &iv)?;
    Ok(xor(&encrypted, &pad))
}
