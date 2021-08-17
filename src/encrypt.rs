// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    data_map::ChunkKey,
    data_map::RawChunk,
    encryption::{self, Iv, Key, Pad},
    error::{Error, Result},
    get_pad_key_and_iv, xor, EncryptedChunk, EncryptionBatch, COMPRESSION_QUALITY,
};
use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use std::io::Cursor;
use std::sync::Arc;

/// Encrypt the chunks
pub fn encrypt(batches: Vec<EncryptionBatch>) -> Vec<Result<EncryptedChunk>> {
    let src_hashes = Arc::new(
        batches
            .iter()
            .map(|b| &b.chunk_infos)
            .flatten()
            .sorted_by_key(|c| c.index)
            .map(|d| &d.hash)
            .cloned()
            .collect_vec(),
    );

    batches
        .into_iter()
        .map(|batch| (batch, src_hashes.clone()))
        .par_bridge()
        .map(|(batch, src_hashes)| {
            batch
                .chunk_infos
                .par_iter()
                .map(|chunk| {
                    let RawChunk { index, data, hash } = chunk.clone();

                    let src_size = data.len();
                    let pki = get_pad_key_and_iv(index, src_hashes.as_ref());
                    let encrypted_content = encrypt_chunk(data, pki)?;
                    let dst_hash = crate::hash(encrypted_content.as_ref());

                    Ok(EncryptedChunk {
                        content: encrypted_content,
                        key: ChunkKey {
                            index,
                            dst_hash,
                            src_hash: hash,
                            src_size,
                        },
                    })
                })
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect()
}

fn encrypt_chunk(content: Bytes, pki: (Pad, Key, Iv)) -> Result<Bytes> {
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
    Ok(xor(encrypted, &pad))
}
