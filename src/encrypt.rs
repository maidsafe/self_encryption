// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk::{EncryptionBatch, RawChunk},
    data_map::DataMap,
    encryption::{self, Iv, Key, Pad},
    error::Error,
    utils::{get_pad_key_and_iv, xor},
    ChunkInfo, EncryptedChunk, Result, COMPRESSION_QUALITY,
};

use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use std::{io::Cursor, sync::Arc};
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
            |(mut keys, mut chunks),
             result: std::result::Result<(ChunkInfo, EncryptedChunk), Error>| {
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

/// Encrypt chunks in a streaming fashion, processing them in the correct order to satisfy the
/// encryption requirements. Each chunk is encrypted using the hashes of two other chunks:
/// - For chunk 0: Uses hashes of the last two chunks
/// - For chunk 1: Uses hash of chunk 0 and the last chunk
/// - For chunks 2+: Uses hashes of the previous two chunks
pub(crate) fn encrypt_stream(
    chunks: Vec<RawChunk>,
) -> Result<DataMap> {
    // Create a sorted vector of all hashes - we still need this for encryption
    let src_hashes: Vec<_> = chunks.iter().map(|c| c.hash).collect();
    let mut keys = Vec::with_capacity(chunks.len());
    
    // First, process chunks 2 onwards in parallel since they only need their previous two hashes
    let later_chunks: Vec<_> = chunks.iter().skip(2).collect();
    let later_chunk_infos: Vec<ChunkInfo> = later_chunks
        .into_par_iter()
        .map(|chunk| {
            let RawChunk { index, data, hash } = chunk;
            let src_size = data.len();
            
            let pki = get_pad_key_and_iv(*index, &src_hashes);
            let encrypted_content = encrypt_chunk(data.clone(), pki)?;
            let dst_hash = XorName::from_content(encrypted_content.as_ref());
            
            Ok(ChunkInfo {
                index: *index,
                dst_hash,
                src_hash: *hash,
                src_size,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    
    keys.extend(later_chunk_infos);
    
    // Process chunk 1 (needs hash 0 and last hash)
    let chunk = &chunks[1];
    let pki = get_pad_key_and_iv(1, &src_hashes);
    let encrypted_content = encrypt_chunk(chunk.data.clone(), pki)?;
    let dst_hash = XorName::from_content(encrypted_content.as_ref());
    
    // Insert at beginning since this is chunk 1
    keys.insert(
        0,
        ChunkInfo {
            index: 1,
            dst_hash,
            src_hash: chunk.hash,
            src_size: chunk.data.len(),
        },
    );
    
    // Process chunk 0 (needs last two hashes)
    let chunk = &chunks[0];
    let pki = get_pad_key_and_iv(0, &src_hashes);
    let encrypted_content = encrypt_chunk(chunk.data.clone(), pki)?;
    let dst_hash = XorName::from_content(encrypted_content.as_ref());
    
    // Insert at beginning since this is chunk 0
    keys.insert(
        0,
        ChunkInfo {
            index: 0,
            dst_hash,
            src_hash: chunk.hash,
            src_size: chunk.data.len(),
        },
    );
    
    Ok(DataMap::new(keys))
}
