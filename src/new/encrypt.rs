// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    data_map::ChunkDetails, get_pad_key_and_iv, get_start_end_positions, AddressGen, ChunkBatch,
    ChunkContent, DataReader, Pad,
};
use super::{
    encryption,
    error::{Error, Result},
    sequential::{Iv, Key},
    xor,
};
use crate::COMPRESSION_QUALITY;
use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use std::io::Cursor;
use std::sync::Arc;

/// Encrypt the chunks
pub fn encrypt<R: DataReader, G: AddressGen>(
    batches: Vec<ChunkBatch<R, G>>,
) -> Vec<Result<ChunkContent>> {
    let all_infos = Arc::new(
        batches
            .iter()
            .map(|b| &b.chunk_infos)
            .flatten()
            .sorted_by_key(|c| c.index)
            .cloned()
            .collect_vec(),
    );

    batches
        .into_iter()
        .map(|batch| (batch, all_infos.clone()))
        .par_bridge()
        .map(|(batch, all_infos)| {
            batch
                .chunk_infos
                .par_iter()
                .map(|chunk| {
                    let (start, end) = get_start_end_positions(batch.file_size, chunk.index);
                    let pki = get_pad_key_and_iv(chunk.index, all_infos.as_ref(), batch.file_size);

                    let data = batch.file.read(start, end);
                    let encrypted_content = encrypt_chunk(data, pki)?;
                    let hash = batch.address_gen.generate(encrypted_content.clone());

                    Ok(ChunkContent {
                        encrypted_content,
                        details: ChunkDetails {
                            index: chunk.index,
                            dst_hash: hash,
                            src_hash: chunk.src_hash.clone(),
                            src_size: chunk.src_size,
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
    let result = brotli::BrotliCompress(
        &mut Cursor::new(content.as_ref()),
        &mut compressed,
        &enc_params,
    );
    if result.is_err() {
        return Err(Error::Compression);
    }
    let encrypted = encryption::encrypt(Bytes::from(compressed), &key, &iv)?;
    Ok(xor(encrypted, &pad))
}
