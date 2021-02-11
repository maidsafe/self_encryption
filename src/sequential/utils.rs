// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Pad, SelfEncryptionError, COMPRESSION_QUALITY, PAD_SIZE};
use crate::{
    data_map::ChunkDetails,
    encryption::{self, IV_SIZE, KEY_SIZE},
    sequential::{Iv, Key},
};
use brotli::{self, enc::BrotliEncoderParams};
#[cfg(test)]
use rand::Rng;
#[cfg(test)]
use std::cmp;
use std::io::Cursor;

pub fn get_pad_key_and_iv(chunk_index: usize, chunks: &[ChunkDetails]) -> (Pad, Key, Iv) {
    let (n_1, n_2) = match chunk_index {
        0 => (chunks.len() - 1, chunks.len() - 2),
        1 => (0, chunks.len() - 1),
        n => (n - 1, n - 2),
    };
    let this_pre_hash = &chunks[chunk_index].pre_hash;
    let n_1_pre_hash = &chunks[n_1].pre_hash;
    let n_2_pre_hash = &chunks[n_2].pre_hash;

    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in pad
        .iter_mut()
        .chain(iv.iter_mut())
        .zip(this_pre_hash.iter().chain(n_2_pre_hash.iter()))
    {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().zip(n_1_pre_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

pub fn encrypt_chunk(
    content: &[u8],
    pad_key_iv: (Pad, Key, Iv),
) -> Result<Vec<u8>, SelfEncryptionError> {
    let (pad, key, iv) = pad_key_iv;
    let mut compressed = vec![];
    let enc_params = BrotliEncoderParams {
        quality: COMPRESSION_QUALITY,
        ..Default::default()
    };
    let _size = brotli::BrotliCompress(&mut Cursor::new(content), &mut compressed, &enc_params)?;
    let encrypted = encryption::encrypt(&compressed, &key, &iv)?;
    Ok(xor(&encrypted, &pad))
}

pub fn decrypt_chunk(
    content: &[u8],
    pad_key_iv: (Pad, Key, Iv),
) -> Result<Vec<u8>, SelfEncryptionError> {
    let (pad, key, iv) = pad_key_iv;
    let xor_result = xor(content, &pad);
    let decrypted = encryption::decrypt(&xor_result, &key, &iv)?;
    let mut decompressed = vec![];
    let result = brotli::BrotliDecompress(&mut Cursor::new(decrypted), &mut decompressed);
    if result.is_err() {
        return Err(SelfEncryptionError::Compression);
    }
    Ok(decompressed)
}

// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub fn xor(data: &[u8], &Pad(pad): &Pad) -> Vec<u8> {
    data.iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect()
}

#[cfg(test)]
pub fn make_random_pieces<'a, T: Rng>(
    rng: &mut T,
    data: &'a [u8],
    min_len_of_first_piece: usize,
) -> Vec<&'a [u8]> {
    let mut pieces = vec![];
    let mut split_index = 0;
    loop {
        let min_len = if split_index == 0 {
            min_len_of_first_piece
        } else {
            1
        };
        let max_len = cmp::max(data.len() / 3, min_len + 1);
        let new_split_index = split_index + rng.gen_range(min_len, max_len);
        if new_split_index >= data.len() {
            pieces.push(&data[split_index..]);
            break;
        }
        pieces.push(&data[split_index..new_split_index]);
        split_index = new_split_index;
    }
    pieces
}
