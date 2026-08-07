// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use crate::{
    cipher::{self, Key, Nonce, Pad},
    error::Error,
    utils::xor,
    Result, COMPRESSION_QUALITY,
};
use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use std::io::Cursor;

/// Encrypt a chunk
pub(crate) fn encrypt_chunk(content: Bytes, pki: (Pad, Key, Nonce)) -> Result<Bytes> {
    let (pad, key, nonce) = pki;

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
    let encrypted = cipher::encrypt(Bytes::from(compressed), &key, &nonce)?;
    Ok(xor(&encrypted, &pad))
}
