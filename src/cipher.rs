// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use crate::Error;
use bytes::Bytes;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use xor_name::XOR_NAME_LEN;

/// 32-byte key for ChaCha20-Poly1305
pub(crate) struct Key(pub(crate) [u8; KEY_SIZE]);
/// 12-byte nonce for ChaCha20-Poly1305
pub(crate) struct Nonce(pub(crate) [u8; NONCE_SIZE]);
/// XOR obfuscation pad
pub(crate) struct Pad(pub(crate) [u8; PAD_SIZE]);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) const KEY_SIZE: usize = 32;
pub(crate) const NONCE_SIZE: usize = 12;
pub(crate) const HASH_SIZE: usize = XOR_NAME_LEN;
pub(crate) const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - NONCE_SIZE;

pub(crate) fn encrypt(data: Bytes, key: &Key, nonce: &Nonce) -> Result<Bytes, Error> {
    let cha_key = ChaKey::from_slice(key.as_ref());
    let cipher = ChaCha20Poly1305::new(cha_key);
    let cha_nonce = ChaNonce::from_slice(nonce.as_ref());
    let encrypted = cipher
        .encrypt(cha_nonce, data.as_ref())
        .map_err(|_| Error::Encryption)?;
    Ok(Bytes::from(encrypted))
}

pub(crate) fn decrypt(encrypted_data: Bytes, key: &Key, nonce: &Nonce) -> Result<Bytes, Error> {
    let cha_key = ChaKey::from_slice(key.as_ref());
    let cipher = ChaCha20Poly1305::new(cha_key);
    let cha_nonce = ChaNonce::from_slice(nonce.as_ref());
    cipher
        .decrypt(cha_nonce, encrypted_data.as_ref())
        .map(Bytes::from)
        .map_err(|e| Error::Decryption(format!("Decrypt failed with {e}")))
}
