// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes128,
};
use bytes::Bytes;
use xor_name::XOR_NAME_LEN;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub(crate) struct Key(pub(crate) [u8; KEY_SIZE]);
pub(crate) struct Iv(pub(crate) [u8; IV_SIZE]);
pub(crate) struct Pad(pub(crate) [u8; PAD_SIZE]);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Iv {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) const KEY_SIZE: usize = 16;
pub(crate) const IV_SIZE: usize = 16;
pub(crate) const HASH_SIZE: usize = XOR_NAME_LEN;
pub(crate) const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

pub(crate) fn encrypt(data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128CbcEnc::new(key.as_ref().into(), iv.as_ref().into());
    let encrypted = cipher.encrypt_padded_vec_mut::<Pkcs7>(&data);
    Ok(Bytes::from(encrypted))
}

pub(crate) fn decrypt(encrypted_data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128CbcDec::new(key.as_ref().into(), iv.as_ref().into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_data)
        .map(Bytes::from)
        .map_err(|e| Error::Decryption(format!("Decrypt failed with {e}")))
}
