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

pub(crate) const KEY_SIZE: usize = 16;
pub(crate) const IV_SIZE: usize = 16;

pub(crate) const HASH_SIZE: usize = XOR_NAME_LEN;
pub(crate) const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

/// Padding.
///
/// In cryptography, padding is any of a number of distinct practices which
/// all include adding data to the beginning, middle, or end of a message prior to encryption.
/// https://en.wikipedia.org/wiki/Padding_(cryptography)
pub(crate) struct Pad(pub [u8; PAD_SIZE]);
pub(crate) struct Key(pub [u8; KEY_SIZE]);
/// Initialization vector.
///
/// In cryptography, an initialization vector (IV) or starting variable (SV)[1]
/// is an input to a cryptographic primitive being used to provide the initial state.
/// https://en.wikipedia.org/wiki/Initialization_vector
pub(crate) struct Iv(pub [u8; IV_SIZE]);

pub(crate) fn encrypt(data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128CbcEnc::new(key.0.as_ref().into(), iv.0.as_ref().into());
    Ok(Bytes::from(cipher.encrypt_padded_vec_mut::<Pkcs7>(&data)))
}

pub(crate) fn decrypt(encrypted_data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128CbcDec::new(key.0.as_ref().into(), iv.0.as_ref().into());
    match cipher.decrypt_padded_vec_mut::<Pkcs7>(encrypted_data.as_ref()) {
        Ok(vec) => Ok(Bytes::from(vec)),
        Err(err) => Err(Error::Decryption(format!(
            "Decrypt failed with UnpadError({:?})",
            err
        ))),
    }
}
