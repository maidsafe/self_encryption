// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use aes::Aes128;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use bytes::Bytes;
use xor_name::XOR_NAME_LEN;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub(crate) const KEY_SIZE: usize = 16;
pub(crate) const IV_SIZE: usize = 16;

pub(crate) const HASH_SIZE: usize = XOR_NAME_LEN;
pub(crate) const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

pub(crate) struct Pad(pub [u8; PAD_SIZE]);
pub(crate) struct Key(pub [u8; KEY_SIZE]);
pub(crate) struct Iv(pub [u8; IV_SIZE]);

pub(crate) fn encrypt(data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128Cbc::new_fix(key.0.as_ref().into(), iv.0.as_ref().into());
    Ok(Bytes::from(cipher.encrypt_vec(data.as_ref())))
}

pub(crate) fn decrypt(encrypted_data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128Cbc::new_fix(key.0.as_ref().into(), iv.0.as_ref().into());
    Ok(Bytes::from(cipher.decrypt_vec(encrypted_data.as_ref())?))
}
