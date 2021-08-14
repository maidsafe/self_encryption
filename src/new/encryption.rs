// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::super::Error;
use super::sequential::{Iv, Key};
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use bytes::Bytes;
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub const KEY_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;

pub fn encrypt(data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128Cbc::new_fix(key.0.as_ref().into(), iv.0.as_ref().into());
    Ok(Bytes::from(cipher.encrypt_vec(data.as_ref())))
}

pub fn decrypt(encrypted_data: Bytes, key: &Key, iv: &Iv) -> Result<Bytes, Error> {
    let cipher = Aes128Cbc::new_fix(key.0.as_ref().into(), iv.0.as_ref().into());
    Ok(Bytes::from(cipher.decrypt_vec(encrypted_data.as_ref())?))
}
