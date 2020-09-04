// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::sequential::{Iv, Key};
use crate::SelfEncryptionError;
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub const KEY_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;

pub fn encrypt(data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, SelfEncryptionError> {
    let cipher = Aes128Cbc::new_var(key.0.as_ref(), iv.0.as_ref())
        .map_err(|e| SelfEncryptionError::Cipher(format!("{:?}", e)))?;
    Ok(cipher.encrypt_vec(data))
}

pub fn decrypt(encrypted_data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, SelfEncryptionError> {
    let cipher = Aes128Cbc::new_var(key.0.as_ref(), iv.0.as_ref())
        .map_err(|err| SelfEncryptionError::Cipher(format!("{:?}", err)))?;
    Ok(cipher.decrypt_vec(encrypted_data)?)
}
