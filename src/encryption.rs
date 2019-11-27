// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO(dirvine) Look at aessafe 256X8 cbc it should be very much faster  :01/03/2015

use crate::sequential::{Iv, Key};
use crate::MAX_CHUNK_SIZE;
use crate::{SelfEncryptionError, StorageError};
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub const KEY_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;

// Buffer size is set to max chunk size + 100 bytes for padding.
pub const BUFFER_SIZE: usize = MAX_CHUNK_SIZE as usize + 100;

pub fn encrypt<E>(data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, SelfEncryptionError<E>>
where
    E: StorageError,
{
    let cipher = Aes128Cbc::new_var(key.0.as_ref(), iv.0.as_ref()).unwrap();
    let pos = data.len();
    let mut buffer = [0u8; BUFFER_SIZE];
    buffer[..pos].copy_from_slice(data);
    cipher
        .encrypt(&mut buffer, pos)
        .map(|res| res.to_vec())
        .map_err(|_| SelfEncryptionError::Encryption)
}

pub fn decrypt<E>(
    encrypted_data: &[u8],
    key: &Key,
    iv: &Iv,
) -> Result<Vec<u8>, SelfEncryptionError<E>>
where
    E: StorageError,
{
    let cipher = Aes128Cbc::new_var(key.0.as_ref(), iv.0.as_ref()).unwrap();
    let mut buffer = encrypted_data.to_vec();
    cipher
        .decrypt(&mut buffer)
        .map(|res| res.to_vec())
        .map_err(|_| SelfEncryptionError::Decryption)
}
