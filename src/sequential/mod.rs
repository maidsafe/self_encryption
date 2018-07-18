// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod encryptor;
pub mod large_encryptor;
pub mod medium_encryptor;
pub mod small_encryptor;
pub mod utils;

pub use super::{
    SelfEncryptionError, Storage, StorageError, COMPRESSION_QUALITY, MAX_CHUNK_SIZE, MAX_FILE_SIZE,
    MIN_CHUNK_SIZE,
};
use safe_crypto::{NONCE_SIZE as IV_SIZE, SYMMETRIC_KEY_SIZE as KEY_SIZE};

pub const HASH_SIZE: usize = 32;
pub const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

pub struct Pad(pub [u8; PAD_SIZE]);
