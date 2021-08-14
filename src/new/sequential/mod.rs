// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod utils;

use super::encryption::{IV_SIZE, KEY_SIZE};
pub use crate::{
    Error, Storage, COMPRESSION_QUALITY, MAX_CHUNK_SIZE, MAX_FILE_SIZE, MIN_CHUNK_SIZE,
};

pub const HASH_SIZE: usize = 32;
pub const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

pub struct Pad(pub [u8; PAD_SIZE]);
pub struct Key(pub [u8; KEY_SIZE]);
pub struct Iv(pub [u8; IV_SIZE]);
