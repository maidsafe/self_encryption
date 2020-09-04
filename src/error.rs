// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bincode::ErrorKind;
use block_modes::BlockModeError;
use err_derive::Error;
use std::io::Error as IoError;

/// Errors which can arise during self_encryption or -decryption.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum SelfEncryptionError {
    #[error(display = "An error during compression or decompression.")]
    Compression,
    #[error(display = "An error during initializing CBC-AES cipher instance.")]
    Cipher(String),
    #[error(display = "An error within the symmetric encryption process.")]
    Encryption,
    #[error(display = "An error within the symmetric decryption process.")]
    Decryption(#[source] BlockModeError),
    #[error(display = "A generic I/O error")]
    Io(#[source] IoError),
    #[error(display = "An error in putting or retrieving chunks from the storage object.")]
    Storage,
    #[error(display = "Generic error")]
    Generic(String),
    #[error(display = "Serialisation error")]
    Bincode(#[source] Box<ErrorKind>),
    #[error(display = "deserialization")]
    Deserialise,
    #[error(display = "num parse error")]
    NumParse(#[source] std::num::ParseIntError),
    #[error(display = "Rng error")]
    Rng(#[source] rand::Error),
}
