// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bincode::ErrorKind;
use std::io::Error as IoError;
use thiserror::Error;

/// Specialisation of `std::Result` for crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors which can arise during self_encryption or -decryption.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("An error during compression or decompression.")]
    Compression,
    #[error("An error during initializing CBC-AES cipher instance.")]
    Cipher(String),
    #[error("An error within the symmetric encryption process.")]
    Encryption,
    #[error("An error within the symmetric decryption process({})", _0)]
    Decryption(String),
    #[error("A generic I/O error")]
    Io(#[from] IoError),
    #[error("Generic error({})", _0)]
    Generic(String),
    #[error("Serialisation error")]
    Bincode(#[from] Box<ErrorKind>),
    #[error("deserialization")]
    Deserialise,
    #[error("num parse error")]
    NumParse(#[from] std::num::ParseIntError),
    #[error("Rng error")]
    Rng(#[from] rand::Error),
    #[error("Unable to obtain lock")]
    Poison,
}
