// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::storage::StorageError;
use std::{
    error::Error as StdError,
    fmt::{self, Display, Formatter},
    io::Error as IoError,
};

/// Errors which can arise during self-encryption or -decryption.
#[derive(Debug)]
pub enum SelfEncryptionError<E: StorageError> {
    /// An error during compression or decompression.
    Compression,
    /// An error within the symmetric encryption process.
    Encryption,
    /// An error within the symmetric decryption process.
    Decryption,
    /// A generic I/O error, likely arising from use of memmap.
    Io(IoError),
    /// An error in putting or retrieving chunks from the storage object.
    Storage(E),
}

impl<E: StorageError> Display for SelfEncryptionError<E> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            SelfEncryptionError::Compression => {
                write!(formatter, "Error while compressing or decompressing")
            }
            SelfEncryptionError::Decryption => write!(formatter, "Symmetric decryption error"),
            SelfEncryptionError::Encryption => write!(formatter, "Symmetric encryption error"),
            SelfEncryptionError::Io(ref error) => {
                write!(formatter, "Internal I/O error: {}", error)
            }
            SelfEncryptionError::Storage(ref error) => {
                write!(formatter, "Storage error: {}", error)
            }
        }
    }
}

impl<E: StorageError> StdError for SelfEncryptionError<E> {
    fn description(&self) -> &str {
        match *self {
            SelfEncryptionError::Compression => "Compression error",
            SelfEncryptionError::Decryption => "Symmetric decryption error",
            SelfEncryptionError::Encryption => "Symmetric encryption error",
            SelfEncryptionError::Io(_) => "I/O error",
            SelfEncryptionError::Storage(ref error) => error.description(),
        }
    }
}

impl<E: StorageError> From<IoError> for SelfEncryptionError<E> {
    fn from(error: IoError) -> SelfEncryptionError<E> {
        SelfEncryptionError::Io(error)
    }
}

impl<E: StorageError> From<E> for SelfEncryptionError<E> {
    fn from(error: E) -> SelfEncryptionError<E> {
        SelfEncryptionError::Storage(error)
    }
}
