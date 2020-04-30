// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::storage::StorageError;
use std::error::Error;
use std::{
    fmt::{self, Display, Formatter},
    io::Error as IoError,
};

/// Errors which can arise during self-encryption or -decryption.
#[derive(Debug)]
pub enum SelfEncryptionError<E: StorageError> {
    /// An error during compression or decompression.
    Compression,
    /// An error during initializing CBC-AES cipher instance.
    Cipher(String),
    /// An error within the symmetric encryption process.
    Encryption,
    /// An error within the symmetric decryption process.
    Decryption(String),
    /// A generic I/O error, likely arising from use of memmap.
    Io(IoError),
    /// An error in putting or retrieving chunks from the storage object.
    Storage(E),
    /// Generic error for other issues
    Generic(String)
}

impl<E: StorageError> Display for SelfEncryptionError<E> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            SelfEncryptionError::Compression => {
                write!(formatter, "Error while compressing or decompressing")
            }
            SelfEncryptionError::Cipher(ref error) => write!(
                formatter,
                "Error while creating cipher instance: {:?}",
                error
            ),
            SelfEncryptionError::Decryption(ref error) => {
                write!(formatter, "Symmetric decryption error: {:?}", error)
            }
            SelfEncryptionError::Encryption => write!(formatter, "Symmetric encryption error"),
            SelfEncryptionError::Io(ref error) => {
                write!(formatter, "Internal I/O error: {}", error)
            }
            SelfEncryptionError::Storage(ref error) => {
                write!(formatter, "Storage error: {}", error)
            }
            SelfEncryptionError::Generic(ref error ) => write!(formatter, "Generic error: {}", error)

        }
    }
}

impl<E: StorageError> Error for SelfEncryptionError<E> {
    fn cause(&self) -> Option<&dyn Error> {
        self.source()
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
