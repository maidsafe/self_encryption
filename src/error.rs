// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;

use brotli2::stream::Error as CompressionError;
use encryption::DecryptionError;
use storage::StorageError;

/// Errors which can arise during self-encryption or -decryption.
#[derive(Debug)]
#[cfg_attr(feature="clippy", allow(stutter))]
pub enum SelfEncryptionError<E: StorageError> {
    /// An error during compression or decompression.
    Compression,
    /// An error within the symmetric encryption or decryption process.
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
            SelfEncryptionError::Io(_) => "I/O error",
            SelfEncryptionError::Storage(ref error) => error.description(),
        }
    }
}

impl<E: StorageError> From<CompressionError> for SelfEncryptionError<E> {
    fn from(_error: CompressionError) -> SelfEncryptionError<E> {
        SelfEncryptionError::Compression
    }
}

impl<E: StorageError> From<DecryptionError> for SelfEncryptionError<E> {
    fn from(_error: DecryptionError) -> SelfEncryptionError<E> {
        SelfEncryptionError::Decryption
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
