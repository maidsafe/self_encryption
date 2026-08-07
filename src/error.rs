// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use bincode::ErrorKind;
use std::io::Error as IoError;
use thiserror::Error;

#[cfg(feature = "python")]
use pyo3::PyErr;

/// Specialisation of `std::Result` for crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors which can arise during self_encryption or -decryption.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("An error during compression or decompression.")]
    Compression,
    #[error("An error during initializing cipher instance.")]
    Cipher(String),
    #[error("An error within the symmetric encryption process.")]
    Encryption,
    #[error("An error within the symmetric decryption process({_0})")]
    Decryption(String),
    #[error("A generic I/O error")]
    Io(#[from] IoError),
    #[error("Generic error({_0})")]
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
    #[error("Python error: {_0}")]
    Python(String),
}

#[cfg(feature = "python")]
impl From<PyErr> for Error {
    fn from(err: PyErr) -> Self {
        Error::Python(err.to_string())
    }
}
