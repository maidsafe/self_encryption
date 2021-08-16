// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A file **content** self_encryptor.
//!
//! This library provides convergent encryption on file-based data and produce a `DataMap` type and
//! several chunks of data. Each chunk is up to 1MB in size and has a name.  This name is the
//! SHA3-256 hash of the content, which allows the chunks to be self-validating.  If size and hash
//! checks are utilised, a high degree of certainty in the validity of the data can be expected.
//!
//! [Project GitHub page](https://github.com/maidsafe/self_encryption).
//!
//! # Use
//!
//! To use this library you must implement a storage trait (a key/value store) and associated
//! storage error trait.  These provide a place for encrypted chunks to be put to and got from by
//! the `SelfEncryptor`.
//!
//! The storage trait should be flexible enough to allow implementation as an in-memory map, a
//! disk-based database, or a network-based DHT for example.
//!
//! # Examples
//!
//! This is a simple setup for a memory-based chunk store.  A working implementation can be found
//! in the "examples" folder of this project.
//!
//! ```
//! # extern crate futures;
//! # extern crate self_encryption;
//! use self_encryption::Storage;
//! use tiny_keccak::{Hasher, Sha3};
//! use async_trait::async_trait;
//! use self_encryption::SelfEncryptionError;

//! struct Entry {
//!     name: Vec<u8>,
//!     data: Vec<u8>
//! }
//!
//! struct SimpleStorage {
//!     entries: Vec<Entry>
//! }
//!
//! impl SimpleStorage {
//!     # #[allow(dead_code)]
//!     fn new() -> SimpleStorage {
//!         SimpleStorage { entries: vec![] }
//!     }
//! }
//! #[async_trait]
//! impl Storage for SimpleStorage {
//
//!    async fn get(&mut self, name: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
//!        match self.entries.iter().find(|ref entry| entry.name == name) {
//!            Some(entry) => Ok(entry.data.clone()),
//!            None => Err(SelfEncryptionError::Storage("Chunk not found".into())),
//!        }
//!
//!    }
//!
//!     async fn delete(&mut self, name: &[u8]) -> Result<(), SelfEncryptionError> {
//!        self.entries.retain(|entry| entry.name != name );
//!
//!         Ok(())
//!    }
//!
//!    async fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Result<(),
//!    SelfEncryptionError> {
//!        self.entries.push(Entry {
//!            name: name,
//!            data: data,
//!        });
//!      Ok(())
//!    }
//!
//!    async fn generate_address(&self, data: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
//!         let mut hasher = Sha3::v256();
//!         let mut output = [0; 32];
//!         hasher.update(&data);
//!         hasher.finalize(&mut output);
//!         Ok(output.to_vec())
//!    }
//! }

//! ```
//!
//! Using this `SimpleStorage`, a self_encryptor can be created and written to/read from:
//!
//! ```
//! # extern crate futures;
//! # extern crate self_encryption;
//! use self_encryption::{DataMap, SelfEncryptor};
//! # use self_encryption::test_helpers::SimpleStorage;
//!
//! #[tokio::main]
//! async fn main() {
//!     let storage = SimpleStorage::new();
//!     let encryptor = SelfEncryptor::new(storage, DataMap::None).unwrap();
//!     let data = vec![0, 1, 2, 3, 4, 5];
//!     let mut offset = 0;
//!
//!     encryptor.write(&data, offset).await.unwrap();
//!
//!     offset = 2;
//!     let length = 3;
//!     assert_eq!(encryptor.read(offset, length).await.unwrap(), vec![2, 3, 4]);
//!
//!     let data_map = encryptor.close().await.unwrap().0;
//!     assert_eq!(data_map.len(), 6);
//! }
//! ```
//!
//! The `close()` function returns a `DataMap` which can be used when creating a new encryptor to
//! access the content previously written.  Storage of the `DataMap` is outwith the scope of this
//! library and must be implemented by the user.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true,
    warnings
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    non_camel_case_types
)]
// Doesn't allow casts on constants yet, remove when issue is fixed:
// https://github.com/rust-lang-nursery/rust-clippy/issues/2267
#![allow(clippy::cast_lossless, clippy::decimal_literal_representation)]

/// blah
pub mod new;

pub use crate::new::{
    decrypt, encrypt, test_helpers, ChunkDetails, DataMap, EncryptedChunk, Error, Result, Storage,
};

/// The maximum size of file which can be self_encrypted, defined as 1GB.
pub const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;
/// The maximum size (before compression) of an individual chunk of the file, defined as 1MB.
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;
/// The minimum size (before compression) of an individual chunk of the file, defined as 1kB.
pub const MIN_CHUNK_SIZE: usize = 1024;
/// Controls the compression-speed vs compression-density tradeoffs.  The higher the quality, the
/// slower the compression.  Range is 0 to 11.
pub const COMPRESSION_QUALITY: i32 = 6;
