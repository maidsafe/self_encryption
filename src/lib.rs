// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! A file **content** self-encryptor.
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
//! use futures::{future, Future};
//! use std::error::Error;
//! use std::fmt::{self, Display, Formatter};
//! use self_encryption::{Storage, StorageError};
//!
//! #[derive(Debug, Clone)]
//! struct SimpleStorageError {}
//!
//! impl Display for SimpleStorageError {
//!    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
//!        write!(formatter, "Failed to get data from SimpleStorage")
//!    }
//! }
//!
//! impl Error for SimpleStorageError {
//!     fn description(&self) -> &str {
//!         "SimpleStorage::get() error"
//!     }
//! }
//!
//! impl StorageError for SimpleStorageError {}
//!
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
//!     fn new() -> SimpleStorage {
//!         SimpleStorage { entries: vec![] }
//!     }
//! }
//!
//! impl Storage for SimpleStorage {
//!    type Error = SimpleStorageError;
//!
//!    fn get(&self, name: &[u8]) -> Box<Future<Item=Vec<u8>, Error=Self::Error>> {
//!        let result = match self.entries.iter().find(|ref entry| entry.name == name) {
//!            Some(entry) => Ok(entry.data.clone()),
//!            None => Err(SimpleStorageError {}),
//!        };
//!
//!        Box::new(future::result(result))
//!    }
//!
//!    fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Box<Future<Item=(), Error=Self::Error>> {
//!        self.entries.push(Entry {
//!            name: name,
//!            data: data,
//!        });
//!
//!        Box::new(future::ok(()))
//!    }
//! }
//!
//! # fn main() {}
//! ```
//!
//! Using this `SimpleStorage`, a self-encryptor can be created and written to/read from:
//!
//! ```
//! # extern crate futures;
//! # extern crate self_encryption;
//! use futures::Future;
//! use self_encryption::{DataMap, SelfEncryptor};
//! # use self_encryption::test_helpers::SimpleStorage;
//!
//! fn main() {
//!     let storage = SimpleStorage::new();
//!     let mut encryptor = SelfEncryptor::new(storage, DataMap::None).unwrap();
//!     let data = vec![0, 1, 2, 3, 4, 5];
//!     let mut offset = 0;
//!
//!     encryptor.write(&data, offset).wait().unwrap();
//!
//!     offset = 2;
//!     let length = 3;
//!     assert_eq!(encryptor.read(offset, length).wait().unwrap(), vec![2, 3, 4]);
//!
//!     let data_map = encryptor.close().wait().unwrap().0;
//!     assert_eq!(data_map.len(), 6);
//! }
//! ```
//!
//! The `close()` function returns a `DataMap` which can be used when creating a new encryptor to
//! access the content previously written.  Storage of the `DataMap` is outwith the scope of this
//! library and must be implemented by the user.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/self_encryption")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences, non_camel_case_types)]

extern crate brotli2;
extern crate futures;
#[cfg(test)]
extern crate itertools;
#[cfg(test)]
extern crate maidsafe_utilities;
extern crate memmap;
#[cfg(test)]
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate rust_sodium;
extern crate tiny_keccak;
#[macro_use]
extern crate unwrap;

mod data_map;
mod encryption;
mod error;
mod self_encryptor;
mod sequencer;
mod sequential;
mod storage;
pub mod test_helpers;
mod util;

pub use data_map::{ChunkDetails, DataMap};
pub use error::SelfEncryptionError;
pub use self_encryptor::SelfEncryptor;
pub use sequential::encryptor::Encryptor as SequentialEncryptor;
pub use storage::{Storage, StorageError};

/// The maximum size of file which can be self-encrypted, defined as 1GB.
pub const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;
/// The maximum size (before compression) of an individual chunk of the file, defined as 1MB.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// The minimum size (before compression) of an individual chunk of the file, defined as 1kB.
pub const MIN_CHUNK_SIZE: u32 = 1024;
/// Controls the compression-speed vs compression-density tradeoffs.  The higher the quality, the
/// slower the compression.  Range is 0 to 11.
pub const COMPRESSION_QUALITY: u32 = 6;
