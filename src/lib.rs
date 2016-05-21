// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! A file **content** self encryptor
//!
//! This library will provide convergent encryption on file based data and produce a `DataMap` type
//! and several chunks of data. Each chunk is max 1Mb in size and has a name. This name is the
//! `Sha512` of the content, this allows the chunks to be confirmed. If size and hash
//! checks are utilised, a high degree of certainty in the validity of the data can be expected.
//!
//! [Project github page](https://github.com/dirvine/self_encryption)
//!
//! # Use
//!
//! To use this lib you must implement a trait with two functions, these are to allow `get_chunk`
//! and `put_chunk` from storage. This must be set up by implementing the Storage trait (see below);
//!
//! The trait can allow chunks to be stored in a key value store, disk, vector (as per example
//! below), or a network based DHT.
//!
//! # Examples
//!
//! This is a simple setup for a memory based chunk store. A working implementation can be found
//! in the test crate of this project.
//!
//! ```
//! # #![allow(dead_code)]
//! extern crate self_encryption;
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
//! impl self_encryption::Storage for SimpleStorage {
//!     fn get(&self, name: &[u8]) -> Vec<u8> {
//!         for entry in &self.entries {
//!             if entry.name == name {
//!                 return entry.data.to_vec();
//!             }
//!         }
//!         vec![]
//!     }
//!
//!     fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
//!         self.entries.push(Entry {
//!             name: name,
//!             data: data,
//!         })
//!     }
//! }
//! ```
//!
//! Use of this setup would be to implement a self encryptor e.g. `let mut se =
//! SelfEncryptor::new(storage, datamap::DataMap::None);`
//!
//! Then call write (and read after write)…etc… on the encryptor. The `close()` method will
//! return a `DataMap`. This can be passed to create a new encryptor to access the content
//! `let data_map = se.close();`
//!
//! This is then used to open the data content in future sessions; e.g. `let mut self_encryptor =
//! SelfEncryptor::new(storage, data_map);` where the `data_map` is the object returned
//! from the `close()` call of previous use of this file content via the self_encryptor. Storage of
//! the `DataMap` is out with the scope of this library and must be implemented by the user.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/self_encryption")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate brotli2;
#[macro_use]
#[allow(unused_extern_crates)]  // Only using macros from maidsafe_utilites
extern crate maidsafe_utilities;
extern crate memmap;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;

mod datamap;
mod encryption;
mod self_encryptor;
mod sequencer;
mod storage;
pub mod test_helpers;

pub use datamap::{DataMap, ChunkDetails};
pub use self_encryptor::SelfEncryptor;
pub use storage::Storage;

/// MAX_MEMORY_MAP_SIZE defined as 1GB.
pub const MAX_MEMORY_MAP_SIZE: usize = 1 << 30;
/// MAX_CHUNK_SIZE defined as 1MB.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// MIN_CHUNK_SIZE defined as 1KB.
pub const MIN_CHUNK_SIZE: u32 = 1024;
