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
//! use std::sync::{Arc, Mutex};
//!
//! struct Entry {
//!     name: Vec<u8>,
//!     data: Vec<u8>
//! }
//!
//! struct SimpleStorage {
//!     entries: Arc<Mutex<Vec<Entry>>>
//! }
//!
//! impl SimpleStorage {
//!     fn new() -> SimpleStorage {
//!         SimpleStorage { entries: Arc::new(Mutex::new(Vec::new())) }
//!     }
//! }
//!
//! impl self_encryption::Storage for SimpleStorage {
//!     fn get(&self, name: &[u8]) -> Vec<u8> {
//!         let lock = self.entries.lock().unwrap();
//!         for entry in lock.iter() {
//!             if entry.name == name {
//!                 return entry.data.to_vec();
//!             }
//!         }
//!         vec![]
//!     }
//!
//!     fn put(&self, name: Vec<u8>, data: Vec<u8>) {
//!         let mut lock = self.entries.lock().unwrap();
//!         lock.push(Entry {
//!             name: name,
//!             data: data,
//!         })
//!     }
//! }
//! ```
//!
//! Use of this setup would be to implement a self encryptor e.g. `let mut se =
//! SelfEncryptor::new(my_storage, datamap::DataMap::None);`
//!
//! Then call write (and read after write)…etc… on the encryptor. The `close()` method will
//! return a `DataMap`. This can be passed to create a new encryptor to access the content
//! `let data_map = se.close();`
//!
//! This is then used to open the data content in future sessions; e.g. `let mut self_encryptor =
//! SelfEncryptor::new(my_storage, data_map);` where the `data_map` is the object returned
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

extern crate asynchronous;
extern crate flate2;
#[macro_use]
#[allow(unused_extern_crates)]  // Only using macros from maidsafe_utilites
extern crate maidsafe_utilities;
extern crate memmap;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;

pub mod test_helpers;
mod encryption;
mod datamap;

use std::cmp;
use std::error::Error;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, ErrorKind, Read, Result, Write};
use std::iter::repeat;
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::sync::{Arc, Once, ONCE_INIT};

use asynchronous::{ControlFlow, Deferred};
use encryption::{IV_SIZE, Iv, KEY_SIZE, Key, decrypt, encrypt};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use memmap::{Mmap, Protection};
use sodiumoxide::crypto::hash::sha512;

pub use datamap::{DataMap, ChunkDetails};

const HASH_SIZE: usize = sha512::DIGESTBYTES;
const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;
const MAX_IN_MEMORY_SIZE: usize = 50 * (1 << 20);

/// MAX_MEMORY_MAP_SIZE defined as 1GB.
pub const MAX_MEMORY_MAP_SIZE: usize = 1 << 30;
/// MAX_CHUNK_SIZE defined as 1MB.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// MIN_CHUNK_SIZE defined as 1KB.
pub const MIN_CHUNK_SIZE: u32 = 1024;

struct Pad(pub [u8; PAD_SIZE]);

// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
fn xor(data: &[u8], &Pad(pad): &Pad) -> Vec<u8> {
    data.iter().zip(pad.iter().cycle()).map(|(&a, &b)| a ^ b).collect()
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum ChunkStatus {
    ToBeHashed,
    ToBeEncrypted,
    AlreadyEncrypted,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct Chunk {
    status: ChunkStatus,
    in_sequencer: bool,
}

impl Chunk {
    fn flag_for_encryption(&mut self) {
        if self.status == ChunkStatus::AlreadyEncrypted {
            self.status = ChunkStatus::ToBeEncrypted;
        }
    }
}

/// Optionally create a sequence of bytes via a vector or memory map.
pub struct Sequencer {
    vector: Option<Vec<u8>>,
    mmap: Option<Mmap>,
}

#[cfg_attr(feature="clippy", allow(len_without_is_empty))]
impl Sequencer {
    /// Initialise as a vector.
    pub fn new_as_vector() -> Sequencer {
        Sequencer {
            vector: Some(Vec::with_capacity(MAX_IN_MEMORY_SIZE)),
            mmap: None,
        }
    }

    /// Initialise as a memory map
    pub fn new_as_mmap() -> Result<Sequencer> {
        Ok(Sequencer {
            vector: None,
            mmap: Some(try!(Mmap::anonymous(MAX_MEMORY_MAP_SIZE, Protection::ReadWrite))),
        })
    }

    /// Return the current length of the sequencer.
    pub fn len(&self) -> usize {
        match self.vector {
            Some(ref vector) => vector.len(),
            None => {
                match self.mmap {
                    Some(ref mmap) => mmap.len(),
                    None => 0usize,
                }
            }
        }
    }

    #[allow(unsafe_code)]
    /// Initialise with the Sequencer with 'content'.
    pub fn init(&mut self, content: &[u8]) {
        match self.vector {
            Some(ref mut vector) => {
                for ch in content {
                    vector.push(*ch);
                }
            }
            None => {
                if let Some(ref mut mmap) = self.mmap {
                    let _ = unsafe { mmap.as_mut_slice() }.write_all(&content[..]);
                }
            }
        }
    }

    /// Truncate internal object to given size. Note that this affects the vector only since the
    /// memory map is a fixed size.
    pub fn truncate(&mut self, size: usize) {
        if let Some(ref mut vector) = self.vector {
            vector.truncate(size);
        }
    }

    #[allow(unsafe_code)]
    /// Create a memory map if we haven't already done so.
    pub fn create_mapping(&mut self) -> Result<()> {
        if self.mmap.is_some() {
            return Ok(());
        }
        match self.vector {
            Some(ref mut vector) => {
                let mut mmap = match Mmap::anonymous(MAX_MEMORY_MAP_SIZE, Protection::ReadWrite) {
                    Ok(mmap) => mmap,
                    Err(error) => return Err(error),
                };
                let _ = unsafe { mmap.as_mut_slice() }.write_all(&vector[..]);
                vector.clear();
                self.mmap = Some(mmap);
            }
            None => return Err(io::Error::new(ErrorKind::WriteZero, "Failed to create mapping")),
        };

        if self.mmap.is_some() {
            self.vector = None;
        }
        Ok(())
    }

    /// If we are a vector return the vector otherwise return empty vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self.vector {
            Some(ref vector) => vector.clone(),
            None => Vec::<u8>::new(),
        }
    }
}

#[allow(unsafe_code)]
impl Index<usize> for Sequencer {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        match self.vector {
            Some(ref vector) => &vector[index],
            None => {
                match self.mmap {
                    Some(ref mmap) => unsafe { &mmap.as_slice()[index] },
                    None => panic!("Uninitialised"),
                }
            }
        }
    }
}

#[allow(unsafe_code)]
impl IndexMut<usize> for Sequencer {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        match self.vector {
            Some(ref mut vector) => &mut vector[index],
            None => {
                match self.mmap {
                    Some(ref mut mmap) => unsafe { &mut mmap.as_mut_slice()[index] },
                    None => panic!("Uninitialised"),
                }
            }
        }
    }
}

#[allow(unsafe_code)]
impl Deref for Sequencer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self.vector {
            Some(ref vector) => &*vector,
            None => {
                match self.mmap {
                    Some(ref mmap) => unsafe { &mmap.as_slice() },
                    None => panic!("Uninitialised"),
                }
            }
        }
    }
}

#[allow(unsafe_code)]
impl DerefMut for Sequencer {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self.vector {
            Some(ref mut vector) => &mut *vector,
            None => {
                match self.mmap {
                    Some(ref mut mmap) => unsafe { &mut *mmap.as_mut_slice() },
                    None => panic!("Uninitialised"),
                }
            }
        }
    }
}

impl Extend<u8> for Sequencer {
    fn extend<I>(&mut self, iterable: I)
        where I: IntoIterator<Item = u8>
    {
        if let Some(ref mut vector) = self.vector {
            vector.extend(iterable);
        }
    }
}

/// Storage traits of SelfEncryptor. Data stored in Storage is encrypted, name is the SHA512 hash
/// of content. Storage can be in-memory HashMap or disk based
pub trait Storage {
    /// Fetch the data bearing the name
    fn get(&self, name: &[u8]) -> Vec<u8>;
    /// Insert the data bearing the name.
    fn put(&self, name: Vec<u8>, data: Vec<u8>);
}

/// This is the encryption object and all file handling should be done using this object as the low
/// level mechanism to read and write *content*. This library has no knowledge of file metadata.
/// This is a library to ensure content is secured.
pub struct SelfEncryptor<S: Storage> {
    storage: Arc<S>,
    sorted_map: Vec<ChunkDetails>,  // the original datamap, sorted
    chunks: Vec<Chunk>,             // this is sorted as well
    map_size: u64,                  // original file size of the datamap
    sequencer: Sequencer,
    file_size: u64,
}

impl<S: Storage + Send + Sync + 'static> SelfEncryptor<S> {
    /// This is the only constructor for an encryptor object. Each SelfEncryptor is used for a
    /// single file. The parameters are a DataMap and Storage. If new file, use DataMap::None as
    /// first parameter. The get and put of Storage need to be implemented to allow the
    /// SelfEncryptor to store encrypted chunks and retrieve them when necessary.
    pub fn new(storage: Arc<S>, datamap: DataMap) -> SelfEncryptor<S> {
        initialise_sodiumoxide();
        let file_size = datamap.len();
        let mut sequencer;

        if file_size <= MAX_IN_MEMORY_SIZE as u64 {
            sequencer = Sequencer::new_as_vector();
        } else {
            sequencer = unwrap_result!(Sequencer::new_as_mmap());
        }

        let sorted_map;
        let chunks;
        let map_size;
        match datamap {
            DataMap::Content(ref content) => {
                sequencer.init(content);
                sorted_map = vec![];
                chunks = vec![];
                map_size = 0;
            }
            DataMap::Chunks(_) => {
                sorted_map = datamap.get_sorted_chunks();
                let c = Chunk {
                    status: ChunkStatus::AlreadyEncrypted,
                    in_sequencer: false,
                };
                chunks = vec![c; sorted_map.len()];
                map_size = file_size;
            }
            DataMap::None => {
                sorted_map = vec![];
                chunks = vec![];
                map_size = 0;
            }
        }

        SelfEncryptor {
            storage: storage,
            sorted_map: sorted_map,
            chunks: chunks,
            sequencer: sequencer,
            file_size: file_size,
            map_size: map_size,
        }
    }

    /// This is an implementation of the get_storage function from example.
    pub fn get_storage(&self) -> Arc<S> {
        self.storage.clone()
    }

    /// Write method mirrors a posix type write mechanism. It loosely mimics a filesystem interface
    /// for easy connection to FUSE like programs as well as fine grained access to system level
    /// libraries for developers. The input data will be written from the specified position
    /// (starts from 0).
    #[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
    pub fn write(&mut self, data: &[u8], position: u64) {
        self.prepare_window_for_writing(position, data.len() as u64);
        for (i, &byte) in data.iter().enumerate() {
            self.sequencer[position as usize + i] = byte;
        }
    }

    /// The returned content is read from the specified position with specified length. Trying to
    /// read beyond the file size will cause the self_encryptor to return content filled with 0u8
    /// in the gap (file size isn't affected).  Any other unwritten gaps will also be filled with
    /// '0u8's.
    #[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
    pub fn read(&mut self, position: u64, length: u64) -> Vec<u8> {
        self.prepare_window_for_reading(position, length);
        let mut result = Vec::with_capacity(length as usize);
        for &byte in self.sequencer.iter().skip(position as usize).take(length as usize) {
            result.push(byte);
        }
        result
    }

    /// This function returns a DataMap, which is the info required to recover encrypted content
    /// from data storage location.  Content temporarily held in self_encryptor will only get
    /// flushed into storage when this function gets called.
    #[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
    pub fn close(mut self) -> DataMap {
        if self.file_size == 0 {
            return DataMap::None;
        }
        if self.file_size < 3 * MIN_CHUNK_SIZE as u64 {
            let mut content = self.sequencer.to_vec();
            content.truncate(self.file_size as usize);
            return DataMap::Content(content);
        }

        // Decrypt:
        // - first two chunks if last chunks size has changed
        // - chunks whose size is out of date
        let possibly_reusable_end;  // end of range of possibly reusable chunks
        let (resized_start, resized_end) = resized_chunks(self.map_size, self.file_size);
        if resized_start != resized_end {
            self.chunks[0].flag_for_encryption();
            self.chunks[1].flag_for_encryption();
            let byte_end = get_start_end_positions(self.map_size, 1).1;
            self.prepare_window_for_reading(0, byte_end);

            let byte_start = get_start_end_positions(self.map_size, resized_start).0;
            let byte_end = self.map_size;
            self.prepare_window_for_reading(byte_start, byte_end - byte_start);
            possibly_reusable_end = resized_start as usize;
        } else {
            possibly_reusable_end = get_num_chunks(self.map_size) as usize;
        }

        let num_new_chunks = get_num_chunks(self.file_size) as usize;
        let mut new_map = vec![ChunkDetails::new(); num_new_chunks];

        let mut deferred_hashes = Vec::new();
        for i in 0 .. num_new_chunks {
            if i < possibly_reusable_end && self.chunks[i].status != ChunkStatus::ToBeHashed {
                new_map[i].chunk_num = i as u32;
                new_map[i].hash.clear();
                new_map[i].pre_hash = self.sorted_map[i].pre_hash.clone();
                new_map[i].source_size = self.sorted_map[i].source_size;
            } else {
                let this_size = get_chunk_size(self.file_size, i as u32) as usize;
                let pos = get_start_end_positions(self.file_size, i as u32).0;
                assert!(this_size > 0);

                let mut tmp = vec![0u8; this_size];
                for (index, tmp_byte) in tmp.iter_mut().enumerate() {
                    *tmp_byte = self.sequencer[index + pos as usize];
                }

                deferred_hashes.push(Deferred::<_, String>::new(move || {
                    let sha512::Digest(name) = sha512::hash(&tmp[..]);
                    Ok((i, name, this_size))
                }));
            }
        }
        if let Ok(result) = Deferred::vec_to_promise(deferred_hashes,
                                                     ControlFlow::ParallelCPUS)
                                .sync() {
            for (chunk_number, name, this_size) in result {
                new_map[chunk_number].chunk_num = chunk_number as u32;
                new_map[chunk_number].hash.clear();
                new_map[chunk_number].pre_hash = name.to_vec();
                new_map[chunk_number].source_size = this_size as u64;
            }
        }

        let mut deferred_encryption = Vec::new();
        for i in 0 .. num_new_chunks {
            if i < possibly_reusable_end && self.chunks[i].status == ChunkStatus::AlreadyEncrypted {
                new_map[i].hash = self.sorted_map[i].hash.clone();
            } else {
                let this_size = get_chunk_size(self.file_size, i as u32) as usize;
                let pos = get_start_end_positions(self.file_size, i as u32).0;

                assert!(this_size > 0);
                let mut tmp = vec![0u8; this_size];
                for (index, tmp_char) in tmp.iter_mut().enumerate() {
                    *tmp_char = self.sequencer[index + pos as usize];
                }

                let storage = self.storage.clone();
                let pki = get_pad_key_and_iv(i as u32, &new_map, self.file_size);
                let def = encrypt_chunk(tmp, pki)
                              .chain::<_, String, _>(move |res| {
                                  let content = unwrap_result!(res);
                                  let sha512::Digest(name) = sha512::hash(&content);
                                  storage.put(name.to_vec(), content);
                                  Ok((i, name))
                              });
                deferred_encryption.push(def);
            }
        }
        if let Ok(result) = Deferred::vec_to_promise(deferred_encryption,
                                                     ControlFlow::ParallelCPUS)
                                .sync() {
            for (chunk_number, name) in result {
                new_map[chunk_number].hash = name.to_vec();
            }
        }

        DataMap::Chunks(new_map)
    }

    /// Truncate the self_encryptor to the specified size (if extended, filled with 0u8).
    #[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
    pub fn truncate(&mut self, new_size: u64) -> bool {
        if self.file_size == new_size {
            return true;
        }
        if new_size < self.file_size {
            let (chunks_start, chunks_end) =
                overlapped_chunks(self.map_size, new_size, self.file_size - new_size);
            if chunks_start != chunks_end {
                // One chunk might need to be decrypted.
                if !self.chunks[chunks_start].in_sequencer {
                    let byte_start = get_start_end_positions(self.map_size, chunks_start as u32).0;
                    if byte_start < new_size {
                        self.prepare_window_for_reading(byte_start, new_size - byte_start);
                    }
                }
                for chunk in &mut self.chunks[chunks_start .. chunks_end] {
                    chunk.status = ChunkStatus::ToBeHashed;
                    chunk.in_sequencer = true;
                }
            }
            self.sequencer.truncate(new_size as usize);
        } else {
            self.extend_sequencer_up_to(new_size);
        }
        self.file_size = new_size;
        true
    }

    /// Current file size as is known by encryptor.
    pub fn len(&self) -> u64 {
        self.file_size
    }

    /// Returns true if file size as is known by encryptor == 0.
    pub fn is_empty(&self) -> bool {
        self.file_size == 0
    }

    fn prepare_window_for_writing(&mut self, position: u64, length: u64) {
        self.file_size = cmp::max(self.file_size, position + length);

        let (chunks_start, chunks_end) = overlapped_chunks(self.map_size, position, length);
        if chunks_start == chunks_end {
            self.extend_sequencer_up_to(position + length);
            return;
        }

        // Two more chunks need to be decrypted for re-encryption.
        let next_two = [chunks_end % get_num_chunks(self.map_size) as usize,
                        (chunks_end + 1) % get_num_chunks(self.map_size) as usize];

        let required_len = {
            let mut end = get_start_end_positions(self.map_size, chunks_end as u32 - 1).1;
            end = cmp::max(end, get_start_end_positions(self.map_size, next_two[0] as u32).1);
            end = cmp::max(end, get_start_end_positions(self.map_size, next_two[1] as u32).1);
            cmp::max(position + length, end)
        };
        self.extend_sequencer_up_to(required_len);

        // Middle chunks don't need decrypting since they'll get overwritten.
        // TODO If first/last chunk gets completely overwritten, no need to decrypt.
        let mut vec_deferred = Vec::new();
        for &i in [chunks_start, chunks_end - 1].iter().chain(&next_two) {
            if self.chunks[i].in_sequencer {
                continue;
            }
            self.chunks[i].in_sequencer = true;
            let pos = get_start_end_positions(self.map_size, i as u32).0;
            vec_deferred.push(self.decrypt_chunk(i as u32)
                                  .chain::<_, String, _>(move |res| {
                                      Ok((pos, unwrap_result!(res)))
                                  }));
        }
        for (pos, vec) in unwrap_result!(Deferred::vec_to_promise(vec_deferred,
                                                                  ControlFlow::ParallelCPUS)
                                             .sync()) {
            let mut pos_aux = pos;
            for &byte in &vec {
                self.sequencer[pos_aux as usize] = byte;
                pos_aux += 1;
            }
        }
        for chunk in &mut self.chunks[chunks_start .. chunks_end] {
            chunk.status = ChunkStatus::ToBeHashed;
            chunk.in_sequencer = true;
        }
        for &i in &next_two {
            self.chunks[i].flag_for_encryption();
        }
    }

    fn prepare_window_for_reading(&mut self, position: u64, length: u64) {
        let (chunks_start, chunks_end) = overlapped_chunks(self.map_size, position, length);

        if chunks_start == chunks_end {
            self.extend_sequencer_up_to(position + length);
            return;
        }

        let required_len = {
            let end = get_start_end_positions(self.map_size, chunks_end as u32 - 1).1;
            cmp::max(position + length, end)
        };
        self.extend_sequencer_up_to(required_len);

        let mut vec_deferred = Vec::new();
        for i in chunks_start .. chunks_end {
            if self.chunks[i].in_sequencer {
                continue;
            }
            self.chunks[i].in_sequencer = true;
            let pos = get_start_end_positions(self.map_size, i as u32).0;
            vec_deferred.push(self.decrypt_chunk(i as u32)
                                  .chain::<_, String, _>(move |res| {
                                      Ok((pos, unwrap_result!(res)))
                                  }));
        }
        for (pos, vec) in unwrap_result!(Deferred::vec_to_promise(vec_deferred,
                                                                  ControlFlow::ParallelCPUS)
                                             .sync()) {
            let mut pos_aux = pos;
            for &byte in &vec {
                self.sequencer[pos_aux as usize] = byte;
                pos_aux += 1;
            }
        }
    }

    fn extend_sequencer_up_to(&mut self, new_len: u64) {
        if new_len > self.sequencer.len() as u64 {
            if new_len > MAX_IN_MEMORY_SIZE as u64 {
                match self.sequencer.create_mapping() {
                    Ok(()) => (),
                    Err(_) => return,   // FIXME return error or something
                }
            } else {
                let old_len = self.sequencer.len() as u64;
                self.sequencer.extend(repeat(0).take((new_len - old_len) as usize));
            }
        }
    }

    /// Decrypts a chunk of data.
    fn decrypt_chunk(&self, chunk_number: u32) -> Deferred<Vec<u8>, String> {
        let name = &self.sorted_map[chunk_number as usize].hash;
        let content = self.storage.get(name);
        let (pad, key, iv) =
            get_pad_key_and_iv(chunk_number, &self.sorted_map, self.map_size);

        // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
        Deferred::<Vec<u8>, String>::new(move || {
            let xor_result = xor(&content, &pad);
            match decrypt(&xor_result, &key, &iv) {
                Ok(decrypted) => {
                    let mut chunk = Vec::new();
                    let mut decoder = DeflateDecoder::new(&decrypted[..]);
                    match decoder.read_to_end(&mut chunk) {
                        Ok(size) => {
                            if size > 0 {
                                return Ok(chunk);
                            }
                            Err("Decompression failure".to_owned())
                        }
                        Err(error) => Err(error.description().to_owned()),
                    }
                }
                _ => Err(format!("Failed decrypting chunk {}", chunk_number)),
            }
        })
    }
}

/// Encrypts a chunk of data.
fn encrypt_chunk(content: Vec<u8>, pki: (Pad, Key, Iv)) -> Deferred<Vec<u8>, String> {
    let (pad, key, iv) = pki;
    // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
    Deferred::<Vec<u8>, String>::new(move || {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::Default);
        match encoder.write_all(&content[..]) {
            Ok(()) => {
                match encoder.finish() {
                    Ok(compressed) => {
                        let encrypted = encrypt(&compressed, &key, &iv);
                        Ok(xor(&encrypted, &pad))
                    }
                    Err(error) => Err(error.description().to_owned()),
                }
            }
            Err(error) => Err(error.description().to_owned()),
        }
    })
}

fn get_pad_key_and_iv(chunk_number: u32, sorted_map: &[ChunkDetails], map_size: u64)
                                                                 -> (Pad, Key, Iv) {
    let n_1 = get_previous_chunk_number(map_size, chunk_number);
    let n_2 = get_previous_chunk_number(map_size, n_1);
    let vec     = &sorted_map[chunk_number as usize].pre_hash;
    let n_1_vec = &sorted_map[n_1 as usize].pre_hash;
    let n_2_vec = &sorted_map[n_2 as usize].pre_hash;

    let mut pad = [0u8; PAD_SIZE];
    for (i, &element) in vec.iter()
                            .chain(&n_1_vec[(KEY_SIZE + IV_SIZE)..HASH_SIZE])
                            .chain(&n_2_vec[..])
                            .enumerate() {
        pad[i] = element;
    }

    let mut key = [0u8; KEY_SIZE];
    for (i, &element) in n_1_vec[0..KEY_SIZE].iter().enumerate() {
        key[i] = element;
    }

    let mut iv = [0u8; IV_SIZE];
    for (i, &element) in n_1_vec[KEY_SIZE..(KEY_SIZE + IV_SIZE)].iter().enumerate() {
        iv[i] = element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

/// Returns the chunk range [start, end) that is overlapped by the byte range defined by
/// `position` and `length`. Returns empty range if file_size is so small that there are
/// no chunks.
fn overlapped_chunks(file_size: u64, position: u64, length: u64) -> (usize, usize) {
    if file_size < (3 * MIN_CHUNK_SIZE as u64) || position >= file_size || length == 0 {
        return (0, 0);
    }
    let start = get_chunk_number(file_size, position);
    let end_pos = position + length - 1;    // inclusive
    let end =
        if end_pos < file_size {
            get_chunk_number(file_size, end_pos) + 1
        } else {
            get_num_chunks(file_size)
        };
    (start as usize, end as usize)
}

/// Returns a chunk range [start, end) whose sizes are affected by a change in file size.
fn resized_chunks(old_size: u64, new_size: u64) -> (u32, u32) {
    if old_size == new_size || old_size < (3 * MIN_CHUNK_SIZE as u64) {
        return (0, 0);
    }
    if old_size < (3 * MAX_CHUNK_SIZE as u64) {
        return (0, 3);
    }
    if new_size > old_size {
        let remainder = (old_size % MAX_CHUNK_SIZE as u64) as u32;
        if remainder == 0 {
            return (0, 0);
        } else if remainder >= MIN_CHUNK_SIZE {
            let last = get_num_chunks(old_size) - 1;
            return (last, last + 1);
        } else {
            let last = get_num_chunks(old_size) - 1;
            return (last - 1, last + 1);
        }
    }

    // new_size is less than old_size, old_size is at least 3 * MAX_CHUNK_SIZE

    if new_size >= (3 * MAX_CHUNK_SIZE as u64) {
        let remainder = (new_size % MAX_CHUNK_SIZE as u64) as u32;
        if remainder == 0 {
            return (0, 0);
        } else if remainder >= MIN_CHUNK_SIZE {
            let last = get_chunk_number(old_size, new_size - 1);
            return (last, last + 1);
        } else {
            let last = get_chunk_number(old_size, new_size - 1);
            return (last - 1, last + 1);
        }
    }
    if new_size > 0 {
        return (0, get_chunk_number(old_size, new_size - 1) + 1);
    }
    (0, 0)
}

/// Returns the number of chunks according to file size.
#[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
fn get_num_chunks(file_size: u64) -> u32 {
    if file_size < (3 * MIN_CHUNK_SIZE as u64) {
        return 0;
    }
    if file_size < (3 * MAX_CHUNK_SIZE as u64) {
        return 3;
    }
    if file_size % MAX_CHUNK_SIZE as u64 == 0 {
        (file_size / MAX_CHUNK_SIZE as u64) as u32
    } else {
        ((file_size / MAX_CHUNK_SIZE as u64) + 1) as u32
    }
}

/// Returns the size of a chunk according to file size.
#[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
fn get_chunk_size(file_size: u64, chunk_number: u32) -> u32 {
    if file_size < 3 * MIN_CHUNK_SIZE as u64 {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE as u64 {
        if chunk_number < 2 {
            return (file_size / 3) as u32;
        } else {
            return (file_size - (2 * (file_size / 3))) as u32;
        }
    }
    if chunk_number < get_num_chunks(file_size) - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = (file_size % MAX_CHUNK_SIZE as u64) as u32;
    let penultimate = (get_num_chunks(file_size) - 2) == chunk_number;
    if remainder == 0 {
        return MAX_CHUNK_SIZE;
    }
    if remainder < MIN_CHUNK_SIZE {
        if penultimate {
            MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        } else {
            MIN_CHUNK_SIZE + remainder
        }
    } else {
        if penultimate {
            MAX_CHUNK_SIZE
        } else {
            remainder
        }
    }
}

/// Returns the [start, end) half-open byte range of a chunk.
fn get_start_end_positions(file_size: u64, chunk_number: u32) -> (u64, u64) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start;
    let last = (get_num_chunks(file_size) - 1) == chunk_number;
    if last {
        start = get_chunk_size(file_size, 0) as u64 * (chunk_number as u64 - 1) +
                get_chunk_size(file_size, chunk_number - 1) as u64;
    } else {
        start = get_chunk_size(file_size, 0) as u64 * chunk_number as u64;
    }
    (start, start + get_chunk_size(file_size, chunk_number) as u64)
}

fn get_previous_chunk_number(file_size: u64, chunk_number: u32) -> u32 {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }
    (get_num_chunks(file_size) + chunk_number - 1) % get_num_chunks(file_size)
}

#[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
fn get_chunk_number(file_size: u64, position: u64) -> u32 {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }

    let remainder = file_size % get_chunk_size(file_size, 0) as u64;
    if remainder == 0 || remainder >= MIN_CHUNK_SIZE as u64 ||
       position < file_size - remainder - MIN_CHUNK_SIZE as u64 {
        return (position / get_chunk_size(file_size, 0) as u64) as u32;
    }
    get_num_chunks(file_size) - 1
}

impl<S: Storage + Send + Sync + 'static> Debug for SelfEncryptor<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        try!(write!(formatter, "SelfEncryptor {{\n    chunks:\n"));
        for (i, chunk) in self.chunks.iter().enumerate() {
            try!(write!(formatter, "        {:?}   {:?}\n", self.sorted_map[i], chunk))
        }
        try!(write!(formatter, "    map_size: {}\n", self.map_size));
        write!(formatter, "    file_size: {}\n}}", self.file_size)
    }
}

fn initialise_sodiumoxide() {
    static INITIALISE_SODIUMOXIDE: Once = ONCE_INIT;
    INITIALISE_SODIUMOXIDE.call_once(|| assert!(sodiumoxide::init()));
}

#[cfg(test)]
mod test {
    use maidsafe_utilities::serialisation;
    use rand::distributions::{Range, Sample};
    use rand::{random, thread_rng};
    use std::sync::Arc;
    use super::*;
    use test_helpers::{random_bytes, SimpleStorage};

    #[test]
    fn helper_functions() {
        let mut file_size = MIN_CHUNK_SIZE as u64 * 3;
        assert_eq!(::get_num_chunks(file_size), 3);
        assert_eq!(::get_chunk_size(file_size, 0), 1024);
        assert_eq!(::get_chunk_size(file_size, 1), 1024);
        assert_eq!(::get_chunk_size(file_size, 2), 1024);
        assert_eq!(::get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(::get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(::get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(::get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(::get_start_end_positions(file_size, 0).1, MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).0, MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).1, 2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).0, 2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).1, 3 * MIN_CHUNK_SIZE as u64);

        file_size = (MIN_CHUNK_SIZE as u64 * 3) + 1;
        assert_eq!(::get_num_chunks(file_size), 3);
        assert_eq!(::get_chunk_size(file_size, 0), 1024);
        assert_eq!(::get_chunk_size(file_size, 1), 1024);
        assert_eq!(::get_chunk_size(file_size, 2), 1025);
        assert_eq!(::get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(::get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(::get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(::get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(::get_start_end_positions(file_size, 0).1, MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).0, MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).1, 2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).0, 2 * MIN_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).1,
                   1 + 3 * MIN_CHUNK_SIZE as u64);

        file_size = MAX_CHUNK_SIZE as u64 * 3;
        assert_eq!(::get_num_chunks(file_size), 3);
        assert_eq!(::get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 2), MAX_CHUNK_SIZE);
        assert_eq!(::get_previous_chunk_number(file_size, 0), 2);
        assert_eq!(::get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(::get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(::get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(::get_start_end_positions(file_size, 0).1, MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).0, MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).1, 2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).0, 2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).1, 3 * MAX_CHUNK_SIZE as u64);

        file_size = MAX_CHUNK_SIZE as u64 * 3 + 1;
        assert_eq!(::get_num_chunks(file_size), 4);
        assert_eq!(::get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 2), MAX_CHUNK_SIZE - MIN_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 3), MIN_CHUNK_SIZE + 1);
        assert_eq!(::get_previous_chunk_number(file_size, 0), 3);
        assert_eq!(::get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(::get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(::get_previous_chunk_number(file_size, 3), 2);
        assert_eq!(::get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(::get_start_end_positions(file_size, 0).1, MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).0, MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).1, 2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).0, 2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).1,
                   ((3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE) as u64);
        assert_eq!(::get_start_end_positions(file_size, 3).0,
                   ::get_start_end_positions(file_size, 2).1);
        assert_eq!(::get_start_end_positions(file_size, 3).1, file_size);

        file_size = (MAX_CHUNK_SIZE * 7) as u64 + 1024;
        assert_eq!(::get_num_chunks(file_size), 8);
        assert_eq!(::get_chunk_size(file_size, 0), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 1), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 2), MAX_CHUNK_SIZE);
        assert_eq!(::get_chunk_size(file_size, 3), MAX_CHUNK_SIZE);
        assert_eq!(::get_previous_chunk_number(file_size, 0), 7);
        assert_eq!(::get_previous_chunk_number(file_size, 1), 0);
        assert_eq!(::get_previous_chunk_number(file_size, 2), 1);
        assert_eq!(::get_previous_chunk_number(file_size, 3), 2);
        assert_eq!(::get_start_end_positions(file_size, 0).0, 0u64);
        assert_eq!(::get_start_end_positions(file_size, 0).1, MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).0, MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 1).1, 2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).0, 2 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 2).1, 3 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 3).0, 3 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, 7).1,
                           ((7 * MAX_CHUNK_SIZE) as u64 + 1024));

        file_size = (MAX_CHUNK_SIZE * 11) as u64 - 1;
        assert_eq!(::get_num_chunks(file_size), 11);
        assert_eq!(::get_previous_chunk_number(file_size, 11), 10);

        file_size = (MAX_CHUNK_SIZE * 11) as u64 + 1;
        assert_eq!(::get_num_chunks(file_size), 11 + 1);
        assert_eq!(::get_previous_chunk_number(file_size, 11), 10);

        let number_of_chunks: u32 = 11;
        file_size = (MAX_CHUNK_SIZE as u64 * number_of_chunks as u64) + 1024;
        assert_eq!(::get_num_chunks(file_size), number_of_chunks + 1);
        for i in 0..number_of_chunks {
            // preceding and next index, wrapped around
            let h = (i + number_of_chunks) % (number_of_chunks + 1);
            let j = (i + 1) % (number_of_chunks + 1);
            assert_eq!(::get_chunk_size(file_size, i), MAX_CHUNK_SIZE);
            assert_eq!(::get_previous_chunk_number(file_size, i), h);
            assert_eq!(::get_start_end_positions(file_size, i).0,
                       i as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(::get_start_end_positions(file_size, i).1,
                       j as u64 * MAX_CHUNK_SIZE as u64);
        }
        assert_eq!(::get_chunk_size(file_size, number_of_chunks), MIN_CHUNK_SIZE);
        assert_eq!(::get_previous_chunk_number(file_size, number_of_chunks),
                   number_of_chunks - 1);
        assert_eq!(::get_start_end_positions(file_size, number_of_chunks).0,
                   number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, number_of_chunks).1,
                   ((number_of_chunks * MAX_CHUNK_SIZE) as u64 + 1024));

        let number_of_chunks: u32 = 100;
        file_size = MAX_CHUNK_SIZE as u64 * number_of_chunks as u64;
        assert_eq!(::get_num_chunks(file_size), number_of_chunks);
        for i in 0..number_of_chunks - 1 {
            // preceding and next index, wrapped around
            let h = (i + number_of_chunks - 1) % number_of_chunks;
            let j = (i + 1) % number_of_chunks;
            assert_eq!(::get_chunk_size(file_size, i), MAX_CHUNK_SIZE);
            assert_eq!(::get_previous_chunk_number(file_size, i), h);
            assert_eq!(::get_start_end_positions(file_size, i).0,
                       i as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(::get_start_end_positions(file_size, i).1,
                       j as u64 * MAX_CHUNK_SIZE as u64);
        }
        assert_eq!(::get_previous_chunk_number(file_size, number_of_chunks),
                   number_of_chunks - 1);
        assert_eq!(::get_start_end_positions(file_size, number_of_chunks).0,
                   number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
        assert_eq!(::get_start_end_positions(file_size, number_of_chunks - 1).1,
                   ((number_of_chunks * MAX_CHUNK_SIZE) as u64));
    }

    fn check_file_size(se: &SelfEncryptor<SimpleStorage>, expected_file_size: u64) {
        assert_eq!(se.file_size, expected_file_size);
        if se.sorted_map.len() > 0 {
            let chunks_cumulated_size = se.sorted_map.iter().fold(0u64, |acc, chunk| {
                acc + chunk.source_size
            });
            assert_eq!(chunks_cumulated_size, expected_file_size);
        }
    }

    #[test]
    fn xor() {
        let mut data: Vec<u8> = vec![];
        let mut pad = [0u8; super::PAD_SIZE];
        for _ in 0..800 {
            data.push(random::<u8>());
        }
        for ch in pad.iter_mut() {
            *ch = random::<u8>();
        }
        assert_eq!(data,
                   super::xor(&super::xor(&data, &super::Pad(pad)), &super::Pad(pad)));
    }

    #[test]
    fn write() {
        let my_storage = Arc::new(SimpleStorage::new());
        let mut se = SelfEncryptor::new(my_storage, DataMap::None);
        let size = 3;
        let offset = 5u32;
        let the_bytes = random_bytes(size);
        se.write(&the_bytes, offset as u64);
        check_file_size(&se, (size + offset as usize) as u64);
    }

    #[test]
    fn multiple_writes() {
        let my_storage = Arc::new(SimpleStorage::new());
        let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
        let size1 = 3;
        let size2 = 4;
        let part1 = random_bytes(size1);
        let part2 = random_bytes(size2);
        // Just testing multiple subsequent write calls
        se.write(&part1, 0);
        se.write(&part2, size1 as u64);
        // Let's also test an overwrite.. over middle bytes of part2
        se.write(&[4u8, 2], size1 as u64 + 1);
        check_file_size(&se, (size1 + size2) as u64);
        let data_map = se.close();
        se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = se.read(0, (size1 + size2) as u64);
        assert!(&fetched[..size1] == &part1[..]);
        assert_eq!(fetched[size1], part2[0]);
        assert!(&fetched[size1 + 1..size1 + 3] == &[4u8, 2][..]);
        assert!(&fetched[size1 + 3..] == &part2[3..]);
    }

    #[test]
    fn three_min_chunks_minus_one() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE * 3) - 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.sorted_map.len(), 0);
            assert_eq!(se.sequencer.len(), bytes_len as usize);
            check_file_size(&se, bytes_len as u64);
            // check close
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(_) => panic!("shall not return DataMap::Chunks"),
            DataMap::Content(ref content) => assert_eq!(content.len(), bytes_len as usize),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn three_min_chunks() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let the_bytes = random_bytes(MIN_CHUNK_SIZE as usize * 3);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, MIN_CHUNK_SIZE as u64 * 3);
            let fetched = se.read(0, MIN_CHUNK_SIZE as u64 * 3);
            assert!(fetched == the_bytes);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(my_storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, MIN_CHUNK_SIZE as u64 * 3);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn three_min_chunks_plus_one() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(my_storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn three_max_chunks() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(my_storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn three_max_chunks_plus_one() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = (MAX_CHUNK_SIZE * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            // check close
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                assert_eq!(my_storage.clone().num_entries(), 4);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn seven_and_a_bit_max_chunks() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = (MAX_CHUNK_SIZE * 7) + 1024;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 8);
                assert_eq!(my_storage.clone().num_entries(), 8);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn large_file_one_byte_under_eleven_chunks() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) - 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize);
                assert_eq!(my_storage.clone().num_entries(), number_of_chunks as usize);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn large_file_one_byte_over_eleven_chunks() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize + 1);
                assert_eq!(my_storage.clone().num_entries(),
                           number_of_chunks as usize + 1);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn large_file_size_1024_over_eleven_chunks() {
        // has been tested for 50 chunks
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1024;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            // check close
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize + 1);
                assert_eq!(my_storage.clone().num_entries(),
                           number_of_chunks as usize + 1);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn five_and_extend_to_seven_plus_one() {
        let my_storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE * 5;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len as u64);
            se.truncate((7 * MAX_CHUNK_SIZE + 1) as u64);
            check_file_size(&se, (7 * MAX_CHUNK_SIZE + 1) as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 8);
                assert_eq!(my_storage.clone().num_entries(), 8);
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
    }

    #[test]
    fn truncate_three_max_chunks() {
        let storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
            se.write(&bytes, 0);
            check_file_size(&se, bytes_len as u64);
            se.truncate(bytes_len as u64 - 24);
            check_file_size(&se, bytes_len as u64 - 24);
            data_map = se.close();
        }
        assert_eq!(data_map.len(), bytes_len as u64 - 24);
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert!(storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("datamap should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(storage.clone(), data_map);
        let fetched = se.read(0, bytes_len as u64 - 24);
        assert!(&fetched[..] == &bytes[..(bytes_len - 24) as usize]);
    }

    #[test]
    fn truncate_from_datamap() {
        let storage = Arc::new(SimpleStorage::new());
        let bytes_len = MAX_CHUNK_SIZE * 3;
        let bytes = random_bytes(bytes_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
            se.write(&bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        let data_map2: DataMap;
        {
            // Start with an existing datamap.
            let mut se = SelfEncryptor::new(storage.clone(), data_map);
            se.truncate(bytes_len as u64 - 24);
            data_map2 = se.close();
        }
        assert_eq!(data_map2.len(), bytes_len as u64 - 24);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.clone().num_entries(), 6);   // old ones + new ones
                for chunk_detail in chunks.iter() {
                    assert!(storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("datamap should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(storage.clone(), data_map2);
        let fetched = se.read(0, bytes_len as u64 - 24);
        assert!(&fetched[..] == &bytes[..(bytes_len - 24) as usize]);
    }

    #[test]
    fn truncate_to_extend_from_datamap() {
        let storage = Arc::new(SimpleStorage::new());
        let bytes_len = MAX_CHUNK_SIZE * 3 - 24;
        let bytes = random_bytes(bytes_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
            se.write(&bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        let data_map2: DataMap;
        {
            // Start with an existing datamap.
            let mut se = SelfEncryptor::new(storage.clone(), data_map);
            se.truncate(bytes_len as u64 + 24);
            data_map2 = se.close();
        }
        assert_eq!(data_map2.len(), bytes_len as u64 + 24);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(storage.clone().num_entries(), 6);   // old ones + new ones
                for chunk_detail in chunks.iter() {
                    assert!(storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("datamap should be DataMap::Chunks"),
        }
        let mut se = SelfEncryptor::new(storage.clone(), data_map2);
        let fetched = se.read(0, bytes_len as u64 + 24);
        assert!(&fetched[..bytes_len as usize] == &bytes[..]);
        assert!(&fetched[bytes_len as usize..] == &[0u8; 24]);
    }

    #[test]
    fn large_100mb_file() {
        let storage = Arc::new(SimpleStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 100;
        let bytes_len = MAX_CHUNK_SIZE as usize * number_of_chunks as usize;
        let bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
            se.write(&bytes, 0);
            check_file_size(&se, bytes_len as u64);
            data_map = se.close();
        }
        match data_map {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize);
                assert_eq!(storage.clone().num_entries(), number_of_chunks as usize);
                for chunk_detail in chunks.iter() {
                    assert!(storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == bytes);
    }

    #[test]
    fn write_starting_with_existing_datamap() {
        let my_storage = Arc::new(SimpleStorage::new());
        let part1_len = MIN_CHUNK_SIZE * 3;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&part1_bytes, 0);
            check_file_size(&se, part1_len as u64);
            data_map = se.close();
        }
        let part2_len = 1024;
        let part2_bytes = random_bytes(part2_len as usize);
        let full_len = part1_len + part2_len;
        let data_map2: DataMap;
        {
            // Start with an existing datamap.
            let mut se = SelfEncryptor::new(my_storage.clone(), data_map);
            se.write(&part2_bytes, part1_len as u64);
            // check_file_size(&se, full_len);
            data_map2 = se.close();
        }
        assert_eq!(data_map2.len(), full_len as u64);

        let mut se = SelfEncryptor::new(my_storage.clone(), data_map2);
        let fetched = se.read(0, full_len as u64);
        assert!(&part1_bytes[..] == &fetched[..part1_len as usize]);
        assert!(&part2_bytes[..] == &fetched[part1_len as usize..]);
    }

    #[test]
    fn write_starting_with_existing_datamap2() {
        let my_storage = Arc::new(SimpleStorage::new());
        let part1_len = MAX_CHUNK_SIZE * 3 - 24;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&part1_bytes, 0);
            check_file_size(&se, part1_len as u64);
            data_map = se.close();
        }
        let part2_len = 1024;
        let part2_bytes = random_bytes(part2_len as usize);
        let full_len = part1_len + part2_len;
        let data_map2: DataMap;
        {
            // Start with an existing datamap.
            let mut se = SelfEncryptor::new(my_storage.clone(), data_map);
            se.write(&part2_bytes, part1_len as u64);
            data_map2 = se.close();
        }
        assert_eq!(data_map2.len(), full_len as u64);
        match data_map2 {
            DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                assert_eq!(my_storage.clone().num_entries(), 7);   // old ones + new ones
                for chunk_detail in chunks.iter() {
                    assert!(my_storage.clone().has_chunk(&chunk_detail.hash));
                }
            }
            _ => panic!("datamap should be DataMap::Chunks"),
        }

        let mut se = SelfEncryptor::new(my_storage.clone(), data_map2);
        let fetched = se.read(0, full_len as u64);
        assert!(&part1_bytes[..] == &fetched[..part1_len as usize]);
        assert!(&part2_bytes[..] == &fetched[part1_len as usize..]);
    }

    #[test]
    fn overwrite_starting_with_existing_datamap() {
        let my_storage = Arc::new(SimpleStorage::new());
        let part1_len = MAX_CHUNK_SIZE * 4;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&part1_bytes, 0);
            check_file_size(&se, part1_len as u64);
            data_map = se.close();
        }
        let part2_len = 2;
        let part2_bytes = random_bytes(part2_len);
        let data_map2: DataMap;
        {
            // Start with an existing datamap.
            let mut se = SelfEncryptor::new(my_storage.clone(), data_map);
            // Overwrite. This and next two chunks will have to be re-encrypted.
            se.write(&part2_bytes, 2);
            data_map2 = se.close();
        }
        assert_eq!(data_map2.len(), part1_len as u64);

        let mut se = SelfEncryptor::new(my_storage.clone(), data_map2);
        let fetched = se.read(0, part1_len as u64);
        assert!(&part1_bytes[..2] == &fetched[..2]);
        assert!(&part2_bytes[..] == &fetched[2..2 + part2_len]);
        assert!(&part1_bytes[2 + part2_len..] == &fetched[2 + part2_len..]);
    }

    fn create_vector_data_map(storage: Arc<SimpleStorage>, vec_len: usize) -> DataMap {
        let data: Vec<usize> = (0..vec_len).collect();
        let serialised_data: Vec<u8> = serialisation::serialise(&data)
                                           .expect("failed to serialise Vec<usize>");
        let mut self_encryptor = SelfEncryptor::new(storage, DataMap::None);
        self_encryptor.write(&serialised_data, 0);
        check_file_size(&self_encryptor, serialised_data.len() as u64);
        self_encryptor.close()
    }

    fn check_vector_data_map(storage: Arc<SimpleStorage>, vec_len: usize, datamap: &DataMap) {
        let mut self_encryptor = SelfEncryptor::new(storage, datamap.clone());
        let length = self_encryptor.len();
        let data_to_deserialise: Vec<u8> = self_encryptor.read(0, length);
        let data: Vec<usize> = serialisation::deserialise(&data_to_deserialise)
                                   .expect("failed to deserialise Vec<usize>");
        assert_eq!(data.len(), vec_len);
        for (index, data_char) in data.iter().enumerate() {
            assert_eq!(*data_char, index);
        }
    }

    #[test]
    fn serialised_vectors() {
        for vec_len in vec![1000, 2000, 5000, 10_000, 20_000, 50_000, 100_000, 20_0000, 50_0000,
                            1_000_000] {
            let storage = Arc::new(SimpleStorage::new());
            let datamap: DataMap = create_vector_data_map(storage.clone(), vec_len);
            check_vector_data_map(storage.clone(), vec_len, &datamap);
        }
    }

    #[test]
    fn get_chunk_number() {
        // Test chunk_number for files up to 3 * MIN_CHUNK_SIZE - 1.  Should be 0 for all bytes.
        let mut min_test_size = 0;
        let mut max_test_size = 3 * MIN_CHUNK_SIZE;
        for file_size in min_test_size..max_test_size {
            for byte_index in 0..file_size {
                assert_eq!(::get_chunk_number(file_size as u64, byte_index as u64), 0);
            }
        }

        // Test chunk_number for files up to 3 * MAX_CHUNK_SIZE.  File should be thirded with any
        // extra bytes appended to last chunk.
        min_test_size = max_test_size;
        max_test_size = (3 * MAX_CHUNK_SIZE) + 1;
        let mut range = Range::new(90000, 100000);
        let mut rng = thread_rng();
        let step = range.sample(&mut rng);
        for file_size in (min_test_size..max_test_size).filter(|&elt| elt % step == 0) {
            assert_eq!(::get_num_chunks(file_size as u64), 3);
            let mut index_start;
            let mut index_end = 0;
            for chunk_index in 0..3 {
                index_start = index_end;
                index_end += ::get_chunk_size(file_size as u64, chunk_index);
                for byte_index in index_start..index_end {
                    assert_eq!(::get_chunk_number(file_size as u64, byte_index as u64), chunk_index);
                }
            }
        }

        // Test chunk_number for files up to (3 * MAX_CHUNK_SIZE) + MIN_CHUNK_SIZE - 1.  First two
        // chunks should each have MAX_CHUNK_SIZE bytes, third chunk should have
        // (MAX_CHUNK_SIZE - MIN_CHUNK_SIZE) bytes, with final chunk containing remainder.
        min_test_size = max_test_size;
        max_test_size = (3 * MAX_CHUNK_SIZE) + MIN_CHUNK_SIZE;
        const CHUNK_0_START: u32 = 0;
        const CHUNK_0_END: u32 = MAX_CHUNK_SIZE - 1;
        const CHUNK_1_START: u32 = MAX_CHUNK_SIZE;
        const CHUNK_1_END: u32 = (2 * MAX_CHUNK_SIZE) - 1;
        const CHUNK_2_START: u32 = 2 * MAX_CHUNK_SIZE;
        for file_size in min_test_size..max_test_size {
            const CHUNK_2_END: u32 = (3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE - 1;
            assert_eq!(::get_num_chunks(file_size as u64), 4);
            let mut test_indices = vec![CHUNK_0_START,
                                        CHUNK_0_END,
                                        CHUNK_1_START,
                                        CHUNK_1_END,
                                        CHUNK_2_START,
                                        CHUNK_2_END];
            test_indices.append(&mut ((CHUNK_2_END + 1)..(file_size - 1)).collect::<Vec<_>>());
            for byte_index in test_indices {
                let expected_number = match byte_index {
                    CHUNK_0_START...CHUNK_0_END => 0,
                    CHUNK_1_START...CHUNK_1_END => 1,
                    CHUNK_2_START...CHUNK_2_END => 2,
                    _ => 3,
                };
                assert_eq!(::get_chunk_number(file_size as u64, byte_index as u64), expected_number);
            }
        }

        // Test chunk_number for files up to 4 * MAX_CHUNK_SIZE.  First three chunks should each
        // have MAX_CHUNK_SIZE bytes, fourth chunk containing remainder.
        min_test_size = max_test_size;
        max_test_size = 4 * MAX_CHUNK_SIZE;
        for file_size in (min_test_size..max_test_size).filter(|&elt| elt % step == 0) {
            const CHUNK_2_END: u32 = (3 * MAX_CHUNK_SIZE) - 1;
            assert_eq!(::get_num_chunks(file_size as u64), 4);
            let mut test_indices = vec![CHUNK_0_START,
                                        CHUNK_0_END,
                                        CHUNK_1_START,
                                        CHUNK_1_END,
                                        CHUNK_2_START,
                                        CHUNK_2_END];
            test_indices.append(&mut ((CHUNK_2_END + 1)..(file_size - 1)).collect::<Vec<_>>());
            for byte_index in test_indices {
                let expected_number = match byte_index {
                    CHUNK_0_START...CHUNK_0_END => 0,
                    CHUNK_1_START...CHUNK_1_END => 1,
                    CHUNK_2_START...CHUNK_2_END => 2,
                    _ => 3,
                };
                assert_eq!(::get_chunk_number(file_size as u64, byte_index as u64), expected_number);
            }
        }
    }
}
