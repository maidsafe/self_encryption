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
//! extern crate self_encryption;
//! use std::sync::{Arc,Mutex};
//!
//! struct Entry {
//!     name: Vec<u8>,
//!     data: Vec<u8>
//! }
//!
//! struct MyStorage {
//!     entries: Arc<Mutex<Vec<Entry>>>
//! }
//!
//! impl MyStorage {
//!     fn new() -> MyStorage {
//!         MyStorage { entries: Arc::new(Mutex::new(Vec::new())) }
//!     }
//!
//!     fn has_chunk(&self, name: &[u8]) -> bool {
//!         let lock = self.entries.lock().unwrap();
//!         for entry in lock.iter() {
//!             if entry.name == name { return true }
//!         }
//!         false
//!     }
//!  }
//!
//!  impl self_encryption::Storage for MyStorage {
//!     fn get(&self, name: Vec<u8>) -> Vec<u8> {
//!         let lock = self.entries.lock().unwrap();
//!         for entry in lock.iter() {
//!             if entry.name == name { return entry.data.to_vec() }
//!         }
//!         vec![]
//!     }
//!
//!     fn put(&self, name: Vec<u8>, data: Vec<u8>) {
//!         let mut lock = self.entries.lock().unwrap();
//!         lock.push(Entry { name : name, data : data })
//!     }
//! }
//! ```
//!
//! Use of this setup would be to implement a self encryptor e.g  `let mut se =
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
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

extern crate asynchronous;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate memmap as mmap;
extern crate flate2;

// This is pub to test the tests directory integration tests; these are temporary and need to be
// replaced with actual integration tests. This should be private
mod encryption;
/// Information required to recover file content from chunks.
pub mod datamap;

use std::cmp;
use std::iter::repeat;
use std::sync::Arc;
use std::io::{self, ErrorKind, Read, Result, Write};
use std::error::Error;
use std::ops::{Deref, DerefMut, Index, IndexMut};

use asynchronous::{ControlFlow, Deferred};
use sodiumoxide::crypto::hash::sha512;
use encryption::{IV_SIZE, Iv, KEY_SIZE, Key, decrypt, encrypt};
use datamap::DataMap;
use mmap::{Mmap, Protection};
use flate2::write::DeflateEncoder;
use flate2::read::DeflateDecoder;
use flate2::Compression;

const HASH_SIZE: usize = sha512::DIGESTBYTES;
const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

const MAX_IN_MEMORY_SIZE: usize = 50 * (1 << 20);
/// MAX_MEMORY_MAP_SIZE defined as 1GB.
pub const MAX_MEMORY_MAP_SIZE: usize = 1 << 30;

struct Pad(pub [u8; PAD_SIZE]);

/// MAX_CHUNK_SIZE defined as 1MB.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// MIN_CHUNK_SIZE defined as 1KB.
pub const MIN_CHUNK_SIZE: u32 = 1024;

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
fn xor(data: &[u8], &Pad(pad): &Pad) -> Vec<u8> {
    data.iter().zip(pad.iter().cycle()).map(|(&a, &b)| a ^ b).collect()
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ChunkStatus {
    ToBeHashed,
    ToBeEncrypted,
    AlreadyEncrypted,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ChunkLocation {
    InSequencer,
    Remote,
}

// pub struct Chunk { pub name:  Vec<u8>, pub content: Vec<u8> }

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Chunk {
    number: u32,
    status: ChunkStatus,
    location: ChunkLocation,
}

/// Optionally create a sequence of bytes via a vector or memory map.
pub struct Sequencer {
    vector: Option<Vec<u8>>,
    mmap: Option<Mmap>,
}

impl Sequencer {
    /// Initialise as a vector.
    pub fn as_vector() -> Sequencer {
        Sequencer {
            vector: Some(Vec::with_capacity(MAX_IN_MEMORY_SIZE)),
            mmap: None,
        }
    }

    /// Initialise as a memory map
    pub fn as_mmap() -> Sequencer {
        Sequencer {
            vector: None,
            mmap: Some(Mmap::anonymous(MAX_MEMORY_MAP_SIZE, Protection::ReadWrite).unwrap()),
        }
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
                for i in 0..content.len() {
                    vector.push(content[i]);
                }
            }
            None => {
                match self.mmap {
                    Some(ref mut mmap) => {
                        let _ = unsafe { mmap.as_mut_slice() }.write_all(&content[..]);
                    }
                    None => {}
                }
            }
        }
    }

    /// Truncate internal object to given size. Note that this affects the vector only since the
    /// memory map is a fixed size.
    pub fn truncate(&mut self, size: usize) {
        match self.vector {
            Some(ref mut vector) => {
                vector.truncate(size);
            }
            None => {}
        }
    }

    #[allow(unsafe_code)]
    /// Create a memory map if we haven't already done so.
    pub fn create_mapping(&mut self) -> Result<()> {
        match self.mmap {
            Some(_) => return Ok(()),
            None => {}
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
        match self.vector {
            Some(ref mut vector) => vector.extend(iterable),
            None => {}
        }
    }
}

/// Storage traits of SelfEncryptor. Data stored in Storage is encrypted, name is the SHA512 hash
/// of content. Storage can be in-memory HashMap or disk based
pub trait Storage {
    /// Fetch the data bearing the name
    fn get(&self, name: Vec<u8>) -> Vec<u8>;
    /// Insert the data bearing the name.
    fn put(&self, name: Vec<u8>, data: Vec<u8>);
}

/// This is the encryption object and all file handling should be done using this object as the low
/// level mechanism to read and write *content*. This library has no knowledge of file metadata.
/// This is a library to ensure content is secured.
pub struct SelfEncryptor<S: Storage> {
    storage: Arc<S>,
    datamap: DataMap,
    chunks: Vec<Chunk>,
    sequencer: Sequencer,
    file_size: u64,
}

impl<S: Storage + Send + Sync + 'static> SelfEncryptor<S> {
    /// This is the only constructor for an encryptor object. Each SelfEncryptor is used for a
    /// single file. The parameters are a DataMap and Storage. If new file, use DataMap::None as
    /// first parameter. The get and put of Storage need to be implemented to allow the
    /// SelfEncryptor to store encrypted chunks and retrieve them when necessary.
    pub fn new(storage: Arc<S>, datamap: DataMap) -> SelfEncryptor<S> {
        sodiumoxide::init();
        let file_size = datamap.len();
        let mut sequencer;
        let mut chunks = vec![];

        if file_size <= MAX_IN_MEMORY_SIZE as u64 {
            sequencer = Sequencer::as_vector();
        } else {
            sequencer = Sequencer::as_mmap();
        }

        match datamap {
            DataMap::Content(ref content) => {
                sequencer.init(content);
                chunks.push(Chunk {
                    number: 0,
                    status: ChunkStatus::AlreadyEncrypted,
                    location: ChunkLocation::Remote,
                })
            }
            DataMap::Chunks(ref data_map_chunks) => {
                for chunk in data_map_chunks.iter() {
                    chunks.push(Chunk {
                        number: chunk.chunk_num,
                        status: ChunkStatus::AlreadyEncrypted,
                        location: ChunkLocation::Remote,
                    });
                }
            }
            DataMap::None => {}
        }

        SelfEncryptor {
            storage: storage,
            datamap: datamap,
            chunks: chunks,
            sequencer: sequencer,
            file_size: file_size,
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
    pub fn write(&mut self, data: &[u8], position: u64) {
        if self.file_size < (data.len() as u64 + position) {
            let length = self.file_size;
            self.prepare_window(length, 0);
        }
        self.file_size = cmp::max(self.file_size, data.len() as u64 + position);
        if self.file_size as usize > MAX_IN_MEMORY_SIZE &&
           self.sequencer.len() <= MAX_IN_MEMORY_SIZE {
            match self.sequencer.create_mapping() {
                Ok(()) => (),
                Err(_) => return,
            }
        }
        self.prepare_window(data.len() as u64, position);
        for i in 0..data.len() {
            self.sequencer[position as usize + i] = data[i];
        }
    }

    /// The returned content is read from the specified position with specified length. Trying to
    /// read beyond the file size will cause the self_encryptor to be truncated up and return
    /// content filled with 0u8 in the gap.  Any other unwritten gaps will also be filled with
    /// '0u8's.
    pub fn read(&mut self, position: u64, length: u64) -> Vec<u8> {
        self.prepare_window(length, position);
        let mut read = Vec::with_capacity(length as usize);
        for &byte in self.sequencer.iter().skip(position as usize).take(length as usize) {
            read.push(byte);
        }
        read
        // &self.sequencer[position as usize..(position+length) as usize]
    }

    /// This function returns a DataMap, which is the info required to recover encrypted content
    /// from data storage location.  Content temporarily held in self_encryptor will only get
    /// flushed into storage when this function gets called.
    pub fn close(&mut self) -> DataMap {
        // Call prepare_window for the full file size to force any missing chunks to be inserted
        // into self.chunks.
        let file_size = self.file_size;
        self.prepare_window(file_size, 0);

        if self.file_size < (3 * MIN_CHUNK_SIZE) as u64 {
            let mut content = self.sequencer.to_vec();
            content.truncate(self.file_size as usize);
            DataMap::Content(content)
        } else {
            // assert(self.get_num_chunks() > 2 && "Try to close with less than 3 chunks");
            let real_chunk_count = self.get_num_chunks();
            let mut tmp_chunks = vec![datamap::ChunkDetails::new(); real_chunk_count as usize];

            let mut vec_deferred = Vec::new();
            for chunk in self.chunks.iter() {
                let missing_pre_encryption_hash = if self.datamap.has_chunks() {
                    self.datamap.get_sorted_chunks()[chunk.number as usize].pre_hash.len() == 0
                } else {
                    true
                };
                if chunk.number < real_chunk_count &&
                   (chunk.status == ChunkStatus::ToBeHashed || missing_pre_encryption_hash ||
                    real_chunk_count == 3) {
                    let this_size = self.get_chunk_size(chunk.number) as usize;
                    let pos = self.get_start_end_positions(chunk.number).0;

                    let mut tmp = vec![0u8; this_size];
                    for i in 0..this_size {
                        tmp[i] = self.sequencer[i + pos as usize];
                    }

                    let chunk_number = chunk.number;
                    vec_deferred.push(Deferred::<_, String>::new(move || {
                        let sha512::Digest(name) = sha512::hash(&tmp[..]);
                        Ok((chunk_number, name, this_size))
                    }));
                }
            }
            if let Ok(result) = Deferred::vec_to_promise(vec_deferred, ControlFlow::ParallelCPUS)
                                    .sync() {
                for (chunk_number, name, this_size) in result {
                    tmp_chunks[chunk_number as usize].pre_hash.clear();
                    tmp_chunks[chunk_number as usize].pre_hash = name.to_vec();
                    tmp_chunks[chunk_number as usize].source_size = this_size as u64;
                    tmp_chunks[chunk_number as usize].chunk_num = chunk_number;
                    // assert(4096 == tmp_chunks[chunk.number].pre_hash.len() && "Hash size wrong");
                }
            }
            self.datamap = DataMap::Chunks(tmp_chunks.to_vec());
            for chunk in self.chunks.iter_mut() {
                if chunk.number < real_chunk_count && chunk.status == ChunkStatus::ToBeHashed {
                    chunk.status = ChunkStatus::ToBeEncrypted;
                }
            }
            let mut vec_deferred = Vec::new();
            for chunk in self.chunks.iter() {
                if chunk.number < real_chunk_count && chunk.status == ChunkStatus::ToBeEncrypted {
                    let this_size = self.get_chunk_size(chunk.number) as usize;
                    let pos = self.get_start_end_positions(chunk.number).0;

                    let mut tmp = vec![0u8; this_size];
                    for i in 0..this_size {
                        tmp[i] = self.sequencer[i + pos as usize];
                    }

                    let storage = self.storage.clone();
                    let chunk_number = chunk.number;
                    let def = self.encrypt_chunk(chunk.number, tmp)
                                  .chain::<_, String, _>(move |res| {
                                      let content = res.unwrap();
                                      let sha512::Digest(name) = sha512::hash(&content);
                                      storage.put(name.to_vec(), content);
                                      Ok((chunk_number, name))
                                  });
                    vec_deferred.push(def);
                }
            }
            if let Ok(result) = Deferred::vec_to_promise(vec_deferred, ControlFlow::ParallelCPUS)
                                    .sync() {
                for (chunk_number, name) in result {
                    tmp_chunks[chunk_number as usize].hash = name.to_vec();
                }
            }

            for chunk in self.chunks.iter_mut() {
                if chunk.status == ChunkStatus::ToBeEncrypted {
                    chunk.status = ChunkStatus::AlreadyEncrypted;
                }
            }

            DataMap::Chunks(tmp_chunks)
        }
    }

    /// Truncate the self_encryptor to the specified size (if extend, filled with 0u8).
    pub fn truncate(&mut self, position: u64) -> bool {
        let old_size = self.file_size;
        self.file_size = position;  //  All helper methods calculate from file size
        if position < old_size {
            self.sequencer.truncate(position as usize);
            let last_chunk = self.get_chunk_number(position) + 1;
            self.chunks.truncate(last_chunk as usize);
        } else {
            if self.file_size > old_size {
                if self.file_size as usize > MAX_IN_MEMORY_SIZE &&
                   self.sequencer.len() <= MAX_IN_MEMORY_SIZE {
                    match self.sequencer.create_mapping() {
                        Ok(()) => (),
                        Err(_) => return false,
                    }
                }
            }
            // assert(position - old_size < std::numeric_limits<size_t>::max());
            self.prepare_window((position - old_size), old_size);
        }

        true
    }

    /// Current file size as is known by encryptor.
    pub fn len(&self) -> u64 {
        self.file_size
    }

    /// Prepare a sliding window to ensure there are enough chunk slots for writing, and to read in
    /// any absent chunks from external storage.
    fn prepare_window(&mut self, length: u64, position: u64) {
        if (length + position) as usize > self.sequencer.len() {
            let tmp_size = self.sequencer.len();
            self.sequencer.extend(repeat(0).take((length as usize + position as usize) - tmp_size));
        }
        if self.file_size < (3 * MIN_CHUNK_SIZE) as u64 {
            return;
        }
        let mut first_chunk = self.get_chunk_number(position);
        let mut last_chunk = self.get_chunk_number(position + length);
        if self.file_size < (3 * MAX_CHUNK_SIZE) as u64 {
            first_chunk = 0;
            last_chunk = 3;
        } else {
            for _ in 0..2 {
                if last_chunk < self.get_num_chunks() {
                    last_chunk += 1;
                }
            }
        }
        // [TODO]: Thread next - 2015-02-28 06:09pm
        let mut vec_deferred = Vec::new();
        for i in first_chunk..last_chunk {
            let mut found = false;
            for itr in self.chunks.iter() {
                if itr.number == i {
                    let pos = self.get_start_end_positions(i).0;
                    if itr.location == ChunkLocation::Remote {
                        vec_deferred.push(self.decrypt_chunk(i)
                                              .chain::<_, String, _>(move |res| {
                                                  Ok((pos, res.unwrap()))
                                              }));
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                self.chunks.push(Chunk {
                    number: i,
                    status: ChunkStatus::ToBeHashed,
                    location: ChunkLocation::InSequencer,
                });
            } else {
                match self.chunks.get_mut(i as usize) {
                    Some(found_chunk) => {
                        found_chunk.status = ChunkStatus::ToBeHashed;
                        found_chunk.location = ChunkLocation::InSequencer;
                    }
                    None => {}
                }
            }
        }
        for (pos, vec) in Deferred::vec_to_promise(vec_deferred, ControlFlow::ParallelCPUS)
                              .sync()
                              .unwrap() {
            let mut pos_aux = pos;
            for &byte in &vec {
                self.sequencer[pos_aux as usize] = byte;
                pos_aux += 1;
            }
        }
    }

    fn get_pad_key_and_iv(&self, chunk_number: u32) -> (Pad, Key, Iv) {
        let n_1 = self.get_previous_chunk_number(chunk_number);
        let n_2 = self.get_previous_chunk_number(n_1);
        let sorted_chunks = self.datamap.get_sorted_chunks();
        let vec = &sorted_chunks[chunk_number as usize].pre_hash;
        let n_1_vec = &sorted_chunks[n_1 as usize].pre_hash;
        let n_2_vec = &sorted_chunks[n_2 as usize].pre_hash;

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

    /// Performs the decryption algorithm to decrypt chunk of data.
    fn decrypt_chunk(&self, chunk_number: u32) -> Deferred<Vec<u8>, String> {
        let name = self.datamap.get_sorted_chunks()[chunk_number as usize].hash.clone();
        // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
        let (pad, key, iv) = self.get_pad_key_and_iv(chunk_number);
        let content = self.storage.get(name);

        Deferred::<Vec<u8>, String>::new(move || {
            if content.len() == 0 {
                ()
            }
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
                            return Err("Decompression failure".to_string());
                        }
                        Err(error) => Err(error.description().to_string()),
                    }
                }
                _ => Err(format!("Failed decrypting chunk {}", chunk_number)),
            }
        })
    }

    /// Performs encryption algorithm on chunk of data.
    fn encrypt_chunk(&self, chunk_number: u32, content: Vec<u8>) -> Deferred<Vec<u8>, String> {
        // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
        let (pad, key, iv) = self.get_pad_key_and_iv(chunk_number);
        Deferred::<Vec<u8>, String>::new(move || {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::Default);
            match encoder.write_all(&content[..]) {
                Ok(()) => {
                    match encoder.finish() {
                        Ok(compressed) => {
                            let encrypted = encrypt(&compressed, &key, &iv);
                            Ok(xor(&encrypted, &pad))
                        },
                        Err(error) => { Err(error.description().to_string()) }
                    }
                }
                Err(error) => Err(error.description().to_string()),
            }
        })
    }

    // Helper methods.

    /// Returns the number of chunks according to file size.
    fn get_num_chunks(&self) -> u32 {
        if self.file_size < (3 * MIN_CHUNK_SIZE as u64) {
            return 0;
        }
        if self.file_size < (3 * MAX_CHUNK_SIZE as u64) {
            return 3;
        }
        if self.file_size % MAX_CHUNK_SIZE as u64 == 0 {
            (self.file_size / MAX_CHUNK_SIZE as u64) as u32
        } else {
            ((self.file_size / MAX_CHUNK_SIZE as u64) + 1) as u32
        }
    }

    /// Returns the size of a chunk of data.
    fn get_chunk_size(&self, chunk_number: u32) -> u32 {
        if self.file_size < 3 * MIN_CHUNK_SIZE as u64 {
            return 0;
        }
        if self.file_size < 3 * MAX_CHUNK_SIZE as u64 {
            if chunk_number < 2 {
                return (self.file_size / 3) as u32;
            } else {
                return (self.file_size - (2 * (self.file_size / 3))) as u32;
            }
        }
        if chunk_number < self.get_num_chunks() - 2 {
            return MAX_CHUNK_SIZE;
        }
        let remainder = (self.file_size % MAX_CHUNK_SIZE as u64) as u32;
        let penultimate = (self.get_num_chunks() - 2) == chunk_number;
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

    /// Returns the start and end positions of chunk data in the file.
    fn get_start_end_positions(&self, chunk_number: u32) -> (u64, u64) {
        if self.get_num_chunks() == 0 {
            return (0, 0);
        }
        let start;
        let last = (self.get_num_chunks() - 1) == chunk_number;
        if last {
            start = self.get_chunk_size(0) as u64 * (chunk_number as u64 - 1) +
                    self.get_chunk_size(chunk_number - 1) as u64;
        } else {
            start = self.get_chunk_size(0) as u64 * chunk_number as u64;
        }
        (start, (start + self.get_chunk_size(chunk_number) as u64))
    }

    fn get_previous_chunk_number(&self, chunk_number: u32) -> u32 {
        if self.get_num_chunks() == 0 {
            return 0;
        }
        (self.get_num_chunks() + chunk_number - 1) % self.get_num_chunks()
    }

    fn get_chunk_number(&self, position: u64) -> u32 {
        if self.get_num_chunks() == 0 {
            return 0;
        }
        (position / self.get_chunk_size(0) as u64) as u32
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use std::sync::{Arc, Mutex};
    use datamap::DataMap;

    fn random_bytes(length: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(rand::random::<u8>());
        }
        bytes
    }

    pub struct Entry {
        name: Vec<u8>,
        data: Vec<u8>,
    }

    pub struct MyStorage {
        entries: Arc<Mutex<Vec<Entry>>>,
    }

    impl MyStorage {
        pub fn new() -> MyStorage {
            MyStorage { entries: Arc::new(Mutex::new(Vec::new())) }
        }

        pub fn has_chunk(&self, name: &[u8]) -> bool {
            let lock = self.entries.lock().unwrap();
            for entry in lock.iter() {
                if entry.name == name {
                    return true;
                }
            }
            false
        }

        pub fn num_entries(&self) -> usize {
            let lock = self.entries.lock().unwrap();
            lock.len()
        }
    }

    impl Storage for MyStorage {
        fn get(&self, name: Vec<u8>) -> Vec<u8> {
            let lock = self.entries.lock().unwrap();
            for entry in lock.iter() {
                if entry.name == name {
                    return entry.data.to_vec();
                }
            }

            vec![]
        }

        fn put(&self, name: Vec<u8>, data: Vec<u8>) {
            let mut lock = self.entries.lock().unwrap();
            lock.push(Entry {
                name: name,
                data: data,
            })
        }
    }

    fn check_file_size(se: &SelfEncryptor<MyStorage>, expected_file_size: u64) {
        assert_eq!(se.file_size, expected_file_size);
        if let DataMap::Chunks(ref chunk_details) = se.datamap {
            let chunks_cumulated_size = chunk_details.iter().fold(0u64, |acc, chunk| {
                acc + chunk.source_size
            });
            assert_eq!(chunks_cumulated_size, expected_file_size);
        }
    }

    #[test]
    fn test_xor() {
        let mut data: Vec<u8> = vec![];
        let mut pad = [0u8; super::PAD_SIZE];
        for _ in 0..800 {
            data.push(rand::random::<u8>());
        }
        for i in 0..super::PAD_SIZE {
            pad[i] = rand::random::<u8>();
        }
        assert_eq!(data,
                   super::xor(&super::xor(&data, &super::Pad(pad)), &super::Pad(pad)));
    }

    #[test]
    fn check_write() {
        let my_storage = Arc::new(MyStorage::new());
        let mut se = SelfEncryptor::new(my_storage, DataMap::None);
        let size = 3u64;
        let offset = 5u64;
        let the_bytes = random_bytes(size as usize);
        se.write(&the_bytes, offset);
        check_file_size(&se, size + offset);
    }

    #[test]
    fn check_multiple_writes() {
        let my_storage = Arc::new(MyStorage::new());
        let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
        let size1 = 3u64;
        let size2 = 4u64;
        let part1 = random_bytes(size1 as usize);
        let part2 = random_bytes(size2 as usize);
        // Just testing multiple subsequent write calls
        se.write(&part1, 0);
        se.write(&part2, size1);
        // Let's also test an overwrite.. over middle bytes of part2
        se.write(&[4u8, 2], size1+1);
        check_file_size(&se, size1 + size2);
        let data_map = se.close();
        let mut se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = se.read(0, size1 + size2);
        let size1 = size1 as usize;
        assert!(&fetched[..size1] == &part1[..]);
        assert_eq!(fetched[size1], part2[0]);
        assert!(&fetched[size1+1 .. size1+3] == &[4u8, 2][..]);
        assert!(&fetched[size1+3 ..] == &part2[3..]);
    }

    #[test]
    fn check_3_min_chunks_minus1() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE as u64 * 3) - 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), 0);
            assert_eq!(se.chunks.len(), 0);
            assert_eq!(se.sequencer.len(), bytes_len as usize);
            check_file_size(&se, bytes_len);
            match se.datamap {
                DataMap::Chunks(_) => panic!("shall not return DataMap::Chunks"),
                DataMap::Content(_) => panic!("shall not return DataMap::Content"),
                DataMap::None => {}
            }
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
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_3_min_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let the_bytes = random_bytes(MIN_CHUNK_SIZE as usize * 3);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            // check helper functions
            assert_eq!(se.get_num_chunks(), 3);
            assert_eq!(se.get_chunk_size(0), 1024);
            assert_eq!(se.get_chunk_size(1), 1024);
            assert_eq!(se.get_chunk_size(2), 1024);
            assert_eq!(se.get_previous_chunk_number(0), 2);
            assert_eq!(se.get_previous_chunk_number(1), 0);
            assert_eq!(se.get_previous_chunk_number(2), 1);
            assert_eq!(se.get_start_end_positions(0).0, 0u64);
            assert_eq!(se.get_start_end_positions(0).1, MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).0, MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).1, 2 * MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).0, 2 * MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).1, 3 * MIN_CHUNK_SIZE as u64);
            check_file_size(&se, MIN_CHUNK_SIZE as u64 * 3);
            // check close
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
    fn check_3_min_chunks_plus1() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let bytes_len = (MIN_CHUNK_SIZE as u64 * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), 3);
            assert_eq!(se.get_chunk_size(0), 1024);
            assert_eq!(se.get_chunk_size(1), 1024);
            assert_eq!(se.get_chunk_size(2), 1025);
            assert_eq!(se.get_previous_chunk_number(0), 2);
            assert_eq!(se.get_previous_chunk_number(1), 0);
            assert_eq!(se.get_previous_chunk_number(2), 1);
            assert_eq!(se.get_start_end_positions(0).0, 0u64);
            assert_eq!(se.get_start_end_positions(0).1, MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).0, MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).1, 2 * MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).0, 2 * MIN_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).1,
                       1 + 3 * MIN_CHUNK_SIZE as u64);
            check_file_size(&se, bytes_len);
            // check close
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
        let fetched = new_se.read(0, bytes_len);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn check_3_max_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE as u64 * 3;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), 3);
            assert_eq!(se.get_chunk_size(0), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(1), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(2), MAX_CHUNK_SIZE);
            assert_eq!(se.get_previous_chunk_number(0), 2);
            assert_eq!(se.get_previous_chunk_number(1), 0);
            assert_eq!(se.get_previous_chunk_number(2), 1);
            assert_eq!(se.get_start_end_positions(0).0, 0u64);
            assert_eq!(se.get_start_end_positions(0).1, MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).0, MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).1, 2 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).0, 2 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).1, 3 * MAX_CHUNK_SIZE as u64);
            check_file_size(&se, bytes_len);
            // check close
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
        let fetched = new_se.read(0, bytes_len);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn check_3_max_chunks_plus1() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let bytes_len = (MAX_CHUNK_SIZE as u64 * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), 4);
            assert_eq!(se.get_chunk_size(0), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(1), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(2), MAX_CHUNK_SIZE - MIN_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(3), MIN_CHUNK_SIZE + 1);
            assert_eq!(se.get_previous_chunk_number(0), 3);
            assert_eq!(se.get_previous_chunk_number(1), 0);
            assert_eq!(se.get_previous_chunk_number(2), 1);
            assert_eq!(se.get_previous_chunk_number(3), 2);
            assert_eq!(se.get_start_end_positions(0).0, 0u64);
            assert_eq!(se.get_start_end_positions(0).1, MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).0, MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).1, 2 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).0, 2 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).1,
                       ((3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE) as u64);
            assert_eq!(se.get_start_end_positions(3).0,
                       se.get_start_end_positions(2).1);
            assert_eq!(se.get_start_end_positions(3).1, bytes_len);
            check_file_size(&se, bytes_len);
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
        let fetched = new_se.read(0, bytes_len);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn check_7_and_a_bit_max_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let bytes_len = (MAX_CHUNK_SIZE as u64 * 7) + 1024;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), 8);
            assert_eq!(se.get_chunk_size(0), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(1), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(2), MAX_CHUNK_SIZE);
            assert_eq!(se.get_chunk_size(3), MAX_CHUNK_SIZE);
            assert_eq!(se.get_previous_chunk_number(0), 7);
            assert_eq!(se.get_previous_chunk_number(1), 0);
            assert_eq!(se.get_previous_chunk_number(2), 1);
            assert_eq!(se.get_previous_chunk_number(3), 2);
            assert_eq!(se.get_start_end_positions(0).0, 0u64);
            assert_eq!(se.get_start_end_positions(0).1, MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).0, MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(1).1, 2 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).0, 2 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(2).1, 3 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(3).0, 3 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(7).1,
                       ((7 * MAX_CHUNK_SIZE) as u64 + 1024));
            check_file_size(&se, bytes_len);
            // check close
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
        // check read and write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert!(fetched == the_bytes);
    }

    #[test]
    fn check_large_file_1_byte_under_11_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) - 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks);
            assert_eq!(se.get_previous_chunk_number(number_of_chunks),
                       number_of_chunks - 1);
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
    fn check_large_file_1_byte_over_11_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks + 1);
            assert_eq!(se.get_previous_chunk_number(number_of_chunks),
                       number_of_chunks - 1);
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
    fn check_large_file_size_1024_over_11_chunks() {
        // has been tested for 50 chunks
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1024;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks + 1);
            for i in 0..number_of_chunks {
                // preceding and next index, wrapped around
                let h = (i + number_of_chunks) % (number_of_chunks + 1);
                let j = (i + 1) % (number_of_chunks + 1);
                assert_eq!(se.get_chunk_size(i), MAX_CHUNK_SIZE);
                assert_eq!(se.get_previous_chunk_number(i), h);
                assert_eq!(se.get_start_end_positions(i).0,
                           i as u64 * MAX_CHUNK_SIZE as u64);
                assert_eq!(se.get_start_end_positions(i).1,
                           j as u64 * MAX_CHUNK_SIZE as u64);
            }
            assert_eq!(se.get_chunk_size(number_of_chunks), MIN_CHUNK_SIZE);
            assert_eq!(se.get_previous_chunk_number(number_of_chunks),
                       number_of_chunks - 1);
            assert_eq!(se.get_start_end_positions(number_of_chunks).0,
                       number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(number_of_chunks).1,
                       ((number_of_chunks * MAX_CHUNK_SIZE) as u64 + 1024));
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
    fn check_5_and_extend_to_7_plus_one() {
        let my_storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let bytes_len = MAX_CHUNK_SIZE as u64 * 5;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            check_file_size(&se, bytes_len);
            se.truncate((7 * MAX_CHUNK_SIZE + 1) as u64);
            assert_eq!(se.get_num_chunks(), 8);
            check_file_size(&se, (7 * MAX_CHUNK_SIZE + 1) as u64);
            // check close
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
    fn check_large_100mb_file() {
        let storage = Arc::new(MyStorage::new());
        let data_map: DataMap;
        let number_of_chunks: u32 = 100;
        let bytes_len = MAX_CHUNK_SIZE as usize * number_of_chunks as usize;
        let bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
            se.write(&bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks);
            for i in 0..number_of_chunks - 1 {
                // preceding and next index, wrapped around
                let h = (i + number_of_chunks - 1) % number_of_chunks;
                let j = (i + 1) % number_of_chunks;
                assert_eq!(se.get_chunk_size(i), MAX_CHUNK_SIZE);
                assert_eq!(se.get_previous_chunk_number(i), h);
                assert_eq!(se.get_start_end_positions(i).0,
                           i as u64 * MAX_CHUNK_SIZE as u64);
                assert_eq!(se.get_start_end_positions(i).1,
                           j as u64 * MAX_CHUNK_SIZE as u64);
            }
            assert_eq!(se.get_previous_chunk_number(number_of_chunks),
                       number_of_chunks - 1);
            assert_eq!(se.get_start_end_positions(number_of_chunks).0,
                       number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(number_of_chunks - 1).1,
                       ((number_of_chunks * MAX_CHUNK_SIZE) as u64));
            check_file_size(&se, bytes_len as u64);
            // check close
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
        // check read and write
        let mut new_se = SelfEncryptor::new(storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert!(fetched == bytes);
    }

    #[test]
    fn check_write_starting_with_existing_datamap() {
        let my_storage = Arc::new(MyStorage::new());
        let part1_len = MIN_CHUNK_SIZE as u64 * 3;
        let part1_bytes = random_bytes(part1_len as usize);
        let data_map: DataMap;
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&part1_bytes, 0);
            check_file_size(&se, part1_len);
            data_map = se.close();
        }
        let part2_len = 1024;
        let part2_bytes = random_bytes(part2_len as usize);
        let full_len = part1_len + part2_len;
        let data_map2: DataMap;
        {
            // Start with an existing datamap.
            let mut se = SelfEncryptor::new(my_storage.clone(), data_map);
            se.write(&part2_bytes, part1_len);
            //check_file_size(&se, full_len);
            data_map2 = se.close();
        }
        assert_eq!(data_map2.len(), full_len);

        let mut se = SelfEncryptor::new(my_storage.clone(), data_map2);
        let fetched = se.read(0, full_len);
        assert!(&part1_bytes[..] == &fetched[.. part1_len as usize]);
        assert!(&part2_bytes[..] == &fetched[part1_len as usize ..]);
    }

    // Definitions for testing serialisation of a vector
    extern crate cbor;
    use self::cbor::{Decoder, Encoder, CborError};

    pub fn serialise<T>(data: &T) -> Result<Vec<u8>, CborError>
        where T: ::rustc_serialize::Encodable
    {
        let mut encoder = Encoder::from_memory();
        try!(encoder.encode(&[data]));
        Ok(encoder.into_bytes())
    }

    pub fn deserialise<T>(data: &[u8]) -> Result<T, CborError>
        where T: ::rustc_serialize::Decodable
    {
        let mut decoder = Decoder::from_bytes(data);
        decoder.decode().next().unwrap()
    }

    fn create_vector_data_map(storage: Arc<MyStorage>, vec_len: usize) -> DataMap {
        let data: Vec<usize> = (0..vec_len).collect();
        let serialised_data: Vec<u8> = serialise(&data)
                                           .ok()
                                           .expect("failed to serialise Vec<usize>");
        let mut self_encryptor = SelfEncryptor::new(storage, DataMap::None);
        self_encryptor.write(&serialised_data, 0);
        check_file_size(&self_encryptor, serialised_data.len() as u64);
        self_encryptor.close()
    }

    fn check_vector_data_map(storage: Arc<MyStorage>, vec_len: usize, datamap: &DataMap) {
        let mut self_encryptor = SelfEncryptor::new(storage, datamap.clone());
        let length = self_encryptor.len();
        let data_to_deserialise: Vec<u8> = self_encryptor.read(0, length);
        let data: Vec<usize> = deserialise(&data_to_deserialise)
                                   .ok()
                                   .expect("failed to deserialise Vec<usize>");
        assert_eq!(data.len(), vec_len);
        for i in 0..vec_len {
            assert_eq!(data[i], i);
        }
    }

    #[test]
    fn check_serialised_vectors() {
        for vec_len in vec![1000, 2000, 5000, 10_000, 20_000, 50_000, 100_000, 20_0000, 50_0000,
                            1_000_000] {
            let storage = Arc::new(MyStorage::new());
            let datamap: DataMap = create_vector_data_map(storage.clone(), vec_len);
            check_vector_data_map(storage.clone(), vec_len, &datamap);
        }
    }
}
