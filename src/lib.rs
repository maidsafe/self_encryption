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
//!     fn has_chunk(&self, name: Vec<u8>) -> bool {
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
//! Then call write (and read after write)…etc… on the encryptor. The `close()` method will return
//! a `DataMap`. This can be passed to create a new encryptor to access the content `let data_map =
//! se.close();`
//! 
//! This is then used to open the data content in future sessions; e.g. `let mut self_encryptor =
//! SelfEncryptor::new(my_storage, data_map);` where the `data_map` is the object returned
//! from the `close()` call of previous use of this file content via the self_encryptor. Storage of
//! the `DataMap` is out with the scope of this library and must be implemented by the user.

#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://rust-ci.org/dirvine/self_encryption/")]

extern crate rand;
extern crate crypto;
extern crate rustc_serialize;
extern crate asynchronous;
use std::sync::Arc;
use std::cmp;
use crypto::sha2::Sha512 as Sha512;
use crypto::digest::Digest;
use std::iter::repeat;
use asynchronous::Deferred;
use asynchronous::ControlFlow;

// This is pub to test the tests directory integration tests; these are temporary and need to be
// replaced with actual integration tests. This should be private
pub mod encryption;
/// Information required to recover file content from chunks.
pub mod datamap;

/// MAX_CHUNK_SIZE defined as 1MB.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// MIN_CHUNK_SIZE defined as 1KB.
pub const MIN_CHUNK_SIZE: u32 = 1024;

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub fn xor(data: &[u8], pad: &[u8]) -> Vec<u8> {
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
struct Chunks {
    number: u32 ,
    status: ChunkStatus,
    location: ChunkLocation,
}

/// Storage traits of SelfEncryptor.
/// Data stored in Storage is encrypted, name is the SHA512 hash of content.
/// Storage can be in-memory HashMap or disk based
pub trait Storage {
    /// Fetch the data bearing the name
    fn get(&self, name: Vec<u8>) -> Vec<u8>;

    /// Insert the data bearing the name.
    fn put(&self, name: Vec<u8>, data: Vec<u8>);
}

/// This is the encryption object and all file handling should be done using this object as the low level
/// mechanism to read and write *content*. This library has no knowledge of file metadata. This is
/// a library to ensure content is secured.
pub struct SelfEncryptor<S:Storage> {
    storage: Arc<S>,
    my_datamap: datamap::DataMap,
    chunks: Vec<Chunks>,
    sequencer: Vec<u8>,
    file_size: u64,
}

impl<S:Storage + Send + Sync + 'static> SelfEncryptor<S> {
    /// This is the only constructor for an encryptor object.
    /// Each SelfEncryptor is used for a single file.
    /// The parameters are a DataMap and Storage.
    /// If new file, use DataMap::None as first parameter.
    /// The get and put of Storage need to be implemented to
    /// allow the SelfEncryptor to store encrypted chunks and retrieve them when necessary.
    pub fn new(my_storage:Arc<S>, my_datamap: datamap::DataMap) -> SelfEncryptor<S> {
        let mut sequencer = Vec::with_capacity(1024 * 1024 * 100);
        let file_size = my_datamap.len();

        let mut chunks = vec![];
        match my_datamap {
            datamap::DataMap::Content(ref content) => {
                sequencer.extend(content.iter().map(|&x| x));
                chunks.push(Chunks{number: 0, status: ChunkStatus::AlreadyEncrypted,
                                   location: ChunkLocation::Remote})
            },
            datamap::DataMap::Chunks(ref data_map_chunks) => {
                for chunk in data_map_chunks.iter() {
                    chunks.push(Chunks{number: chunk.chunk_num,
                                       status: ChunkStatus::AlreadyEncrypted,
                                       location: ChunkLocation::Remote});
                }
            },
            datamap::DataMap::None => {},
        }

        SelfEncryptor {
            storage: my_storage,
            my_datamap: my_datamap,
            chunks: chunks,
            sequencer: sequencer,
            file_size: file_size,
        }
    }

    /// This is an implementation of the get_storage function from example.
    pub fn get_storage(&self) -> Arc<S> { 
        self.storage.clone()
    }

    /// Write method mirrors a posix type write mechanism.
    /// It loosely mimics a filesystem interface for easy connection to FUSE like
    /// programs as well as fine grained access to system level libraries for developers.
    /// The input data will be written from the specified position (starts from 0).
    pub fn write(&mut self, data: &[u8], position: u64) {
        self.file_size = cmp::max(self.file_size , data.len() as u64 + position);
        self.prepare_window(data.len() as u64, position, true);
        for i in 0..data.len() {
            self.sequencer[position as usize + i] = data[i];
        }
    }

    /// The returned content is read from the specified position with specified length.
    /// Trying to read beyond the file size will cause the self_encryptor to be truncated up
    /// and return content filled with 0u8 in the gap.  Any other unwritten gaps will also be filled
    /// with '0u8's.
    pub fn read(&mut self, position: u64, length: u64) -> Vec<u8> {
        self.prepare_window(length, position, false);
        let mut read_vec = Vec::with_capacity(length as usize);
        for i in self.sequencer.iter().skip(position as usize).take(length as usize) {
            read_vec.push(i.clone());
        }
        read_vec
        //&self.sequencer[position as usize..(position+length) as usize]
    }

    /// This function returns a DataMap, which is the info required to recover encrypted content
    /// from data storage location.  Content temporarily held in self_encryptor will only get flushed into storage
    /// when this function gets called.
    pub fn close(mut self) -> datamap::DataMap {
        if self.file_size < (3 * MIN_CHUNK_SIZE) as u64 {
            let mut content = self.sequencer.to_vec();
            content.truncate(self.file_size as usize);
            datamap::DataMap::Content(content)
        } else {
            // assert(self.get_num_chunks() > 2 && "Try to close with less than 3 chunks");
            let real_chunk_count = self.get_num_chunks();
            let mut tmp_chunks = vec![datamap::ChunkDetails::new(); real_chunk_count as usize];

            let mut vec_deferred = Vec::new();
            for chunk in self.chunks.iter() {
                let missing_pre_encryption_hash = if self.my_datamap.has_chunks() {
                    self.my_datamap.get_sorted_chunks()[chunk.number as usize].pre_hash.len() == 0
                } else {
                    true
                };
                if chunk.number < real_chunk_count && (chunk.status == ChunkStatus::ToBeHashed ||
                        missing_pre_encryption_hash || real_chunk_count == 3) {
                    let this_size = self.get_chunk_size(chunk.number) as usize;
                    let pos = self.get_start_end_positions(chunk.number).0;

                    let mut tmp = vec![0; this_size];
                    for i in 0..this_size {
                        tmp[i] = self.sequencer[i + pos as usize].clone();
                    }
                    // assert(tmp.len() == this_size && "vector diff size from chunk size");

                    let chunk_number = chunk.number.clone(); 
                    vec_deferred.push(Deferred::<_,String>::new(move || {
                        let mut name = vec![0; 64];
                        let mut hash = Sha512::new();
                        hash.input(&mut tmp[..]);
                        hash.result(&mut name[..]);
                        Ok((chunk_number, name, this_size))
                    }));
                }
            }
            for (chunk_number, name, this_size) in Deferred::vec_to_promise(vec_deferred, ControlFlow::ParallelCPUS).sync().unwrap() {
                tmp_chunks[chunk_number as usize].pre_hash.clear();
                tmp_chunks[chunk_number as usize].pre_hash = name.to_vec();
                tmp_chunks[chunk_number as usize].source_size = this_size as u64;
                tmp_chunks[chunk_number as usize].chunk_num = chunk_number;
                // assert(4096 == tmp_chunks[chunk.number].pre_hash.len() && "Hash size wrong");
            }
            self.my_datamap = datamap::DataMap::Chunks(tmp_chunks.to_vec());
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

                    let mut tmp = vec![0; this_size];
                    for i in 0..this_size {
                        tmp[i] = self.sequencer[i + pos as usize].clone();
                    }

                    let storage = self.storage.clone();
                    let chunk_number = chunk.number.clone();                    
                    let def = self.encrypt_chunk(chunk.number, tmp).chain::<_,String,_>(move |res| {
                        let content = res.unwrap();
                        let mut name = vec![0; 64];
                        let mut hash = Sha512::new();
                        hash.input(&content);
                        hash.result(&mut name[..]);                                        
                        storage.put(name.to_vec(), content);                    
                        Ok((chunk_number, name))
                    });    
                    vec_deferred.push(def);
                }
            }
            for (chunk_number, name) in Deferred::vec_to_promise(vec_deferred, ControlFlow::ParallelCPUS).sync().unwrap() {
                tmp_chunks[chunk_number as usize].hash = name;
            }
            
            for chunk in self.chunks.iter_mut() {
                if chunk.status == ChunkStatus::ToBeEncrypted {
                    chunk.status = ChunkStatus::AlreadyEncrypted;
                }
            }

        datamap::DataMap::Chunks(tmp_chunks)
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
            // assert(position - old_size < std::numeric_limits<size_t>::max());
            self.prepare_window((position - old_size), old_size, true);
        }

        true
    }

    /// Current file size as is known by encryptor.
    pub fn len(&self) -> u64 {
        self.file_size
    }

    /// Prepare a sliding window to ensure there are enough chunk slots for write;
    /// the algorithm may read-in some chunks from external storage.
    fn prepare_window(&mut self, length: u64, position: u64, write: bool) {
        if (length + position) as usize > self.sequencer.len() {
          let tmp_size = self.sequencer.len();
          self.sequencer.extend(repeat(0).take((length as usize + position as usize) - tmp_size));
        }
        if self.file_size < (3 * MIN_CHUNK_SIZE) as u64 { return }
        let mut first_chunk = self.get_chunk_number(position);
        let mut last_chunk = self.get_chunk_number(position + length);
        if self.file_size < (3 * MAX_CHUNK_SIZE) as u64 {
            first_chunk = 0;
            last_chunk = 3;
        } else {
            for _ in 0..2 {
                if last_chunk < self.get_num_chunks() { last_chunk += 1; }
            }
        }
        // [TODO]: Thread next - 2015-02-28 06:09pm
        let mut vec_deferred = Vec::new();
        for i in (first_chunk..last_chunk) {
            let mut found = false;            
            for itr in self.chunks.iter() {
                if itr.number == i {
                    let pos = self.get_start_end_positions(i).0;
                    if itr.location == ChunkLocation::Remote  {
                        vec_deferred.push(self.decrypt_chunk(i)
                            .chain::<_,String,_>(move |res|{ 
                                Ok((pos, res.unwrap()) )
                            })
                        );
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                if write {
                    self.chunks.push(Chunks{number: i, status: ChunkStatus::ToBeHashed,
                                           location: ChunkLocation::InSequencer});
                } else {
                    self.chunks.push(Chunks{number: i, status: ChunkStatus::AlreadyEncrypted,
                                           location: ChunkLocation::InSequencer});
                }
            }
        }        
        for (pos, vec) in Deferred::vec_to_promise(vec_deferred, ControlFlow::ParallelCPUS).sync().unwrap() {
            let mut pos_aux = pos;
            for itr2 in vec.iter() {
                self.sequencer[pos_aux as usize] = *itr2;
                pos_aux += 1;
            }
        }        
    }

   // [TODO]: use fixed width arrays here, derived
   // from key size of cipher used (compile time) - 2015-03-02 01:01am
    fn get_pad_iv_key(&self, chunk_number: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut vec = self.my_datamap.get_sorted_chunks()[chunk_number as usize].pre_hash.clone();
        let n_1 = self.get_previous_chunk_number(chunk_number);
        let n_1_vec = self.my_datamap.get_sorted_chunks()[n_1 as usize].pre_hash.clone();
        let n_2 = self.get_previous_chunk_number(n_1);
        let n_2_vec = self.my_datamap.get_sorted_chunks()[n_2 as usize].pre_hash.clone();

        vec.extend(n_1_vec[48..64].to_vec());
        vec.extend(n_2_vec[..].to_vec());

        (vec, n_1_vec[0..32].to_vec(), n_1_vec[32..48].to_vec())
    }

    /// Performs the decryption algorithm to decrypt chunk of data.
    fn decrypt_chunk(&self, chunk_number: u32) -> Deferred<Vec<u8>,String> {
        let name = self.my_datamap.get_sorted_chunks()[chunk_number as usize].hash.clone();
        // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
        let kvp = self.get_pad_iv_key(chunk_number);
        let content = self.storage.get(name);
        Deferred::<Vec<u8>, String>::new(move ||{
            let xor_result = xor(&content, &kvp.0);
            Ok(encryption::decrypt(&xor_result, &kvp.1[..], &kvp.2[..]).unwrap())
        })
    }

    /// Performs encryption algorithm on chunk of data.
    fn encrypt_chunk(&self, chunk_number: u32, content: Vec<u8>) -> Deferred<Vec<u8>,String> {
        // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
        let kvp = self.get_pad_iv_key(chunk_number);
        Deferred::<Vec<u8>, String>::new(move ||{
            let enc = &encryption::encrypt(&content, &kvp.1[..], &kvp.2[..]).unwrap();
            Ok(xor(&enc, &kvp.0))
        })
        // let result = xor(&enc, &kvp.0);
        // let mut name : Vec<u8> = Vec::new();
        // name.reserve(4096);
        // let mut hash = Sha512::new();
        // hash.input(result.as_slice());
        // hash.result(name.as_mut_slice());
        // self.storage.put(name, result.to_vec());
        // result
    }

    // Helper methods.
    /// Returns the number label of a chunk.
    fn get_num_chunks(&self) -> u32 {
        if self.file_size < (3 * MIN_CHUNK_SIZE as u64) { return 0 }
        if self.file_size < (3 * MAX_CHUNK_SIZE as u64) { return 3 }
        if self.file_size % MAX_CHUNK_SIZE as u64 == 0 {
            (self.file_size / MAX_CHUNK_SIZE as u64) as u32
        } else {
            ((self.file_size / MAX_CHUNK_SIZE as u64) + 1) as u32
        }
    }

    /// Returns the size of a chunk of data.
    fn get_chunk_size(&self, chunk_number: u32) -> u32 {
        if self.file_size < 3 * MIN_CHUNK_SIZE as u64 { return 0 }
        if self.file_size < 3 * MAX_CHUNK_SIZE as u64 {
            if chunk_number < 2 {
                return (self.file_size / 3) as u32
            } else {
                return (self.file_size - (2 * self.file_size / 3)) as u32
            }
        }
        if chunk_number < self.get_num_chunks() - 2 { return MAX_CHUNK_SIZE }
        let remainder = (self.file_size % MAX_CHUNK_SIZE as u64) as u32;
        let penultimate = (SelfEncryptor::get_num_chunks(self) - 2) == chunk_number;
        if remainder == 0 { return MAX_CHUNK_SIZE }
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


    /// Returns ordering of chunks.
    fn get_start_end_positions(&self, chunk_number: u32) -> (u64, u64) {
        if self.get_num_chunks() == 0 { return (0, 0) }
        let mut start;
        let penultimate = (self.get_num_chunks() - 2) == chunk_number;
        let last = (self.get_num_chunks() - 1) == chunk_number;
        if last {
            start = (self.get_chunk_size(0) * (chunk_number - 2) +
                self.get_chunk_size(chunk_number - 2) +
                self.get_chunk_size(chunk_number - 1)) as u64;
        } else if penultimate {
            start = (self.get_chunk_size(0) * (chunk_number - 1) +
                self.get_chunk_size(chunk_number - 1)) as u64;
        } else {
            start = (self.get_chunk_size(0) * chunk_number) as u64;
        }
        (start, (start + self.get_chunk_size(chunk_number) as u64))
    }

    fn get_previous_chunk_number(&self, chunk_number: u32) -> u32 {
        if self.get_num_chunks() == 0 { return 0 }
        (self.get_num_chunks() + chunk_number - 1) % self.get_num_chunks()
    }

    fn get_chunk_number(&self, position: u64) -> u32 {
        if self.get_num_chunks() == 0 { return 0 }
        (position / self.get_chunk_size(0) as u64) as u32
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::{Arc,Mutex};

    fn random_bytes(length: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(length);
        for _ in (0..length) {
            bytes.push(super::rand::random::<u8>());
        }
        bytes
    }

    pub struct Entry {
        name: Vec<u8>,
        data: Vec<u8>
    }

    pub struct MyStorage {
        entries: Arc<Mutex<Vec<Entry>>>
    }

    impl MyStorage {
        pub fn new() -> MyStorage {
            MyStorage { entries: Arc::new(Mutex::new(Vec::new())) }
        }

        pub fn has_chunk(&self, name: Vec<u8>) -> bool {
            let lock = self.entries.lock().unwrap();
            for entry in lock.iter() {
                if entry.name == name { return true }
            }
            false
        }

        pub fn num_entries(&self) -> usize{
            let lock = self.entries.lock().unwrap();
            lock.len()
        }
    }

    impl Storage for MyStorage {
        fn get(&self, name: Vec<u8>) -> Vec<u8> {
            let lock = self.entries.lock().unwrap();
            for entry in lock.iter() {
                if entry.name == name { return entry.data.to_vec() }
            }

            vec![]
        }

        fn put(&self, name: Vec<u8>, data: Vec<u8>) {
            let mut lock = self.entries.lock().unwrap();
            lock.push(Entry { name : name, data : data })
        }
    }

    #[test]
    fn test_xor() {
        let mut data: Vec<u8> = vec![];
        let mut pad: Vec<u8> = vec![];
        for _ in (0..800) {
            data.push(super::rand::random::<u8>());
        }
        for _ in (0..333) {
            pad.push(super::rand::random::<u8>());
        }
        assert_eq!(data, xor(&xor(&data,&pad), &pad));
    }

    #[test]
    fn check_write() {
        let my_storage = Arc::new(MyStorage::new());
        let mut se = SelfEncryptor::new(my_storage, datamap::DataMap::None);
        let size = 3u64;
        let offset = 5u64;
        let the_bytes = random_bytes(size as usize);
        se.write(&the_bytes, offset);
        assert_eq!(se.file_size, size + offset);
    }

    #[test]
    fn check_3_min_chunks_minus1() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let bytes_len = (MIN_CHUNK_SIZE as u64 * 3) - 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);            
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), 0);
            assert_eq!(se.chunks.len(), 0);
            assert_eq!(se.sequencer.len(), bytes_len as usize);
            match se.my_datamap {
                datamap::DataMap::Chunks(_) => panic!("shall not return DataMap::Chunks"),
                datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
                datamap::DataMap::None => {}
            }
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(_) => panic!("shall not return DataMap::Chunks"),
            datamap::DataMap::Content(ref content) => assert_eq!(content.len(), bytes_len as usize),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_3_min_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let the_bytes = random_bytes(MIN_CHUNK_SIZE as usize * 3);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
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
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(my_storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, MIN_CHUNK_SIZE as u64 * 3);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_3_min_chunks_plus1() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let bytes_len = (MIN_CHUNK_SIZE as u64 * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
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
            assert_eq!(se.get_start_end_positions(2).1, 1 + 3 * MIN_CHUNK_SIZE as u64);
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(my_storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_3_max_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let bytes_len = MAX_CHUNK_SIZE as u64 * 3;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
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
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 3);
                assert_eq!(my_storage.clone().num_entries(), 3);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read, write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_3_max_chunks_plus1() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let bytes_len = (MAX_CHUNK_SIZE as u64 * 3) + 1;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
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
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 4);
                assert_eq!(my_storage.clone().num_entries(), 4);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_7_and_a_bit_max_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let bytes_len = (MAX_CHUNK_SIZE as u64 * 7) + 1024;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
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
            assert_eq!(se.get_start_end_positions(7).1, ((7 * MAX_CHUNK_SIZE) as u64 + 1024));
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), 8);
                assert_eq!(my_storage.clone().num_entries(), 8);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    }
    
    #[test]
    fn check_large_file_1_byte_under_11_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let number_of_chunks : u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) - 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks);
            assert_eq!(se.get_previous_chunk_number(number_of_chunks), number_of_chunks - 1);
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize);
                assert_eq!(my_storage.clone().num_entries(), number_of_chunks as usize);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_large_file_1_byte_over_11_chunks() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let number_of_chunks : u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks + 1);
            assert_eq!(se.get_previous_chunk_number(number_of_chunks), number_of_chunks - 1);
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize + 1);
                assert_eq!(my_storage.clone().num_entries(), number_of_chunks as usize + 1);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_large_file_size_1024_over_11_chunks() {
        // has been tested for 50 chunks
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let number_of_chunks : u32 = 11;
        let bytes_len = (MAX_CHUNK_SIZE as usize * number_of_chunks as usize) + 1024;
        let the_bytes = random_bytes(bytes_len);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
            se.write(&the_bytes, 0);
            assert_eq!(se.get_num_chunks(), number_of_chunks + 1);
            for i in 0..number_of_chunks {
                // preceding and next index, wrapped around
                let h = (i + number_of_chunks)%(number_of_chunks + 1);
                let j = (i + 1)%(number_of_chunks + 1);
                assert_eq!(se.get_chunk_size(i), MAX_CHUNK_SIZE);
                assert_eq!(se.get_previous_chunk_number(i), h);
                assert_eq!(se.get_start_end_positions(i).0, i as u64 * MAX_CHUNK_SIZE as u64);
                assert_eq!(se.get_start_end_positions(i).1, j as u64 * MAX_CHUNK_SIZE as u64);
            }
            assert_eq!(se.get_chunk_size(number_of_chunks), MIN_CHUNK_SIZE);
            assert_eq!(se.get_previous_chunk_number(number_of_chunks), number_of_chunks - 1);
            assert_eq!(se.get_start_end_positions(number_of_chunks).0,
            number_of_chunks as u64 * MAX_CHUNK_SIZE as u64);
            assert_eq!(se.get_start_end_positions(number_of_chunks).1,
            ((number_of_chunks * MAX_CHUNK_SIZE) as u64 + 1024));
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
                assert_eq!(chunks.len(), number_of_chunks as usize + 1);
                assert_eq!(my_storage.clone().num_entries(), number_of_chunks as usize + 1);
                for chunk_detail in chunks.iter() {
                    assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
                }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
        // check read and write
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len as u64);
        assert_eq!(fetched, the_bytes);
    }

    #[test]
    fn check_5_and_extend_to_7_plus_one() {
        let my_storage = Arc::new(MyStorage::new());
        let mut data_map: datamap::DataMap;
        let bytes_len = MAX_CHUNK_SIZE as u64 * 5;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
            se.write(&the_bytes, 0);
            se.truncate((7*MAX_CHUNK_SIZE + 1) as u64);
            assert_eq!(se.get_num_chunks(), 8);
            // check close
            data_map = se.close();
        }
        match data_map {
            datamap::DataMap::Chunks(ref chunks) => {
              assert_eq!(chunks.len(), 8);
              assert_eq!(my_storage.clone().num_entries(), 8);
              for chunk_detail in chunks.iter() {
                  assert_eq!(my_storage.clone().has_chunk(chunk_detail.hash.to_vec()), true);
              }
            }
            datamap::DataMap::Content(_) => panic!("shall not return DataMap::Content"),
            datamap::DataMap::None => panic!("shall not return DataMap::None"),
        }
    }
}