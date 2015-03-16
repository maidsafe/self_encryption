/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */

//! A file **content** self encryptor
//!
//! This library will provide convergent encryption on file based data and produce a
//! ```DataMap``` type and several chunks of data. Each chunk is max 1Mb in size
//! and has a name. This name is the ``Sah512``` of the content. This allows the chunks
//! to be confirmed and if using size and Hash checks then there is a high degree of certainty
//! in the data validity.
//!
//! # Use
//! To use this lib you must implement two trait functions (another later), these are to allow
//! get_chunk and put_chunk from storage.
//!
//!

#![allow(dead_code, unused_variables)]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://rust-ci.org/dirvine/self_encryption/")]
//#![warn(missing_docs)]
#![feature(collections, rustc_private)]

extern crate rand;
extern crate crypto;
extern crate rustc_back;

use std::cmp;
use rustc_back::tempdir::TempDir;
use crypto::sha2::Sha512 as Sha512;
use crypto::digest::Digest;
// this is pub to test the tests dir integration tests these are temp and need to be
// replaced with actual integration tests and this should be private
mod encryption;
/// Holds pre and post encryption hashes as well as original chunk size
pub mod datamap;

pub static MAX_CHUNK_SIZE: u32 = 1024*1024;
pub static MIN_CHUNK_SIZE: u32 = 1024;
pub fn xor(data: &Vec<u8>, pad: &Vec<u8>)->Vec<u8> {
  data.iter().zip(pad.iter().cycle()).map(|(&a, &b)| a ^ b).collect()
}
/// Will use a tempdir to stream un procesed data, although this is done vie AES streaming with
/// a randome key and IV
pub fn create_temp_dir() ->TempDir {
  match rustc_back::tempdir::TempDir::new("self_encryptor") {
    Ok(dir) => dir,
    Err(e) => panic!("couldn't create temporary directory: {}", e)
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ChunkStatus {
  ToBeHashed,
  ToBeEncrypted,
  AlreadyEncrypted
  }

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ChunkLocation {
    InSequencer,
    OnDisk,  // therefor only being used as read cache`
    Remote

}
pub struct Chunk { pub name:  Vec<u8>, pub content: Vec<u8> }

#[derive(PartialEq, Eq, PartialOrd, Ord)]

struct Chunks { number: u32 , status: ChunkStatus, location: ChunkLocation }
pub trait Storage {
      fn get(&self, name: Vec<u8>) -> Vec<u8>;
      fn put(&self, name: Vec<u8>, data: Vec<u8>);
}


/// This is the encryption object and all file handling should be done via this as the low level
/// mechanism to read and write *content* this library has no knowledge of file metadata. This is
/// a library to ensure content is secured

pub struct SelfEncryptor<'a> {
  storage: &'a mut (Storage + 'a),
  my_datamap: datamap::DataMap,
  chunks: Vec<Chunks>,
  sequencer: Vec<u8>,
  tempdir : TempDir,
  file_size: u64,
  closed: bool,
  }




impl<'a> SelfEncryptor<'a> {
  //! constructor for encryptor object
  //! Each SelfEncryptor is used for a single file.
  //! The parameters are a DataMap a Get and Put functor.
  //! the get and put functors should be passed to this library to
  //! allow the SelfEncryptor to store encrypted chunks and retrieve these
  //! when necessary.
  /// This is the only constructor, if new file use DataMap::None as first param
  pub fn new(my_storage:&'a mut Storage, my_datamap: datamap::DataMap)-> SelfEncryptor {
    SelfEncryptor{storage: my_storage, my_datamap: my_datamap, chunks: Vec::new(),
                 sequencer: Vec::with_capacity(1024 * 1024 * 100 as usize),
                 tempdir: create_temp_dir(), file_size: 0, closed: false}
    }

  /// This is an implementation of the get_storage function from example
  pub fn get_storage(&'a mut self) -> &'a mut Storage {self.storage}



  /// Write method mirrors a posix type write mechanism
  /// loosly mimics filsystem interface for easy connection to FUSE like
  /// programs as well as fine grained access to system level libraries for developers.
  pub fn write(&mut self, data: &str, position: u64) {
    if self.closed { panic!("Encryptor closed, you must start a new Encryptor::new()") }
    let new_size = cmp::max(self.file_size , data.len() as u64 + position);
    self.prepare_window(data.len() as u64, position, true);
    for i in 0..data.len()   {
        self.sequencer[position as usize + i] = data.as_bytes()[i];
      }

    self.file_size = new_size;
  }
  
  /// return string, this is a change fomr existing API wehre we used c type const char *
  pub fn read(&mut self, position: u64, length: u64)-> String {
    if self.closed { panic!("Encryptor closed, you must start a new Encryptor::new()") }
    self.prepare_window(length, position, false);
    let mut data = String::with_capacity(length as usize);
      for i in (0..length) {
            data.push(self.sequencer[(position + i) as usize] as char);
      }
      data
      // TODO(dirvine)  this can be reduced to a single line (map range)  :01/03/2015
  }

  /// return datamap
  pub fn close(&mut self)-> datamap::DataMap {
    // multiple call to close is allowed but will return
    if self.closed {
      datamap::DataMap::None
    } else {
      if self.file_size < (3 * MIN_CHUNK_SIZE) as u64 {
        let tmp = self.sequencer.to_vec();
        self.my_datamap = datamap::DataMap::Content(tmp.to_vec());
        self.closed = true;
        datamap::DataMap::Content(tmp)
      } else {
        // assert(self.get_num_chunks() > 2 && "Try to close with less than 3 chunks");
        let mut tmp_chunks : Vec<datamap::ChunkDetails> = Vec::new();
        tmp_chunks.reserve(self.get_num_chunks() as usize);

        for chunk in self.chunks.iter() {
          if chunk.status == ChunkStatus::ToBeHashed ||
              tmp_chunks[chunk.number as usize].pre_hash.len() == 0 || self.get_num_chunks() == 3 {
            let this_size = self.get_chunk_size(chunk.number);
            let pos = self.get_start_end_positions(chunk.number);

            let mut tmp : Vec<u8> = Vec::new();
            tmp.reserve(this_size as usize);
            for i in 0..this_size { tmp[i as usize] = self.sequencer[(i + pos.0 as u32) as usize].clone(); }
            // assert(tmp.len() == this_size && "vector diff size from chunk size");

            let mut tmp2 : Vec<u8> = Vec::new();
            tmp2.reserve(4096);
            let mut hash = Sha512::new();
            hash.input(tmp.as_mut_slice());
            hash.result(tmp2.as_mut_slice());
            {
              tmp_chunks[chunk.number as usize].pre_hash.clear();
              tmp_chunks[chunk.number as usize].pre_hash = tmp2.to_vec();
             // assert(4096 == tmp_chunks[chunk.number].pre_hash.len() && "Hash size wrong");
            }
          }
        }
        for chunk in self.chunks.iter_mut() {
          if chunk.status == ChunkStatus::ToBeHashed {
            chunk.status = ChunkStatus::ToBeEncrypted;
          }
        }

        self.my_datamap = datamap::DataMap::Chunks(tmp_chunks.to_vec());
        for chunk in self.chunks.iter() {
          if chunk.status == ChunkStatus::ToBeEncrypted {
            let this_size = self.get_chunk_size(chunk.number);
            let pos = self.get_start_end_positions(chunk.number);

            let mut tmp : Vec<u8> = Vec::new();
            tmp.reserve(this_size as usize);
            for i in 0..this_size { tmp[i as usize] = self.sequencer[(i + pos.0 as u32) as usize].clone(); }
            let result = self.encrypt_chunk(chunk.number, tmp);
          }
        }
        for chunk in self.chunks.iter_mut() {
          if chunk.status == ChunkStatus::ToBeEncrypted {
            chunk.status = ChunkStatus::AlreadyEncrypted;
          }
        }
        self.closed = true;
        datamap::DataMap::Chunks(tmp_chunks)
      }
    }
  }

  pub fn truncate(&self, position: u64) {


  }

  /// current file size as is known by encryptor
  pub fn len(&self)->u64 {
    self.file_size
  }

  /// Prepere a sliding window to ensure there are enouch chunk slots for write
  /// will possibly readin some chunks from external storage
  fn prepare_window(&mut self, length: u64, position: u64, write: bool) {
    if  (length + position) as usize > self.sequencer.len() {
      self.sequencer.resize((length + position) as usize, 0u8);
    }
    if self.file_size < (3 * MIN_CHUNK_SIZE) as u64 { return }
    let mut first_chunk = self.get_chunk_number(position);
    let mut last_chunk = self.get_chunk_number(position + length);
    if write && self.sequencer.len() < (position + length) as usize {
      self.sequencer.resize((length + position) as usize, 0u8);
    }
    if self.file_size < (3 * MAX_CHUNK_SIZE) as u64 {
      first_chunk = 0;
      last_chunk = 3;
    } else {
      for _ in (1..2) {
        if last_chunk < self.get_num_chunks() { last_chunk += 1; }
      }
    }
    // [TODO]: Thread next - 2015-02-28 06:09pm
    for i in (first_chunk..last_chunk) {
    let mut tmp_chunks = Vec::new();
      for itr in  self.chunks.iter() {
        if itr.number == i  {
          let mut pos = self.get_start_end_positions(i).0;
          if itr.location == ChunkLocation::Remote  {
            let vec : Vec<u8> = self.decrypt_chunk(i);
            for itr2 in vec.iter() {
              self.sequencer[pos as usize] = *itr2;
              pos += 1;
            }
          }

        } else {
          if write { tmp_chunks.push(Chunks{number: i,
                          status: ChunkStatus::ToBeHashed, location: ChunkLocation::InSequencer}); }
          else { tmp_chunks.push(Chunks{number: i,
                    status: ChunkStatus::AlreadyEncrypted, location: ChunkLocation::InSequencer}); }

        }
      }
      self.chunks.append(&mut tmp_chunks);
    }
  }
 // [TODO]: use fixed width arrays here, derived
 // from key size of cipher used (compile time) - 2015-03-02 01:01am
  fn get_pad_iv_key(&self, chunk_number: u32)->(Vec<u8>, Vec<u8>, Vec<u8>) {
    let vec : Vec<u8> = self.my_datamap.get_sorted_chunks()[chunk_number as usize].pre_hash.clone();
    let n_1_vec : Vec<u8> = self.my_datamap.get_sorted_chunks()
                       [self.get_previous_chunk_number(chunk_number - 1) as usize].pre_hash.clone();
    let n_2_vec : Vec<u8> = self.my_datamap.get_sorted_chunks()
                       [self.get_previous_chunk_number(chunk_number - 2) as usize].pre_hash.clone();

     (vec + &n_1_vec[48..64] + &n_2_vec[..] , n_1_vec[0..32].to_vec() , n_1_vec[32..48].to_vec())
  }


  fn decrypt_chunk(&self, chunk_number : u32)->Vec<u8> {
    let name = self.my_datamap.get_sorted_chunks()[chunk_number as usize].hash.clone();
    // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
    let kvp = &self.get_pad_iv_key(chunk_number);
    let xor_result = xor(&self.storage.get(name), &kvp.0);
    return encryption::decrypt(&xor_result, &kvp.2[..], &kvp.1[..]).ok().unwrap();
  }

  fn encrypt_chunk(&self, chunk_number : u32, content : Vec<u8>)->Vec<u8> {
    let name = self.my_datamap.get_sorted_chunks()[chunk_number as usize].hash.clone();
    // [TODO]: work out passing functors properly - 2015-03-02 07:00pm
    let kvp = &self.get_pad_iv_key(chunk_number);
    let enc = &encryption::encrypt(&content, &kvp.2[..], &kvp.1[..]).ok().unwrap();
    xor(&enc, &kvp.0)
  }

  // Helper methods
  fn get_num_chunks(&self)->u32 {
    if self.file_size  < (3 * MIN_CHUNK_SIZE as u64) { return 0 }
    if self.file_size  < (3 * MAX_CHUNK_SIZE as u64) { return 3 }
    if self.file_size  % MAX_CHUNK_SIZE as u64 == 0 {
      return (self.file_size / MAX_CHUNK_SIZE as u64) as u32
    } else {
      return (self.file_size / MAX_CHUNK_SIZE as u64 + 1) as u32
    }
  }

  fn get_chunk_size(&self, chunk_number: u32)->u32 {
    if self.file_size < 3 * MIN_CHUNK_SIZE as u64 { return 0u32 }
    if self.file_size < 3 * MAX_CHUNK_SIZE as u64 {
      if chunk_number < 2 {
        return (self.file_size / 3) as u32
      } else {
        return (self.file_size - (2 * self.file_size / 3)) as u32
      }
    }
    if chunk_number < self.get_num_chunks() - 2 { return MAX_CHUNK_SIZE }
    let remainder :u32 = (self.file_size % MAX_CHUNK_SIZE as u64) as u32;
    let penultimate :bool = (SelfEncryptor::get_num_chunks(self) - 2) == chunk_number;
    if remainder == 0 { return MAX_CHUNK_SIZE }
    if remainder < MIN_CHUNK_SIZE {
       if penultimate {
         return MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
       } else {
         return MIN_CHUNK_SIZE + remainder }
     } else {
       if penultimate { return MAX_CHUNK_SIZE } else { return remainder }
     }

  }

  fn get_start_end_positions(&self, chunk_number :u32)->(u64, u64) {
   if self.get_num_chunks() == 0 { return (0,0) }
   let mut start :u64;
   let penultimate = (self.get_num_chunks() - 2) == chunk_number;
   let last = (self.get_chunk_size(0) - 1) == chunk_number;
   if last {
     start = (self.get_chunk_size(0) * (chunk_number - 2) + self.get_chunk_size(chunk_number - 2) +
       self.get_chunk_size(chunk_number - 1)) as u64;
   } else if penultimate {
     start = (self.get_chunk_size(0) * (chunk_number - 1) +
                                                      self.get_chunk_size(chunk_number - 1)) as u64;
   } else {
     start = (self.get_chunk_size(0) * chunk_number) as u64;
   }
    (start, (start + self.get_chunk_size(chunk_number) as u64))
    }

  fn get_next_chunk_number(&self, chunk_number : u32)->u32 {
    if self.get_num_chunks() == 0 { return 0u32 }
    (self.get_num_chunks() + chunk_number + 1) % self.get_num_chunks()
    }

  fn get_previous_chunk_number(&self, chunk_number :u32)->u32 {
    if self.get_num_chunks() == 0 { return 0u32 }
    (self.get_num_chunks() + chunk_number - 1) % self.get_num_chunks()

  }

  fn get_chunk_number(&self, position: u64)->u32 {
    if self.get_num_chunks() == 0 { return 0u32 }
    (position / self.get_chunk_size(0) as u64) as u32
    }


}

#[cfg(test)]

mod test {
  use super::*;

fn random_string(length: u64) -> String {
      (0..length).map(|_| (0x20u8 + (super::rand::random::<f32>() * 96.0) as u8) as char).collect()
  }

pub struct MyStorage {
    name: Vec<u8>
}

/*pub trait Storage {
      fn get(&self, name: Vec<u8>) -> Vec<u8>;
      fn put(&self, name: Vec<u8>, data: Vec<u8>);
}*/

impl Storage for MyStorage {
   //let mut name: Vec<u8> = vec![0x11];
   fn get(&self, name: Vec<u8>) -> Vec<u8> {
       name
       }
   fn put(&self, name: Vec<u8>, data: Vec<u8>){}
   }


#[test]
fn test_xor() {
  let mut data: Vec<u8> = vec!();
  let mut pad: Vec<u8> = vec!();
  for _ in range(0, 800) {
    data.push(super::rand::random::<u8>());
  }
  for _ in range(0, 333) {
    pad.push(super::rand::random::<u8>());
  }
  assert_eq!(data, xor(&xor(&data,&pad), &pad));
}



#[test]
fn check_write() {
  //struct MyStorage;
  //let name = vec![0x11];
  /*impl Storage for MyStorage {
     fn get(&mut self, name: Vec<u8> ) -> Vec<u8> {name}
  }*/
  let name = vec![0x11];
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string(3), 5u64);
  assert_eq!(se.file_size, 8u64);
  assert_eq!(se.get_storage().get(name),vec![0x11]);
}

#[test]
fn check_helper_3_min_chunks() {
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string(MIN_CHUNK_SIZE as u64 * 3), 0);
  assert_eq!(se.get_num_chunks(), 3);
  assert_eq!(se.get_chunk_size(0), 1024);
  assert_eq!(se.get_chunk_size(1), 1024);
  assert_eq!(se.get_chunk_size(2), 1024);
  assert_eq!(se.get_next_chunk_number(0), 1);
  assert_eq!(se.get_next_chunk_number(1), 2);
  assert_eq!(se.get_next_chunk_number(2), 0);
  assert_eq!(se.get_previous_chunk_number(0), 2);
  assert_eq!(se.get_previous_chunk_number(1), 0);
  assert_eq!(se.get_previous_chunk_number(2), 1);
  assert_eq!(se.get_start_end_positions(0).0, 0u64);
  assert_eq!(se.get_start_end_positions(0).1, MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).0, MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).1, 2 * MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).0, 2 * MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).1, 3 * MIN_CHUNK_SIZE as u64);
}
#[test]
fn check_helper_3_min_chunks_plus1() {
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string((MIN_CHUNK_SIZE as u64 * 3) + 1), 0);
  assert_eq!(se.get_num_chunks(), 3);
  assert_eq!(se.get_chunk_size(0), 1024);
  assert_eq!(se.get_chunk_size(1), 1024);
  assert_eq!(se.get_chunk_size(2), 1025);
  assert_eq!(se.get_next_chunk_number(0), 1);
  assert_eq!(se.get_next_chunk_number(1), 2);
  assert_eq!(se.get_next_chunk_number(2), 0);
  assert_eq!(se.get_previous_chunk_number(0), 2);
  assert_eq!(se.get_previous_chunk_number(1), 0);
  assert_eq!(se.get_previous_chunk_number(2), 1);
  assert_eq!(se.get_start_end_positions(0).0, 0u64);
  assert_eq!(se.get_start_end_positions(0).1, MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).0, MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).1, 2 * MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).0, 2 * MIN_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).1, 1 + 3 * MIN_CHUNK_SIZE as u64);
}

#[test]
fn check_helper_3_max_chunks() {
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string(MAX_CHUNK_SIZE as u64 * 3), 0);
  assert_eq!(se.get_num_chunks(), 3);
  assert_eq!(se.get_chunk_size(0), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(1), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(2), MAX_CHUNK_SIZE);
  assert_eq!(se.get_next_chunk_number(0), 1);
  assert_eq!(se.get_next_chunk_number(1), 2);
  assert_eq!(se.get_next_chunk_number(2), 0);
  assert_eq!(se.get_previous_chunk_number(0), 2);
  assert_eq!(se.get_previous_chunk_number(1), 0);
  assert_eq!(se.get_previous_chunk_number(2), 1);
  assert_eq!(se.get_start_end_positions(0).0, 0u64);
  assert_eq!(se.get_start_end_positions(0).1, MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).0, MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).1, 2 * MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).0, 2 * MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).1, 3 * MAX_CHUNK_SIZE as u64);
}
#[test]
fn check_helper_3_max_chunks_plus1() {
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string((MAX_CHUNK_SIZE as u64 * 3) + 1), 0);
  assert_eq!(se.get_num_chunks(), 4);
  assert_eq!(se.get_chunk_size(0), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(1), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(2), MAX_CHUNK_SIZE - MIN_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(3), MIN_CHUNK_SIZE +1);
  assert_eq!(se.get_next_chunk_number(0), 1);
  assert_eq!(se.get_next_chunk_number(1), 2);
  assert_eq!(se.get_next_chunk_number(2), 3);
  assert_eq!(se.get_next_chunk_number(3), 0);
  assert_eq!(se.get_previous_chunk_number(0), 3);
  assert_eq!(se.get_previous_chunk_number(1), 0);
  assert_eq!(se.get_previous_chunk_number(2), 1);
  assert_eq!(se.get_previous_chunk_number(3), 2);
  assert_eq!(se.get_start_end_positions(0).0, 0u64);
  assert_eq!(se.get_start_end_positions(0).1, MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).0, MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(1).1, 2 * MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).0, 2 * MAX_CHUNK_SIZE as u64);
  assert_eq!(se.get_start_end_positions(2).1, ((3 * MAX_CHUNK_SIZE) - MIN_CHUNK_SIZE) as u64);
}

#[test]
fn check_helper_7_and_a_bit_max_chunks() {
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string((MAX_CHUNK_SIZE as u64 * 7) + 1024), 0);
  assert_eq!(se.get_num_chunks(), 8);
  assert_eq!(se.get_chunk_size(0), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(1), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(2), MAX_CHUNK_SIZE);
  assert_eq!(se.get_chunk_size(3), MAX_CHUNK_SIZE);
  assert_eq!(se.get_next_chunk_number(0), 1);
  assert_eq!(se.get_next_chunk_number(1), 2);
  assert_eq!(se.get_next_chunk_number(2), 3);
  assert_eq!(se.get_next_chunk_number(3), 4);
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
}
}
