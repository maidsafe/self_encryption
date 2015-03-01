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
//!
//!
//! ### Examples
//!
//! ```rust
//! extern crate self_encryption;
//!
//! # fn main() {}
//! ```
//!

#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://doc.rust-lang.org/log/")]
#![warn(missing_docs)]


extern crate rand;
extern crate crypto;
use self::rand::{ Rng, OsRng };
use std::collections::HashMap;
use std::cmp;
use std::old_io::TempDir;
// this is pub to test the tests dir integration tests these are temp and need to be
// replaced with actual integration tests and this should be private
mod encryption;
/// Holds pre and post encryption hashes as well as original chunk size
pub mod datamap;

static MAX_CHUNK_SIZE: u32 = 1024*1024;
static MIN_CHUNK_SIZE: u32 = 1024;
  /// Will use a tempdir to stream un procesed data, although this is done vie AES streaming with 
  /// a randome key and IV
  pub fn create_temp_dir() ->TempDir {
    match TempDir::new("self_encryptor") {
      Ok(dir) => dir,
        Err(e) => panic!("couldn't create temporary directory: {}", e)
    }
  }

enum ChunkStatus {
    ToBeHashed,
    ToBeEncrypted,
    AlreadyEncrypted
  }
#[derive(PartialEq)]   
enum ChunkLocation {
    InSequencer,
    OnDisk,  // therefor only being used as read cache`
    Remote

}
pub struct Chunk { pub name:  Vec<u8>, pub content: Vec<u8> }
 
struct Chunks { number: u32 , status: ChunkStatus, location: ChunkLocation }

impl Chunks {

}

/// This is the encryption object and all file handling should be done via this as the low level 
/// mechanism to read and write *content* this library has no knowledge of file metadata. This is
/// a library to ensure content is secured 
pub struct SelfEncryptor {
  datamap: datamap::DataMap,
  get: Box<FnMut(Vec<u8>)->Chunk + 'static>, 
  put: Box<FnMut(Chunk)->() + 'static>,
  chunks: Vec<Chunks>,
  sequencer: Vec<u8>,
  tempdir : TempDir, 
  file_size: u64,
  closed: bool,
  }

impl SelfEncryptor {
  //! constructor for encryptor object
  //! Each SelfEncryptor is used for a single file.
  //! The parameters are a DataMap a Get and Put functor. 
  //! the get and put functors should be passed to this library to 
  //! allow the SelfEncryptor to store encrypted chunks and retrieve these 
  //! when necessary.
  pub fn new<Get: 'static , Put: 'static>(datamap: datamap::DataMap, get: Get, put: Put)-> SelfEncryptor 
    where Get: FnMut(Vec<u8>)->Chunk, Put: FnMut(Chunk)->() {
    let get_ptr = Box::new(get);
    let put_ptr = Box::new(put);
    SelfEncryptor{datamap: datamap, get: get_ptr, put: put_ptr,  chunks: Vec::new(), sequencer: Vec::with_capacity(1024 * 1024 * 100 as usize), tempdir: create_temp_dir(), file_size: 0, closed: false}
    }
  
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
  
  pub fn read(&mut self, position: u64, length: u64)-> String {
    if self.closed { panic!("Encryptor closed, you must start a new Encryptor::new()") }
    self.prepare_window(length, position, false);
    let mut data = String::with_capacity(length as usize);
      for i in range(0, length) {
            data.push(self.sequencer[(position + i) as usize] as char);
      }
      data
      // TODO(dirvine)  this can be reduced to a single line with functional style (map range)  :01/03/2015
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
      for i in range(1,2) {
        if last_chunk < self.get_num_chunks() { last_chunk += 1; }
      }  
    }
    // [TODO]: Thread next - 2015-02-28 06:09pm 
    for i in range(first_chunk, last_chunk) {
    let mut tmp_chunks = Vec::new();
      let mut found: bool = false;
      for itr in  self.chunks.iter() {
        if itr.number == i  {
          found = true;
          let mut pos = self.get_start_end_positions(i).0;
          if itr.location == ChunkLocation::Remote  { 
            let vec : Vec<u8> = self.decrypt_chunk(i);
            for itr2 in vec.iter() {
              self.sequencer[pos as usize] = *itr2;
              pos += 1;
            }
          }

        } else {
          if write { tmp_chunks.push(Chunks{number: i, status: ChunkStatus::ToBeHashed, location: ChunkLocation::InSequencer}); }
          else { tmp_chunks.push(Chunks{number: i, status: ChunkStatus::AlreadyEncrypted, location: ChunkLocation::InSequencer}); }  

        }
      }
      self.chunks.append(&mut tmp_chunks);
    }
  }

  

  fn decrypt_chunk(&self, chunk : u32)->Vec<u8> {
    Vec::<u8>::new()
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

  fn get_chunk_size(&self, chunk: u32)->u32 {
    if self.file_size < 3 * MIN_CHUNK_SIZE as u64 { return 0u32 }
    if self.file_size < 3 * MAX_CHUNK_SIZE as u64 { 
      if chunk < 2 { 
        return (self.file_size / 3) as u32 
      } else {
        return (self.file_size - (2 * self.file_size / 3)) as u32 
      }
    }
    if chunk < self.get_num_chunks() - 2 { return MAX_CHUNK_SIZE }
    let remainder :u32 = (self.file_size % MAX_CHUNK_SIZE as u64) as u32;
    let penultimate :bool = (SelfEncryptor::get_num_chunks(self) - 2) == chunk;
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

  fn get_start_end_positions(&self, chunk :u32)->(u64, u64) {
   if self.get_num_chunks() == 0 { return (0,0) } 
   let mut start :u64;
   let penultimate = (self.get_num_chunks() - 2) == chunk;
   let last = (self.get_chunk_size(0) - 1) == chunk; 
   if last {
     start = (self.get_chunk_size(0) * (chunk - 2) + self.get_chunk_size(chunk - 2) +
       self.get_chunk_size(chunk - 1)) as u64;
   } else if penultimate {
     start = (self.get_chunk_size(0) * (chunk - 1) + self.get_chunk_size(chunk - 1)) as u64;
   } else {
     start = (self.get_chunk_size(0) * chunk) as u64;
   }
    (start, (start + self.get_chunk_size(chunk) as u64))
    }
  
  fn get_next_chunk_number(&self, chunk : u32)->u32 {
    if self.get_num_chunks() == 0 { return 0u32 }
    (self.get_num_chunks() + chunk + 1) % self.get_num_chunks()
    }

  fn get_previous_chunk_number(&self, chunk :u32)->u32 {
    if self.get_num_chunks() == 0 { return 0u32 }
    (self.get_num_chunks() + chunk - 1) % self.get_num_chunks()
       
  }

  fn get_chunk_number(&self, position: u64)->u32 {
    if self.get_num_chunks() == 0 { return 0u32 }
    (position / self.get_chunk_size(0) as u64) as u32
    }
     

}

fn random_string(length: u64) -> String {
        (0..length).map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char).collect()
        /* (0..length).map(|_| rand::random::<char>()).collect() */
  }


#[test]
fn check_write() {
  let mut se = SelfEncryptor::new(datamap::DataMap::None, |x| {Chunk{name: Vec::<u8>::new(), content: Vec::<u8>::new() }} , |x|{});
  se.write(random_string(3).as_slice(), 5u64);
  assert_eq!(se.file_size, 8u64);
}

#[test]
fn check_helper_3_min_chunks() {
  let mut se = SelfEncryptor::new(datamap::DataMap::None, |x| {Chunk{name: Vec::<u8>::new(), content: Vec::<u8>::new() }} , |x|{});
  se.write(random_string(MIN_CHUNK_SIZE as u64 * 3).as_slice(), 0);
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
  let mut se = SelfEncryptor::new(datamap::DataMap::None, |x| {Chunk{name: Vec::<u8>::new(), content: Vec::<u8>::new() }} , |x|{});
  se.write(random_string((MIN_CHUNK_SIZE as u64 * 3) + 1).as_slice(), 0);
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
  let mut se = SelfEncryptor::new(datamap::DataMap::None, |x| {Chunk{name: Vec::<u8>::new(), content: Vec::<u8>::new() }} , |x|{});
  se.write(random_string(MAX_CHUNK_SIZE as u64 * 3).as_slice(), 0);
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
  let mut se = SelfEncryptor::new(datamap::DataMap::None, |x| {Chunk{name: Vec::<u8>::new(), content: Vec::<u8>::new() }} , |x|{});
  se.write(random_string((MAX_CHUNK_SIZE as u64 * 3) + 1).as_slice(), 0);
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
fn check_helper_3_and_a_bit_max_chunks() {
  let mut se = SelfEncryptor::new(datamap::DataMap::None, |x| {Chunk{name: Vec::<u8>::new(), content: Vec::<u8>::new() }} , |x|{});
  se.write(random_string((MAX_CHUNK_SIZE as u64 * 7) + 1024).as_slice(), 0);
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
