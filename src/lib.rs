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
//! and has a name. Thsi name is the ``Sah512``` of the content. This allows the chunks
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
use std::collections::HashMap;
use std::cmp;
use std::old_io::TempDir;
// this is pub to test the tests dir integration tests these are temp and need to be
// replaced with actual integration tests and this should be private
mod encryption;
/// Holds pre and post encryption hashes as well as original chunk size
pub mod datamap;

static MAXCHUNKSIZE: u32 = 1024*1024;
static MINCHUNKSIZE: u32 = 1024;
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
  }
enum ChunkLocation {
    InSequencer,
    OnDisk,  // therefor only being used as read cache`
    Remote

}

struct Chunks { number: u32 , status: ChunkStatus, location: ChunkLocation, name: String, content: String }

/// This is the encryption object and all file handling should be done via this as the low level 
/// mechanism to read and write *content* this library has no knowledge of file metadata. This is
/// a library to ensure content is secured 
pub struct SelfEncryptor {
  sequencer: Vec<Chunks>,
  tempdir : TempDir, 
  file_size: u64,
  closed: bool,
  }


impl SelfEncryptor {
  /// constructor for encryptor object
  pub fn new()-> SelfEncryptor {
    SelfEncryptor{sequencer: Vec::with_capacity(100 as usize), tempdir: create_temp_dir(), file_size: 0, closed: false}
    }
  /// Write method mirrors a posix type write mechanism
  pub fn write(&mut self, data: &str ,length: u32, position: u64) {
    if self.closed { panic!("Encryptor closed, you must start a new Encryptor::new()") }
    let new_size = cmp::max(self.file_size, length as u64 + position);
    self.prepare_window(length, position, true);
    /* for i in 0u64..length as u64 { */
    /*   self.sequencer[position + i] = data[i] as u8; */
    /*   } */
    /*   */
    self.file_size = new_size;
  }
  /// current file size as is known by encryptor
  pub fn len(&self)->u64 {
    self.file_size
  } 
  /// Prepere a sliding window to ensure there are enouch chunk slots for write
  /// will possibly readin some chunks from external storage
  fn prepare_window(&mut self, length: u32, position: u64, write: bool) {
  }
  // Helper methods
  fn get_num_chunks(&self)->u32 {
    if self.file_size  < (3 * MINCHUNKSIZE as u64) { return 0 }
    if self.file_size  < (3 * MAXCHUNKSIZE as u64) { return 3 }
    if self.file_size  % MAXCHUNKSIZE as u64 == 0 {
      return (self.file_size / MAXCHUNKSIZE as u64) as u32 
    } else {
      return (self.file_size / MAXCHUNKSIZE as u64 + 1) as u32
    }
  }

  fn get_chunk_size(&self, chunk: u32)->u32 {
    if self.file_size < 3 * MINCHUNKSIZE as u64 { return 0u32 }
    if self.file_size < 3 * MAXCHUNKSIZE as u64 { 
      if chunk < 2 { 
        return (self.file_size / 3) as u32 
      } else {
        return (self.file_size - (2 * self.file_size / 3)) as u32 
      }
    }
    if chunk < self.get_num_chunks() - 2 { return MAXCHUNKSIZE }
    let remainder :u32 = self.file_size as u32 % MAXCHUNKSIZE;
    let penultimate :bool = (SelfEncryptor::get_num_chunks(self) - 2) == chunk;
    if remainder == 0 { return MAXCHUNKSIZE }
    if remainder < MINCHUNKSIZE {
       if penultimate { 
         return MAXCHUNKSIZE - MINCHUNKSIZE 
       } else { 
         return MINCHUNKSIZE + remainder } 
     } else {
       if penultimate { return MAXCHUNKSIZE } else { return remainder }
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


#[test]
fn check_write() {
  let mut se = SelfEncryptor::new();
  let mut se_ctr = SelfEncryptor{sequencer: Vec::with_capacity(3*MAXCHUNKSIZE as usize), tempdir: create_temp_dir(), file_size: 0, closed: false};
  se.write("dsd", 3u32, 5u64);
  se_ctr.write("fkghguguykghj", 30u32, 50u64);
  assert_eq!(se.file_size, 8u64);
  assert_eq!(se_ctr.file_size, 80u64);
}

#[test]
fn check_helper_3_min_chunks() {
  let mut se = SelfEncryptor::new();
  se.write("dsd", (MINCHUNKSIZE * 3), 0);
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
  assert_eq!(se.get_start_end_positions(0).1, MINCHUNKSIZE as u64);
  assert_eq!(se.get_start_end_positions(1).0, MINCHUNKSIZE as u64);
  assert_eq!(se.get_start_end_positions(1).1, 2 * MINCHUNKSIZE as u64);
  assert_eq!(se.get_start_end_positions(2).0, 2 * MINCHUNKSIZE as u64);
  assert_eq!(se.get_start_end_positions(2).1, 3 * MINCHUNKSIZE as u64);
}
