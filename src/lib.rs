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
pub mod encryption;
pub mod datamap;

/// This is the encrypto object and all file handling should be done via this as the low level 
/// mechanism to read and write *content* this librar has no knowledge of file metadata. This is
/// a library to ensure content is secured 
pub struct SelfEncryptor {
  /* this_data_map: DataMap, */
  /* sequencer: Vec<u8>, */
  /* chunks: HashMap::new(), */
  tempdir : TempDir, 
  file_size: u64,
  closed: bool,
  }


impl SelfEncryptor {
  /// constructor for encryptor object
  pub fn new() -> SelfEncryptor {
    SelfEncryptor{tempdir: SelfEncryptor::CreateTempDir(), file_size: 0, closed: false }
  }
  /// Write method mirrors a posiix type write mechanism
  pub fn write(&mut self, data: &str ,length: u32, position: u64) {
    let new_size = cmp::max(self.file_size, length as u64 + position);
    /* self.Preparewindow(length, position, true); */
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
  fn Preparewindow(&mut self, length: u32, position: u64, write: bool) {
  }
  /// Will use a tempdir to stream un procesed data, although this is done vie AES streaming with 
  /// a randome key and IV
  fn CreateTempDir() ->TempDir {
    match TempDir::new("self_encryptor") {
      Ok(dir) => dir,
        Err(e) => panic!("couldn't create temporary directory: {}", e)
    }
  }
  
  }


#[test]
fn check_write() {
  let mut se = SelfEncryptor::new();
  se.write("dsd", 3u32, 5u64);
  assert_eq!(se.file_size, 8u64);
}
