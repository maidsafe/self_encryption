// Copyright 2014 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.
//http://is.gd/mKdopK

#![feature(collections)]
#![allow(dead_code, unused_variables)]

extern crate self_encryption;
extern crate rand;
extern crate tempdir;
pub use self_encryption::*;
use std::path::Path;
use std::fs::File;
use std::io::*;
use tempdir::TempDir as TempDir;
use rand::{thread_rng, Rng};

fn random_bytes(length: usize) -> Vec<u8> {
  let mut bytes : Vec<u8> = Vec::with_capacity(length);
  for _ in (0..length) {
    bytes.push(rand::random::<u8>());
  }
  bytes
}

const DATA_SIZE : u64 = 20 * 1024 * 1024;

pub struct MyStorage {
  temp_dir : TempDir
}

impl MyStorage {
  pub fn new() -> MyStorage {
    MyStorage { temp_dir: match TempDir::new("encrypt_storage") {
        Ok(dir) => dir,
        Err(e) => panic!("couldn't create temporary directory: {}", e)
    } }
  }
}

impl Storage for MyStorage {
  fn get(&self, name: Vec<u8>) -> Vec<u8> {
    let file_name = String::from_utf8(name).unwrap();
    let file_path = self.temp_dir.path().join(Path::new(&file_name)); 
    let mut f = match File::open(&file_path) {
        // The `desc` field of `IoError` is a string that describes the error
        Err(why) => panic!("on get couldn't open: "),
        Ok(file) => file,
    };
    let mut s = String::new();
    //f.read_to_string(&mut s); put f into a string
    match f.read_to_string(&mut s){
        Err(why) => panic!("on get couldn't read: "),
        Ok(_) => print!("contains:\n{}", s),
    }
    s.into_bytes()
  }

  #[allow(unused_must_use)]
  fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
    let file_name = String::from_utf8(name).unwrap();
    let file_path = self.temp_dir.path().join(Path::new(&file_name)); 
    let mut f = match File::create(&file_path) {
        // The `desc` field of `IoError` is a string that describes the error
        Err(why) => panic!("on put couldn't open: "),
        Ok(file) => file,
    };
    f.write_all(&data);
  }
}

#[test]
#[allow(unused_must_use)]
fn new_read() {
  let read_size : usize = 4096;
  let mut read_position : usize = 0;
  let mut content_len : usize = 4 * MAX_CHUNK_SIZE as usize;
  let mut my_storage = MyStorage::new();
  let mut data_map = datamap::DataMap::None;
  let mut original : Vec<u8> = Vec::with_capacity(content_len);
  original = random_bytes(content_len);
  {
    let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
    se.write(&original, 0);
    {
      let mut decrypted : Vec<u8> = Vec::with_capacity(read_size);
      let decrypted = se.read(read_position as u64, read_size as u64);
      assert_eq!(original[read_position..(read_position+read_size)].to_vec(),
                 decrypted);

      // read next small part
      read_position += read_size;
      let decrypted = se.read(read_position as u64, read_size as u64);
      assert_eq!(original[read_position ..(read_position+read_size)].to_vec(),
                 decrypted);

      // try to read from end of file, moving the sliding window 
      read_position = content_len - 3 * read_size;
      let decrypted = se.read(read_position as u64, read_size as u64);
      assert_eq!(original[read_position ..(read_position+read_size)].to_vec(),
                 decrypted);

      // read again at beginning of file
      read_position = 5usize;
      let decrypted = se.read(read_position as u64, read_size as u64);
      assert_eq!(original[read_position ..(read_position+read_size)].to_vec(),
                 decrypted);

      // read beyond the file, output is padded with default initalisation
      // TODO(Ben: 2015-03-27) follow-up if SE behaviour is changed!
      read_position = content_len - read_size + 2000;
      let decrypted = se.read(read_position as u64, read_size as u64);
      let mut padded : Vec<u8> = Vec::with_capacity(read_size);
      padded.push_all(&original[read_position..content_len]);
      padded.resize(read_size, 0u8);
      assert_eq!(padded, decrypted);
    }

    { // Finish with many small reads
      let mut decrypted : Vec<u8> = Vec::with_capacity(content_len);
      read_position = 0usize;
      for i in 0..15 {
        decrypted.push_all(&se.read(read_position as u64, read_size as u64));
        assert_eq!(original[0..(read_position+read_size)].to_vec(),
                   decrypted);
        read_position += read_size;
      }
    }
      //TODO(Ben:2015-03-27) Panics at MyStorage::Put, when writing datamap!
      //     Possible cause of bug, by reading sequencer over file-end
//    se.close();
  }
}

#[test]
fn write_random_sized_out_of_sequence_writes_with_gaps_and_overlaps() {
  let parts : usize = 20;
  assert!(DATA_SIZE / MAX_CHUNK_SIZE as u64 >= parts as u64);
  let mut original : Vec<u8> = Vec::with_capacity(DATA_SIZE as usize);
  let mut pieces : Vec<Vec<u8>> = Vec::with_capacity(parts);
  let mut index : Vec<usize> = Vec::with_capacity(parts);
  let mut total_size : Vec<usize> = Vec::with_capacity(parts);
  let mut rng = thread_rng();

  original = random_bytes(DATA_SIZE as usize);

  for i in 0..parts {
    // grab random sized pieces from the data
    let offset : usize = rand::random::<usize>() 
                     % (DATA_SIZE - MAX_CHUNK_SIZE as u64 - 2) as usize;
    let piece_size : usize = (rand::random::<usize>() 
                     % MAX_CHUNK_SIZE as usize) + 1;
    pieces.push(original[offset..(offset + piece_size)].to_vec());
    index.push(i);
  }

  let slice_pieces = pieces.as_mut_slice();
  rng.shuffle(slice_pieces);

  
}

