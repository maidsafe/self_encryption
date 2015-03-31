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

extern crate self_encryption;
extern crate rand;
extern crate tempdir;
pub use self_encryption::*;
//use std::path::Path;
//use std::fs::File;
//use std::io::*;
//use tempdir::TempDir as TempDir;
use rand::{thread_rng, Rng};

fn random_bytes(length: usize) -> Vec<u8> {
  let mut bytes : Vec<u8> = Vec::with_capacity(length);
  for _ in (0..length) {
    bytes.push(rand::random::<u8>());
  }
  bytes
}

const DATA_SIZE : u64 = 20 * 1024 * 1024;

pub struct Entry {
  name: Vec<u8>,
  data: Vec<u8>
}

pub struct MyStorage {
  entries: Vec<Entry>
}

impl MyStorage {
  pub fn new() -> MyStorage {
    MyStorage { entries: Vec::new() }
  }

  pub fn has_chunk(&self, name: Vec<u8>) -> bool {
    for entry in self.entries.iter() {
      if entry.name == name { return true }
    }
    false
  }
}

impl Storage for MyStorage {
  fn get(&self, name: Vec<u8>) -> Vec<u8> {
    for entry in self.entries.iter() {
      if entry.name == name { return entry.data.to_vec() }
    }

    vec![]
  }

  fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
    self.entries.push(Entry { name : name, data : data })
  }
}

// pub struct MyStorage {
//   temp_dir : TempDir
// }

// impl MyStorage {
//   pub fn new() -> MyStorage {
//     MyStorage { temp_dir: match TempDir::new("encrypt_storage") {
//         Ok(dir) => dir,
//         Err(why) => panic!("couldn't create temporary directory: {}", why)
//     } }
//   }
// }

// impl Storage for MyStorage {
//   fn get(&self, name: Vec<u8>) -> Vec<u8> {
//     let file_name = String::from_utf8(name).unwrap();
//     let file_path = self.temp_dir.path().join(Path::new(&file_name)); 
//     let mut f = match File::open(&file_path) {
//         // The `desc` field of `IoError` is a string that describes the error
//         Err(why) => panic!("on get couldn't open: {}", why),
//         Ok(file) => file,
//     };
//     let mut s = String::new();
//     //f.read_to_string(&mut s); put f into a string
//     match f.read_to_string(&mut s){
//         Err(why) => panic!("on get couldn't read: {}", why),
//         Ok(_) => print!("contains:\n{}", s),
//     }
//     s.into_bytes()
//   }

//   #[allow(unused_must_use)]
//   fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
//     let file_name = String::from_utf8(name).unwrap();
//     let file_path = self.temp_dir.path().join(Path::new(&file_name)); 
//     let mut f = match File::create(&file_path) {
//         // The `desc` field of `IoError` is a string that describes the error
//         Err(why) => panic!("on put couldn't open: {}", why),
//         Ok(file) => file,
//     };
//     f.write_all(&data);
//   }
// }

#[test]
fn new_read() {
  let read_size : usize = 4096;
  let mut read_position : usize = 0;
  let content_len : usize = 4 * MAX_CHUNK_SIZE as usize;
  let mut my_storage = MyStorage::new();
  let original = random_bytes(content_len);
  {
    let mut se = SelfEncryptor::new(&mut my_storage, datamap::DataMap::None);
    se.write(&original, 0);
    {
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
      for _ in 0..15 {
        decrypted.push_all(&se.read(read_position as u64, read_size as u64));
        assert_eq!(original[0..(read_position+read_size)].to_vec(),
                   decrypted);
        read_position += read_size;
      }
    }
    //TODO(Ben:2015-03-27) Panics at MyStorage::Put, when writing datamap!
    //     Possible cause of bug, by reading sequencer over file-end
    se.close();
  }
}

#[test]
fn write_random_size_random_position() {
  let mut rng = thread_rng();
  let mut my_storage = MyStorage::new();
  let max_broken_size : u64 = 20 * 1024;
  let original = random_bytes(DATA_SIZE as usize);
  // estimate number of broken pieces, not known in advance
  let mut broken_data : Vec<(u64, &[u8])> =
        Vec::with_capacity((DATA_SIZE / max_broken_size) as usize);

  let mut offset : u64 = 0;
  let mut last_piece : u64 = 0;
  while offset < DATA_SIZE {
    let size : u64;
    if DATA_SIZE - offset < max_broken_size {
      size = DATA_SIZE - offset;
      last_piece = offset;
    } else {
      size = rand::random::<u64>() % max_broken_size;
    }
    let piece : (u64, &[u8]) = (offset, 
          &original[offset as usize..(offset + size) as usize]);
    broken_data.push(piece);
    offset += size;
  }

  {
    let slice_broken_data = &mut broken_data[..];
    rng.shuffle(slice_broken_data);
  }

  match broken_data.iter()
                   .filter(|&x| x.0 != last_piece)
                   .last() {
    None => panic!("Should never occur. Error in test itself."),
    Some(overlap) => {
      let mut extra : Vec<u8> = overlap.1.to_vec();
      extra.push_all(&mut random_bytes(7usize)[..]);
      let post_overlap : (u64, &[u8]) = (overlap.0, &mut extra[..]);
      let post_position: u64 = overlap.0 + overlap.1.len() as u64;
      let mut wtotal : u64 = 0;

      let mut se = SelfEncryptor::new(&mut my_storage, datamap::DataMap::None);
      for element in broken_data.iter() {
        se.write(element.1, element.0);
        wtotal += element.1.len() as u64;
      }
      assert_eq!(wtotal, DATA_SIZE);
      let decrypted = se.read(0u64, DATA_SIZE);
      assert_eq!(original, decrypted);
      
      let mut overwrite = original[0..post_overlap.0 as usize].to_vec();
      overwrite.push_all(post_overlap.1);
      overwrite.push_all(&original[post_position as usize + 7..DATA_SIZE as usize]);
      se.write(post_overlap.1, post_overlap.0);
      let decrypted = se.read(0u64, DATA_SIZE);
      assert_eq!(overwrite.len(), decrypted.len());
      assert_eq!(overwrite, decrypted);
    }
  }
}

// Test disabled because it fails !
#[test]
fn disabled_write_random_sized_out_of_sequence_writes_with_gaps_and_overlaps() {
  let mut my_storage = MyStorage::new();
  let parts : usize = 20;
  assert!(DATA_SIZE / MAX_CHUNK_SIZE as u64 >= parts as u64);
  let original = random_bytes(DATA_SIZE as usize);
  let mut pieces : Vec<&[u8]> = Vec::with_capacity(parts);
  let mut offsets : Vec<usize> = Vec::with_capacity(parts);
  let mut index : Vec<usize> = Vec::with_capacity(parts);
  let mut total_size : usize = 0;
  let mut rng = thread_rng();

  for i in 0..parts {
    // grab random sized pieces from the data
    let offset : usize = rand::random::<usize>() 
                     % (DATA_SIZE - MAX_CHUNK_SIZE as u64 - 2) as usize;
    let piece_size : usize = (rand::random::<usize>() 
                     % MAX_CHUNK_SIZE as usize) + 1;
    pieces.push(&original[offset..(offset + piece_size)]);
    offsets.push(offset);
    index.push(i);
  }
 
  {
    let slice_index = &mut index[..];
    rng.shuffle(slice_index);
  }

  { // write the pieces. Positions could yield overlaps or gaps.
    let mut se = SelfEncryptor::new(&mut my_storage, datamap::DataMap::None);
    for ind in index {
      let piece_size : usize = pieces[ind].len();
      let offset : usize = offsets[ind];
      total_size = std::cmp::max(total_size, offset + piece_size);
      se.write(pieces[ind], offset as u64);
      assert!(DATA_SIZE >= total_size as u64);
      let decrypted = se.read(offset as u64, piece_size as u64);
      assert_eq!(decrypted, original[offset..(offset + piece_size)].to_vec());
      assert_eq!(total_size as u64, se.len());
    }
    let decryptor = se.read(0u64, total_size as u64);
    assert_eq!(decryptor, original[0..total_size].to_vec());
    assert_eq!(total_size as u64, se.len());
    se.close();
  }
}

