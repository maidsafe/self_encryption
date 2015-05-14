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

// the test names contain MB, KB which should retain capitalisation
#![allow(non_snake_case)]

#![feature(test)]
#![allow(dead_code, unused_assignments)]
extern crate test;
extern crate rand;
extern crate self_encryption;
extern crate asynchronous;

use test::Bencher;
use self_encryption::SelfEncryptor;
use self_encryption::Storage;
use self_encryption::datamap::DataMap as DataMap;
use std::sync::{Arc,Mutex};

//TODO(ben 2015-03-24): replace copy from src/lib.rs mod test to properly import and reuse

fn random_bytes(length: usize) -> Vec<u8> {
  let mut bytes : Vec<u8> = Vec::with_capacity(length as usize);
  for _ in (0..length) {
    bytes.push(rand::random::<u8>());
  }
  bytes
}

struct Entry {
  name: Vec<u8>,
  data: Vec<u8>
}

struct MyStorage {
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
// end of copy from src/lib.rs

#[bench]
fn bench_write_then_read_a_200B(b: &mut Bencher) {
  let my_storage = Arc::new(MyStorage::new());
  let bytes_len = 200 as u64;
  b.iter(|| {
    let mut data_map = DataMap::None;
    let the_bytes = random_bytes(bytes_len as usize);
    {
      let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
      se.write(&the_bytes, 0);
      data_map = se.close();
    }
    let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
    let fetched = new_se.read(0, bytes_len);
    assert_eq!(fetched, the_bytes);
  });
  b.bytes = 2 * bytes_len;
}

#[bench]
fn bench_write_then_read_b_1KB(b: &mut Bencher) {
  let my_storage = Arc::new(MyStorage::new());
  let bytes_len = 1024 as u64;
  b.iter(|| {
    let mut data_map = DataMap::None;
    let the_bytes = random_bytes(bytes_len as usize);
    {
      let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
      se.write(&the_bytes, 0);
      data_map = se.close();
    }
    let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
    let fetched = new_se.read(0, bytes_len);
    assert_eq!(fetched, the_bytes);
  });
  b.bytes = 2 * bytes_len;
}

#[bench]
fn bench_write_then_read_c_1MB(b: &mut Bencher) {
  let my_storage = Arc::new(MyStorage::new());
  let bytes_len = 1024 * 1024 as u64;
  b.iter(|| {
    let mut data_map = DataMap::None;
    let the_bytes = random_bytes(bytes_len as usize);
    {
      let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
      se.write(&the_bytes, 0);
      data_map = se.close();
    }
    // let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
     // let fetched = new_se.read(0, bytes_len);
     // assert_eq!(fetched, the_bytes);
  });
  b.bytes = 2 * bytes_len;
}

#[bench]
fn bench_write_then_read_d_3MB(b: &mut Bencher) {
  let my_storage = Arc::new(MyStorage::new());
  let bytes_len = 3 * 1024 * 1024 as u64;
  b.iter(|| {
    let mut data_map = DataMap::None;
    let the_bytes = random_bytes(bytes_len as usize);
    {
      let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
      se.write(&the_bytes, 0);
      data_map = se.close();
    }
    // let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
    // let fetched = new_se.read(0, bytes_len);
    // assert_eq!(fetched, the_bytes);
  });
  b.bytes = 2 * bytes_len;
}

#[bench]
fn bench_write_then_read_e_10MB(b: &mut Bencher) {
  let my_storage = Arc::new(MyStorage::new());
  let bytes_len = 10 * 1024 * 1024 as u64;
  b.iter(|| {
    let mut data_map = DataMap::None;
    let the_bytes = random_bytes(bytes_len as usize);
    {
      let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
      se.write(&the_bytes, 0);
      data_map = se.close();
    }
    // let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
    // let fetched = new_se.read(0, bytes_len);
    // assert_eq!(fetched, the_bytes);
  });
  b.bytes = 2 * bytes_len;
}

/*  The assert fails !!
#[bench]
fn bench_write_then_read_range(b: &mut Bencher) {
  let mut my_storage = MyStorage::new();
  let string_range = vec![     512 * 1024,
                          1 * 1024 * 1024,
                          2 * 1024 * 1024,
                          3 * 1024 * 1024,
                          4 * 1024 * 1024,
                          5 * 1024 * 1024,
                          6 * 1024 * 1024];
  for bytes_len in string_range {
    b.iter(|| {
      let mut data_map = DataMap::None;
      let the_bytes = random_bytes(bytes_len as usize);
      {
        let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, DataMap::None);
        se.write(&the_bytes, 0);
        data_map = se.close();
      }
      let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
      let fetched = new_se.read(0, bytes_len);
      assert_eq!(fetched, the_bytes);
    });
    // write and read the data
    b.bytes = 2*bytes_len;
  }
}
*/
