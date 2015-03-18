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

#![allow(dead_code, unused_variables)]

extern crate self_encryption;
extern crate rand;
extern crate rustc_back;
pub use self_encryption::*;
use std::path::Path;
use std::fs::File;
use rustc_back::tempdir::TempDir as TempDir;
use std::string::String as String;


/// DataMap integratoin tests
#[test]
fn data_map_empty(){
  let dm = self_encryption::datamap::DataMap::Content(vec![110,111]);
  assert_eq!(dm.len(), 2);
  }

#[test]
fn data_map_content_only(){
  let dm = self_encryption::datamap::DataMap::Content(vec![110,111]);
  assert!(dm.len() == 2);
  assert!(dm.has_chunks() == false);
  }

fn random_string(length: u64) -> String {
        (0..length).map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char).collect()
  }
/// Self Enryptor integration tests
/*#[test]
fn check_write() {
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string(3), 5u64);
  assert_eq!(se.len(), 8u64);
}*/


// pub struct MyStorage {
//     name: Vec<u8>
// }



// pub type tempo = TempDir;

pub struct MyStorage {
  temp_dir : TempDir
}

impl MyStorage {
  pub fn new() -> MyStorage {
    MyStorage { temp_dir: match TempDir::new("encrypt_storage") {
        Ok(dir) => dir,
        Err(e) => panic!("couldn't create temporary directory: {}", e)
    } }
    // //tempo = match TempDir::new("encrypt_storage");
    // let store = match TempDir::new("encrypt_storage") {
    //     Ok(dir) => dir,
    //     Err(e) => panic!("couldn't create temporary directory: {}", e)
    // };
    
    // MyStorage { temp_dir: store }
    // //MyStorage { temp_dir: TempDir::new("encrypt_storage") }
  }
}

impl Storage for MyStorage {
  fn get(&self, name: Vec<u8>) -> Vec<u8> {
    //let mut f = std::fs::File::open(self.temp_dir.path() / name);
    // let file_name = String::from_utf8(name).unwrap();
    // let tmppath = self.temp_dir.path().join(&file_name.into_bytes());
    // let tmppath = self.temp_dir.path().join(&name);  --
    let file_name = String::from_utf8(name).unwrap();
    let file_path = self.temp_dir.path().join(Path::new(&file_name)); 
    let mut f = match std::fs::File::open(&file_path) {
        // The `desc` field of `IoError` is a string that describes the error
        Err(why) => panic!("couldn't open: {}", why.description()),
        Ok(file) => file,
    };
    let mut s = String::new();
    //f.read_to_string(&mut s);
    match f.read_to_string(&mut s){
        Err(why) => panic!("couldn't read: {}", why.description()),
        Ok(_) => print!("contains:\n{}", s),
    }
    s.into_bytes()
  }

  fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
    let file_name = String::from_utf8(name).unwrap();
    let file_path = self.temp_dir.path().join(Path::new(&file_name)); 
    let mut f = match std::fs::File::create(&file_path) {
        // The `desc` field of `IoError` is a string that describes the error
        Err(why) => panic!("couldn't open: {}", why.description()),
        Ok(file) => file,
    };
    f.write_all(&data);
  }
}


// pub struct Entry {
//   name: Vec<u8>,
//   data: Vec<u8>
// }


// pub struct MyStorage {
//   entries: Vec<Entry>
// }

// impl MyStorage {
//   pub fn new() -> MyStorage {
//     MyStorage {entries: Vec::new() }
//   }
// }

// /// this function is defined as exceptioni free, so return empty if cannot fetch
// impl Storage for MyStorage {
//   fn get(&self, name: Vec<u8>) -> VEc<u8> {
//     for entry in self.entries.iter() {
//       if entry.name == name {
//         return entry.data.to_vec()
//       }
//     }
//     let result: Vec<u8> = Vec::new();
//     result
//   }

//   fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
//     self.entries.push(Entry {name: name, data: data})
//   }
// }



// impl Storage for MyStorage {
//    //let mut name: Vec<u8> = vec![0x11];
//    fn get(&self, name: Vec<u8>) -> Vec<u8> {
//        name
//        }
//    fn put(&mut self, name: Vec<u8>, data: Vec<u8>){}
//    }

#[test]
fn check_disk_int_5000() {
  let content = random_string(5000);
  let mut my_storage = MyStorage::new();
  let mut data_map = datamap::DataMap::None;
  {
    let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
    se.write(&content, 5u64);
    assert_eq!(se.len(), 5005u64);
    data_map = se.close();
  }
  let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
  let fetched = new_se.read(5u64, 5000);
  assert_eq!(fetched, content);
  let new_data_map = new_se.close();
  match new_data_map {
    datamap::DataMap::Chunks(ref chunks) => {
      assert!(chunks.len() == 3);
    }
    datamap::DataMap::Content(ref content) => panic!("shall not return DataMap::Content"),
    datamap::DataMap::None => panic!("shall not return DataMap::None"),
  }
}


#[test]
fn check_disk_int_1() {
  let content = random_string(1);
  let mut my_storage = MyStorage::new();
  let mut data_map = datamap::DataMap::None;
  {
    let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
    se.write(&content, 5u64);
    assert_eq!(se.len(), 6u64);
    data_map = se.close();
  }
  let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
  let fetched = new_se.read(5u64, 1);
  assert_eq!(fetched, content);
  let new_data_map = new_se.close();
  match new_data_map {
    datamap::DataMap::Chunks(ref chunks) => {
      assert!(chunks.len() == 3);
    }
    datamap::DataMap::Content(ref content) => panic!("shall not return DataMap::Content"),
    datamap::DataMap::None => panic!("shall not return DataMap::None"),
  }
}


#[test]
fn check_disk_int_10000000() {
  let content = random_string(1);
  let mut my_storage = MyStorage::new();
  let mut data_map = datamap::DataMap::None;
  {
    let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
    se.write(&content, 5u64);
    assert_eq!(se.len(), 10000005u64);
    data_map = se.close();
  }
  let mut new_se = SelfEncryptor::new(&mut my_storage as &mut Storage, data_map);
  let fetched = new_se.read(5u64, 10000000);
  assert_eq!(fetched, content);
  let new_data_map = new_se.close();
  match new_data_map {
    datamap::DataMap::Chunks(ref chunks) => {
      assert!(chunks.len() == 3);
    }
    datamap::DataMap::Content(ref content) => panic!("shall not return DataMap::Content"),
    datamap::DataMap::None => panic!("shall not return DataMap::None"),
  }
}



///# Examples
///
///  SelfEncryptor Example
/// ```
/// extern crate self_encryption
/// extern crate rand;
/// use use self_encryption::*;
///
/// fn main() {
/// fn random_string(length: u64) -> String {
///        (0..length).map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char).collect()
///  } // function to create random string

/// pub struct Entry {
/// name: Vec<u8>,
/// data: Vec<u8>
/// }
/// pub struct MyStorage {
/// entries: Vec<Entry>
/// }
/// impl MyStorage {
/// pub fn new() -> MyStorage {
/// MyStorage { entries: Vec::new() }
/// }


/// impl Storage for MyStorage {
/// fn get(&self, name: Vec<u8>) -> Vec<u8> {
/// for entry in self.entries.iter() {
/// if entry.name == name { return entry.data.to_vec() }
/// }
/// let result : Vec<u8> = Vec::new();
/// result
/// }
/// fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
/// self.entries.push(Entry { name : name, data : data })
/// }
/// }
///
/// let mut my_storage = MyStorage::new();
/// let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
/// let the_string = random_string(3);
/// se.write(&the_string, 5u64);
/// let data_map = se.close();
/// match data_map {
/// datamap::DataMap::Chunks(ref chunks) => panic!("shall not return DataMap::Chunks"),
/// datamap::DataMap::Content(ref content) => {
/// assert_eq!(content.len(), 8 as usize);
/// }
/// datamap::DataMap::None => panic!("shall not return DataMap::None"),
/// }
/// }
/// ```

//#[test]

// fn check_read() {
//   //let name = vec![0x11];
//   //let mut my_storage = MyStorage{name: vec![0x11]};
//   let mut my_storage = MyStorage::new();
//   let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);

//   let the_string = random_string(3);
//     se.write(&the_string, 5u64);
//     let to_be_read = se.read(5u64, 3);
//     assert_eq!(to_be_read, the_string)
//   }