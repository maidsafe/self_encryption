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
pub use self_encryption::*;
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


#[test]
fn check_write() {
  let name = vec![0x11];
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
  se.write(&random_string(3), 5u64);
  assert_eq!(se.len(), 8u64);
  assert_eq!(se.get_storage().get(name),vec![0x11]);
}

#[test]

fn check_read() {
  let name = vec![0x11];
  let mut my_storage = MyStorage{name: vec![0x11]};
  let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);

  let the_string = random_string(3);
    se.write(&the_string, 5u64);
//    let leng = se.len();
    let to_be_read = se.read(5u64, 3);
    assert_eq!(to_be_read, the_string)
  }

