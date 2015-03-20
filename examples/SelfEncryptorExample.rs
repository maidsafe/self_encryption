extern crate self_encryption;
extern crate rand;
use self_encryption::*;


  fn main() {

    fn random_string(length: u64) -> String {
       (0..length).map(|_| (0x20u8 + (rand::random::<f32>() * 96.0) as u8) as char).collect()
    } 

    struct Entry {
      name: Vec<u8>,
      data: Vec<u8>
    }

    struct MyStorage {
      entries: Vec<Entry>
    }

    impl MyStorage {
      fn new() -> MyStorage {
        MyStorage { entries: Vec::new() }
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

    let mut my_storage = MyStorage::new();
    let mut se = SelfEncryptor::new(&mut my_storage as &mut Storage, datamap::DataMap::None);
    let the_string = random_string(3);
    se.write(&the_string, 5u64);
    assert_eq!(se.len(), 8u64);
    let data_map = se.close();
    match data_map {
      datamap::DataMap::Chunks(ref chunks) => panic!("shall not return DataMap::Chunks"),
      datamap::DataMap::Content(ref content) => {
         assert_eq!(content.len(), 8 as usize);
      }
      datamap::DataMap::None => panic!("shall not return DataMap::None"),
    } 
  }  
   
