extern crate rand;
extern crate crypto;
use encryption::{ };
use std::collections::HashMap;
use std::cmp;
// this is pub to test the tests dir integration tests these are temp and need to be
// replaced with actual integration tests and this should be private
pub mod encryption;

struct DataMap;

pub struct SelfEncryption {
  /* this_data_map: DataMap, */
  /* sequencer: Vec<u8>, */
  /* chunks: HashMap::new(), */
  file_size: u64,
  closed: bool,
  }

impl SelfEncryption {
  pub fn write(&mut self, data: &str ,length: u32, position: u64) {
    self.file_size = cmp::max(self.file_size, length as u64 + position);
    }
  
  
  
  
  
  }






#[test]
fn check_write() {
  let mut se = SelfEncryption{file_size: 0u64, closed: false};
  se.write("dsd", 3u32, 5u64);
  assert_eq!(se.file_size, 8u64);
}
