extern crate rand;
extern crate crypto;
use std::collections::HashMap;
use std::cmp;
use std::old_io::TempDir;
// this is pub to test the tests dir integration tests these are temp and need to be
// replaced with actual integration tests and this should be private
pub mod encryption;

struct DataMap;

pub struct SelfEncryptor {
  /* this_data_map: DataMap, */
  /* sequencer: Vec<u8>, */
  /* chunks: HashMap::new(), */
  file_size: u64,
  closed: bool,
  /* tempdir: TempDir, */
  }

/* impl Default for SelfEncryptor { */
/*   fn default() -> SelfEncryptor { */
/*   SelfEncryptor {file_size: 0, closed: false, tempdir: CreateTempDir()} */
/*     } */
/*   } */

impl SelfEncryptor {
  
  pub fn write(&mut self, data: &str ,length: u32, position: u64) {
    let new_size = cmp::max(self.file_size, length as u64 + position);
    /* self.Preparewindow(length, position, true); */
    /* for i in 0u64..length as u64 { */
    /*   self.sequencer[position + i] = data[i] as u8; */
    /*   } */
    /*   */
    self.file_size = new_size;
    }
  
  fn Preparewindow(&mut self, length: u32, position: u64, write: bool) {
    }
  
  fn CreateTempDir() ->TempDir {
    match TempDir::new("self_encryptor") {
      Ok(dir) => dir,
        Err(e) => panic!("couldn't create temporary directory: {}", e)
    }
    }
  
  }






#[test]
fn check_write() {
  let mut se = SelfEncryptor{file_size: 0u64, closed: false};
  se.write("dsd", 3u32, 5u64);
  assert_eq!(se.file_size, 8u64);
}
