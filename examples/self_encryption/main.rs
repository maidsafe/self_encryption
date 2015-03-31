// Copyright 2015 MaidSafe.net limited
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

//! Implementation of a simple commandline for Self-Encryption

extern crate self_encryption;

use std::path;
use std::fs;
use std::io::*;
// use tempdir::TempDir as TempDir;

macro_rules! iotry {
    ($e:expr) => (match $e { Ok(v) => v, Err(e) => panic!("{}", e), })
}

fn usage() {
  println!("Usage: self-encrypt or decrypt a local file");
  println!("       se -e <source_file>");
  println!("       se -d <source_file>");
  println!("       note: use absolute paths");
}

pub struct MyStorage<'b> {
  source_path : &'b path::Path,
  name : &'b str,
  dir : &'b path::Path,
  datamap_path : &'b path::Path
}


impl<'b> MyStorage<'b> {
  pub fn new(&self, filepath_ : &str) -> MyStorage<'b> {
    MyStorage { source_path : match &path::Path::new(filepath_) {
    			  Ok(x) => x,
    			  Err(e) => panic!("Could not parse source file. {}", e)
                },
    			name : match self.source_path.file_name().unwrap(){
    			  Ok(x) => x,
    			  Err(e) => panic!("Source file is not a file. {}", e)
    			},
    			dir : match self.source_path.parent()
    							   .unwrap()
    							   .join(path::Path::new("chunks_".to_string()
    							   	                     + &self.name)) {
    			  Ok(x) => x,
    			  Err(e) => panic!("Folder error.")
    			},
    			datamap_path : match self.dir.join("datamap") {
    			  Ok(x) => x,
    			  Err(e) => panic!("Couldn't create path to datamap.")
    			}
              }
  }
}

impl<'b> self_encryption::Storage for MyStorage<'b> {
  fn get(&self, name: Vec<u8>) -> Vec<u8> {
    let file_name = String::from_utf8(name).unwrap();
    let file_path = self.temp_dir.path().join(path::Path::new(&file_name)); 
    let mut f = match fs::File::open(&file_path) {
        // The `desc` field of `IoError` is a string that describes the error
        Err(why) => panic!("on get couldn't open: {}", why),
        Ok(file) => file,
    };
    let mut s = String::new();
    //f.read_to_string(&mut s); put f into a string
    match f.read_to_string(&mut s){
        Err(why) => panic!("on get couldn't read: {}", why),
        Ok(_) => print!("contains:\n{}", s),
    }
    s.into_bytes()
  }

  #[allow(unused_must_use)]
  fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
    let file_name = String::from_utf8(name).unwrap();
    let file_path = self.temp_dir.path().join(path::Path::new(&file_name)); 
    let mut f = match fs::File::create(&file_path) {
        // The `desc` field of `IoError` is a string that describes the error
        Err(why) => panic!("on put couldn't open: {}", why),
        Ok(file) => file,
    };
    f.write_all(&data);
  }
}

fn main() {

  use std::str::FromStr;

  let args = std::os::args();
  let mut args = args.iter().map(|arg| &arg[..]);
  let source : path::Path;

  enum Mode {
	Encrypt,
	Decrypt
  }

  // Skip program name
  args.next();

  let mode = match args.next() {
	Some("-e") => Mode::Encrypt,
	Some("-d") => Mode::Decrypt,
	_ => { usage(); return; }
  };

  let source = match args.next() {
  	Some(x) => try!(FromStr::from_str(source)),
  	_ => { usage(); return; }
  };

 //  let storage = match &args.collect::<Vec<_>>()[..] {
	// [source, destination] => {
	//   let source = ;
	//   let destination = try!(FromStr::from_str(destination));
	//   MyStorage::new(&source, &destination);
	// },
	// _ => { usage(); return; }
 //  };

}