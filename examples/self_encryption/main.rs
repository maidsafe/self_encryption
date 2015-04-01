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
// use std::os::*;
// use tempdir::TempDir as TempDir;

macro_rules! iotry {
    ($e:expr) => (match $e { Ok(v) => v, Err(e) => panic!("{}", e), })
}

fn usage() {
  println!("Usage: self-encrypt or decrypt local file");
  println!("       se [-e|-d] <full_file_name>");
  println!("       note: the file name should be given as absolute path");
}

// pub struct MyStorage<'b> {
//   dir : &'b path::Path
// }


// impl<'b> MyStorage<'b> {
//   pub fn new(&self, filepath_ : &str) -> MyStorage<'b> {
//     MyStorage { source_path : match path::Path::new(filepath_) {
//     			  Ok(x) => x,
//     			  Err(e) => panic!("Could not parse source file. {}", e)
//                 },
//     			name : match self.source_path.file_name().unwrap(){
//     			  Ok(x) => x,
//     			  Err(e) => panic!("Source file is not a file. {}", e)
//     			},
//     			dir : match self.source_path.parent()
//     							   .unwrap()
//     							   .join(path::Path::new("chunks_".to_string()
//     							   	                     + &self.name)) {
//     			  Ok(x) => x,
//     			  Err(e) => panic!("Folder error.")
//     			},
//     			datamap_path : match self.dir.join("datamap") {
//     			  Ok(x) => x,
//     			  Err(e) => panic!("Couldn't create path to datamap.")
//     			}
//               }
//   }
// }

// impl<'b> self_encryption::Storage for MyStorage<'b> {
//   fn get(&self, name: Vec<u8>) -> Vec<u8> {
//     let file_name = String::from_utf8(name).unwrap();
//     let file_path = self.temp_dir.path().join(path::Path::new(&file_name)); 
//     let mut f = match fs::File::open(&file_path) {
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
//     let file_path = self.temp_dir.path().join(path::Path::new(&file_name)); 
//     let mut f = match fs::File::create(&file_path) {
//         // The `desc` field of `IoError` is a string that describes the error
//         Err(why) => panic!("on put couldn't open: {}", why),
//         Ok(file) => file,
//     };
//     f.write_all(&data);
//   }
// }

fn main() {

  use std::str::FromStr;

  let args : Vec<String> = std::env::args().collect();
  let mut args = args.iter().map(|arg| &arg[..]);
  
  // Skip program name
  args.next();

  enum Mode {
	Encrypt,
	Decrypt
  };

  let mode = match args.next() {
	Some("-e") => Mode::Encrypt,
	Some("-d") => Mode::Decrypt,
	_ => { usage(); return; }
  };
  

  let source_str = match args.next() {
  	Some(x) => x.clone(),
  	_ => { usage(); return; }
  };

  // ungracefully many unwrap()s that can panic!
  // but given time-constraints, just opt for this now
  
  let source = path::Path::new(&source_str);
  let parent = source.parent().unwrap();
  let name = source.file_name().unwrap().to_str().unwrap();
  
  let mut folder : String = String::new();
  folder.push_str(name); 
  folder.push_str("_chunks");
  {
  	let dir = parent.join(&folder).to_str().unwrap();
    fs::create_dir(dir);
  }
}