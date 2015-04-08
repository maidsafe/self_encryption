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
// use of the MaidSafe Software.

extern crate self_encryption;
extern crate rand;
extern crate tempdir;
extern crate docopt;
extern crate rustc_serialize;
use docopt::Docopt;
use std::fs;
use std::fs::{File};
use std::io::prelude::*;
use std::path::Path;
use self_encryption::*;
use std::string::String;
use std::error::Error;
// use serialize::json;
// TODO wait for stabalisation on Beta channel
// Write the Docopt usage string.
static USAGE: &'static str = "
Usage: basic_encryptor -e filename
       basic_encryptor -d datamap destination
       basic_encryptor -h | --help

Options:
    -h, --help      This message.
    -e, --encrypt   encrypt a file.
    -d, --decrypt   decrypt a file,
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_filename: String,
    arg_destination: String,
    arg_datamap: String,
    flag_encrypt: bool,
    flag_decrypt: bool,
    flag_help: bool,
}


pub struct MyStorage;

impl Storage for MyStorage {
  fn get(&self, name: Vec<u8>) -> Vec<u8> {
    let pathstr = match String::from_utf8(name) {
      Err(_) => panic!("couldn't open file"),
        Ok(file) => file,
    };
    let tmpname = "chunk_store_test/".to_string() + &pathstr;
    let path = Path::new(&tmpname);
    let display = path.display();
    let mut file = match File::open(&path) {
      Err(_) => panic!("couldn't open {}", display),
        Ok(f) => f,
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    data
  }

    fn put(&mut self, name: Vec<u8>, data: Vec<u8>) {
    let pathstr = match String::from_utf8(name) {
      Err(_) => panic!("couldn't open file"),
        Ok(file) =>  file
    }; 
    let tmpname = "chunk_store_test/".to_string() + &pathstr;
    let path = Path::new(&tmpname);
    let mut file = match File::create(&path) {
           Err(_) => panic!("couldn't create"),
           Ok(f) => f 
    }; 
           
    match file.write_all(&data[..]) {
             Err(_) => panic!("couldn't write "),
             Ok(_) => println!("chunk  written")
        };
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());
    if args.flag_help { println!("{:?}", args) }

    println!("{:?}", args);


    match fs::create_dir(&Path::new("chunk_store_test")) {
        Err(why) => println!("! {:?}", why.kind()),
        Ok(_) => {},
    }
    let mut my_storage = MyStorage;
    
    if args.flag_encrypt && args.arg_filename != "" {
        let mut se = SelfEncryptor::new(&mut my_storage, datamap::DataMap::None);
        let mut file = match File::open(&args.arg_filename) {
              Err(_) => panic!("couldn't open {}", args.arg_filename),
              Ok(f) => f,
            };
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
      
    se.write(&data, 0);
    // let data_map = se.close();
    
    // let mut file = match File::create("data_map") {
    //        Err(_) => panic!("couldn't create data_map"),
    //        Ok(f) => f 
    // }; 
// Todo - will force nightly as json unstable so park for a couple of weeks
  //  let encoded =  json::encode(&data_map).unwrap();
    //        
    // match file.write_all(&enc.as_bytes()[..]) {
    //          Err(_) => panic!("couldn't write "),
    //          Ok(_) => println!("chunk  written")
    //     };
    }

    
    
   // let decrypted = se.read(read_position as u64, read_size as u64);

}
