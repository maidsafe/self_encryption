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


extern crate self_encryption;
extern crate rand;
extern crate tempdir;
extern crate docopt;
extern crate rustc_serialize;
extern crate cbor;

use std::fmt;
use std::fs;
use std::fs::{File};
use std::io::prelude::*;
use std::path::Path;
use std::string::String;
use std::error::Error;
use std::sync::Arc;

use docopt::Docopt;
use cbor::{ Encoder, Decoder};

use self_encryption::*;

// basic_encryptor -e filename
// basic_encryptor -d datamap destination
// basic_encryptor -h | --help
static USAGE: &'static str = "
Usage: basic_encryptor -h
       basic_encryptor -e <target>
       basic_encryptor -d <target> <dest>

Options:
    -h, --help      This message.
    -e, --encrypt   encrypt a file.
    -d, --decrypt   decrypt a file,
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_target: Option<String>,
    arg_dest: Option<String>,
    flag_encrypt: bool,
    flag_decrypt: bool,
    flag_help: bool,
}


fn to_hex(ch: u8) -> String {
    let hex = fmt::format(format_args!("{:x}", ch));
    if hex.len() == 1 {
        let s = "0".to_string();
        s + &hex
    } else {
        hex
    }
}

fn file_name(name: &Vec<u8>) -> String {
    let mut string = String::new();
    for i in 0..name.len() {
        string.push_str(&to_hex(name[i]));
    }
    string
}

pub struct MyStorage {
    pub storage_path : String
}

impl Storage for MyStorage {
  fn get(&self, name: Vec<u8>) -> Vec<u8> {
    let pathstr = file_name(&name);
    let tmpname = self.storage_path.clone() + &pathstr;
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

    fn put(&self, name: Vec<u8>, data: Vec<u8>) {
    let pathstr = file_name(&name);
    let tmpname = self.storage_path.clone() + &pathstr;
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

    match fs::create_dir(&Path::new("chunk_store_test")) {
        Err(why) => println!("! chunk_store_test {:?}", why.kind()),
        Ok(_) => {},
    }
    let my_storage = Arc::new(MyStorage { storage_path : "chunk_store_test/".to_string() });
    
    if args.flag_encrypt && args.arg_target.is_some() {
        let mut file = match File::open(&args.arg_target.clone().unwrap()) {
              Err(_) => panic!("couldn't open {}", args.arg_target.clone().unwrap()),
              Ok(f) => f,
            };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
        se.write(&data, 0);
        let data_map = se.close();
        let mut file = match File::create("data_map") {
            Err(_) => panic!("couldn't create data_map"),
            Ok(f) => f
        };
        let mut encoded = Encoder::from_memory();
        encoded.encode(&[&data_map]).unwrap();
        match file.write_all(&encoded.as_bytes()[..]) {
            Err(_) => panic!("couldn't write "),
            Ok(_) => println!("chunk  written")
        };
    }
    if args.flag_decrypt && args.arg_target.is_some() && args.arg_dest.is_some() {
        let mut file = match File::open(&args.arg_target.clone().unwrap()) {
              Err(_) => panic!("couldn't open {}", args.arg_target.clone().unwrap()),
              Ok(f) => f,
            };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        let mut d = Decoder::from_bytes(data);
        let data_map : datamap::DataMap = d.decode().next().unwrap().unwrap();

        let mut se = SelfEncryptor::new(my_storage.clone(), data_map);
        let length = se.len();
        let mut file = match File::create(&args.arg_dest.clone().unwrap()) {
            Err(_) => panic!("couldn't create {}", args.arg_dest.clone().unwrap()),
            Ok(f) => f
        };
        match file.write_all(&se.read(0, length)[..]) {
            Err(_) => panic!("couldn't write "),
            Ok(_) => println!("chunk  written")
        };
    }
}
