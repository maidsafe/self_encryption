// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Basic example usage of a `SelfEncryptor`.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy))]

extern crate docopt;
extern crate futures;
extern crate maidsafe_utilities;
extern crate rustc_serialize;
extern crate self_encryption;
#[macro_use]
extern crate unwrap;

use docopt::Docopt;
use futures::Future;
use maidsafe_utilities::serialisation;
use self_encryption::{DataMap, SelfEncryptor, Storage, StorageError};
use std::env;
use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::io::Error as IoError;
use std::path::PathBuf;
use std::string::String;

#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage: basic_encryptor -h
       basic_encryptor -e <target>
       basic_encryptor -d <destination>

Options:
    -h, --help      Display this message.
    -e, --encrypt   Encrypt a file.
    -d, --decrypt   Decrypt a file.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_target: Option<String>,
    arg_destination: Option<String>,
    flag_encrypt: bool,
    flag_decrypt: bool,
    flag_help: bool,
}


fn to_hex(ch: u8) -> String {
    fmt::format(format_args!("{:02x}", ch))
}

fn file_name(name: &[u8]) -> String {
    let mut string = String::new();
    for ch in name {
        string.push_str(&to_hex(*ch));
    }
    string
}

#[derive(Debug)]
struct DiskBasedStorageError {
    io_error: IoError,
}

impl Display for DiskBasedStorageError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "I/O error getting/putting: {}", self.io_error)
    }
}

impl StdError for DiskBasedStorageError {
    fn description(&self) -> &str {
        "DiskBasedStorage Error"
    }
}

impl From<IoError> for DiskBasedStorageError {
    fn from(error: IoError) -> DiskBasedStorageError {
        DiskBasedStorageError { io_error: error }
    }
}

impl StorageError for DiskBasedStorageError {}

struct DiskBasedStorage {
    pub storage_path: String,
}

impl DiskBasedStorage {
    fn calculate_path(&self, name: &[u8]) -> PathBuf {
        let mut path = PathBuf::from(self.storage_path.clone());
        path.push(file_name(name));
        path
    }
}

impl Storage for DiskBasedStorage {
    type Error = DiskBasedStorageError;

    fn get(&self, name: &[u8])
           -> Box<Future<Item=Vec<u8>, Error=DiskBasedStorageError>> {
        let path = self.calculate_path(name);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) => return futures::failed(From::from(error)).boxed()
        };
        let mut data = Vec::new();
        let result = file.read_to_end(&mut data)
                         .map(move |_| data)
                         .map_err(From::from);
        futures::done(result).boxed()
    }

    fn put(&mut self, name: Vec<u8>, data: Vec<u8>)
           -> Box<Future<Item=(), Error=DiskBasedStorageError>> {
        let path = self.calculate_path(&name);
        let mut file = match File::create(&path) {
            Ok(file) => file,
            Err(error) => return futures::failed(From::from(error)).boxed()
        };

        let result = file.write_all(&data[..])
                         .map(|_| {
                            println!("Chunk written to {:?}", path);
                        }).map_err(From::from);
        futures::done(result).boxed()
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());
    if args.flag_help {
        println!("{:?}", args)
    }

    let mut chunk_store_dir = env::temp_dir();
    chunk_store_dir.push("chunk_store_test/");
    let _ = fs::create_dir(chunk_store_dir.clone());
    let mut storage = DiskBasedStorage {
        storage_path: unwrap!(chunk_store_dir.to_str()).to_owned()
    };

    let mut data_map_file = chunk_store_dir;
    data_map_file.push("data_map");

    if args.flag_encrypt && args.arg_target.is_some() {
        if let Ok(mut file) = File::open(unwrap!(args.arg_target.clone())) {
            match file.metadata() {
                Ok(metadata) => {
                    if metadata.len() > self_encryption::MAX_FILE_SIZE as u64 {
                        return println!("File size too large {} is greater than 1GB",
                                        metadata.len());
                    }
                }
                Err(error) => return println!("{}", error.description().to_string()),
            }

            let mut data = Vec::new();
            match file.read_to_end(&mut data) {
                Ok(_) => (),
                Err(error) => return println!("{}", error.description().to_string()),
            }

            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("Encryptor construction shouldn't fail.");
            se.write(&data, 0).wait().expect("Writing to encryptor shouldn't fail.");
            let (data_map, old_storage) = se.close().wait().expect("Closing encryptor shouldn't fail.");
            storage = old_storage;

            match File::create(data_map_file.clone()) {
                Ok(mut file) => {
                    let encoded = unwrap!(serialisation::serialise(&data_map));
                    match file.write_all(&encoded[..]) {
                        Ok(_) => println!("Data map written to {:?}", data_map_file),
                        Err(error) => {
                            println!("Failed to write data map to {:?} - {:?}",
                                     data_map_file,
                                     error);
                        }
                    }
                }
                Err(error) => {
                    println!("Failed to create data map at {:?} - {:?}",
                             data_map_file,
                             error);
                }
            }
        } else {
            println!("Failed to open {}", unwrap!(args.arg_target.clone()));
        }
    }

    if args.flag_decrypt && args.arg_destination.is_some() {
        if let Ok(mut file) = File::open(data_map_file.clone()) {
            let mut data = Vec::new();
            let _ = unwrap!(file.read_to_end(&mut data));

            if let Ok(data_map) = serialisation::deserialise::<DataMap>(&data) {
                let se = SelfEncryptor::new(storage, data_map)
                    .expect("Encryptor construction shouldn't fail.");
                let length = se.len();
                if let Ok(mut file) = File::create(unwrap!(args.arg_destination.clone())) {
                    let content = se.read(0, length)
                        .wait()
                        .expect("Reading from encryptor shouldn't fail.");
                    match file.write_all(&content[..]) {
                        Err(error) => println!("File write failed - {:?}", error),
                        Ok(_) => {
                            println!("File decrypted to {:?}",
                                     unwrap!(args.arg_destination.clone()))
                        }
                    };
                } else {
                    println!("Failed to create {}",
                             unwrap!(args.arg_destination.clone()));
                }
            } else {
                println!("Failed to parse data map - possible corruption");
            }
        } else {
            println!("Failed to open data map at {:?}", data_map_file);
        }
    }
}
