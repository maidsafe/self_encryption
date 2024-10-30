// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Basic example usage of a `SelfEncryptor`.

// For quick_error
#![recursion_limit = "256"]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(deny(warnings)))
)]
// Forbid some very bad patterns. Forbid is stronger than `deny`, preventing us from suppressing the
// lint with `#[allow(...)]` et-all.
#![forbid(
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    unsafe_code
)]
// Turn on some additional warnings to encourage good style.
#![warn(
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    clippy::unicode_not_nfc
)]

use bytes::Bytes;
use docopt::Docopt;
use rayon::prelude::*;
use self_encryption::{
    self, decrypt_full_set, encrypt, test_helpers, DataMap, EncryptedChunk, Error, Result,
};
use serde::Deserialize;
use std::{
    env,
    fmt::{self},
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    string::String,
    sync::Arc,
};
use xor_name::XorName;

#[rustfmt::skip]
static USAGE: &str = "
Usage: basic_encryptor -h
       basic_encryptor -e <target>
       basic_encryptor -d <target> <destination>

Options:
    -h, --help      Display this message.
    -e, --encrypt   Encrypt a file.
    -d, --decrypt   Decrypt a file.
";

#[derive(Debug, Deserialize)]
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

fn file_name(name: XorName) -> String {
    let mut string = String::new();
    for ch in name.0 {
        string.push_str(&to_hex(ch));
    }
    string
}

#[derive(Clone)]
struct DiskBasedStorage {
    pub(crate) storage_path: String,
}

impl DiskBasedStorage {
    fn calculate_path(&self, name: XorName) -> PathBuf {
        let mut path = PathBuf::from(self.storage_path.clone());
        path.push(file_name(name));
        path
    }

    fn get(&self, name: XorName) -> Result<Bytes, Error> {
        let path = self.calculate_path(name);
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        let _ = file.read_to_end(&mut data);
        Ok(Bytes::from(data))
    }

    fn put(&self, name: XorName, data: Bytes) -> Result<()> {
        let path = self.calculate_path(name);
        let mut file = File::create(&path)?;
        file.write_all(&data[..])
            .map(|_| {
                println!("Chunk written to {:?}", path);
            })
            .map_err(From::from)
    }
}

// use tokio to enable an async main func
#[tokio::main]
async fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    if args.flag_help {
        println!("{:?}", args)
    }

    let mut chunk_store_dir = env::temp_dir();
    chunk_store_dir.push("chunk_store_test/");
    let _ = fs::create_dir(chunk_store_dir.clone());
    let storage_path = chunk_store_dir.to_str().unwrap().to_owned();
    let storage = Arc::new(DiskBasedStorage { storage_path });

    let mut data_map_file = chunk_store_dir;
    data_map_file.push("data_map");

    if args.flag_encrypt && args.arg_target.is_some() {
        if let Ok(mut file) = File::open(args.arg_target.clone().unwrap()) {
            let mut data = Vec::new();
            match file.read_to_end(&mut data) {
                Ok(_) => (),
                Err(error) => return println!("{}", error),
            }

            let (data_map, encrypted_chunks) = encrypt(Bytes::from(data)).unwrap();

            let result = encrypted_chunks
                .par_iter()
                .enumerate()
                .map(|(_, c)| (c, storage.clone()))
                .map(|(c, store)| store.put(XorName::from_content(&c.content), c.content.clone()))
                .collect::<Vec<_>>();

            assert!(result.iter().all(|r| r.is_ok()));

            match File::create(data_map_file.clone()) {
                Ok(mut file) => {
                    let encoded = test_helpers::serialise(&data_map).unwrap();
                    match file.write_all(&encoded[..]) {
                        Ok(_) => println!("Data map written to {:?}", data_map_file),
                        Err(error) => {
                            println!(
                                "Failed to write data map to {:?} - {:?}",
                                data_map_file, error
                            );
                        }
                    }
                }
                Err(error) => {
                    println!(
                        "Failed to create data map at {:?} - {:?}",
                        data_map_file, error
                    );
                }
            }
        } else {
            println!("Failed to open {}", args.arg_target.clone().unwrap());
        }
    }

    if args.flag_decrypt && args.arg_target.is_some() && args.arg_destination.is_some() {
        if let Ok(mut file) = File::open(args.arg_target.clone().unwrap()) {
            let mut data = Vec::new();
            let _ = file.read_to_end(&mut data).unwrap();
            match test_helpers::deserialise::<DataMap>(&data) {
                Ok(data_map) => {
                    let (keys, encrypted_chunks) = data_map
                        .infos()
                        .par_iter()
                        .map(|key| {
                            Ok::<(_, _), Error>((
                                key.clone(),
                                EncryptedChunk {
                                    content: storage.get(key.dst_hash)?,
                                },
                            ))
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .flatten()
                        .fold((vec![], vec![]), |(mut keys, mut chunks), (key, chunk)| {
                            keys.push(key);
                            chunks.push(chunk);
                            (keys, chunks)
                        });

                    if let Ok(mut file) = File::create(args.arg_destination.clone().unwrap()) {
                        let content =
                            decrypt_full_set(&DataMap::new(keys), encrypted_chunks.as_ref())
                                .unwrap();
                        match file.write_all(&content[..]) {
                            Err(error) => println!("File write failed - {:?}", error),
                            Ok(_) => {
                                println!("File decrypted to {:?}", args.arg_destination.unwrap())
                            }
                        };
                    } else {
                        println!("Failed to create {}", (args.arg_destination.unwrap()));
                    }
                }
                Err(_) => {
                    println!("Failed to parse data map - possible corruption");
                }
            }
        } else {
            println!("Failed to open data map at {:?}", data_map_file);
        }
    }
}
