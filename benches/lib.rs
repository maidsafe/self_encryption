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

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

// the test names contain MB, KB which should retain capitalisation
#![feature(test)]

#[macro_use]
#[allow(unused_extern_crates)]  // Only using macros from maidsafe_utilites
extern crate maidsafe_utilities;
extern crate rand;
extern crate self_encryption;
extern crate test;

use test::Bencher;
use self_encryption::{DataMap, SelfEncryptor, Storage};
use std::sync::{Arc, Mutex};

// TODO: replace copy from src/lib.rs mod test to properly import and reuse

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(length);
    for _ in 0..length {
        bytes.push(rand::random::<u8>());
    }
    bytes
}

struct Entry {
    name: Vec<u8>,
    data: Vec<u8>,
}

struct MyStorage {
    entries: Arc<Mutex<Vec<Entry>>>,
}

impl MyStorage {
    pub fn new() -> MyStorage {
        MyStorage { entries: Arc::new(Mutex::new(Vec::new())) }
    }
}

impl Storage for MyStorage {
    fn get(&self, name: Vec<u8>) -> Vec<u8> {
        let lock = unwrap_result!(self.entries.lock());
        for entry in lock.iter() {
            if entry.name == name {
                return entry.data.to_vec();
            }
        }

        vec![]
    }

    fn put(&self, name: Vec<u8>, data: Vec<u8>) {
        let mut lock = unwrap_result!(self.entries.lock());
        lock.push(Entry {
            name: name,
            data: data,
        })
    }
}
// end of copy from src/lib.rs

#[bench]
fn write_then_read_200_bytes(b: &mut Bencher) {
    let my_storage = Arc::new(MyStorage::new());
    let bytes_len = 200;
    b.iter(|| {
        let data_map: DataMap;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            data_map = se.close();
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    });
    b.bytes = 2 * bytes_len;
}

#[bench]
fn write_then_read_1_kilobyte(b: &mut Bencher) {
    let my_storage = Arc::new(MyStorage::new());
    let bytes_len = 1024;
    b.iter(|| {
        let data_map: DataMap;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            data_map = se.close();
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    });
    b.bytes = 2 * bytes_len;
}

#[bench]
fn write_then_read_1_megabyte(b: &mut Bencher) {
    let my_storage = Arc::new(MyStorage::new());
    let bytes_len = 1024 * 1024;
    b.iter(|| {
        let data_map: DataMap;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            data_map = se.close();
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    });
    b.bytes = 2 * bytes_len;
}

#[bench]
fn write_then_read_3_megabytes(b: &mut Bencher) {
    let my_storage = Arc::new(MyStorage::new());
    let bytes_len = 3 * 1024 * 1024;
    b.iter(|| {
        let data_map: DataMap;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            data_map = se.close();
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    });
    b.bytes = 2 * bytes_len;
}

#[bench]
fn write_then_read_10_megabytes(b: &mut Bencher) {
    let my_storage = Arc::new(MyStorage::new());
    let bytes_len = 10 * 1024 * 1024;
    b.iter(|| {
        let data_map: DataMap;
        let the_bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(my_storage.clone(), DataMap::None);
            se.write(&the_bytes, 0);
            data_map = se.close();
        }
        let mut new_se = SelfEncryptor::new(my_storage.clone(), data_map);
        let fetched = new_se.read(0, bytes_len);
        assert_eq!(fetched, the_bytes);
    });
    b.bytes = 2 * bytes_len;
}

#[bench]
fn write_then_read_100_megabytes(b: &mut Bencher) {
    let storage = Arc::new(MyStorage::new());
    let bytes_len = 100 * 1024 * 1024;
    b.iter(|| {
        let data_map: DataMap;
        let bytes = random_bytes(bytes_len as usize);
        {
            let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
            se.write(&bytes, 0);
            data_map = se.close();
        }
        let mut se = SelfEncryptor::new(storage.clone(), data_map);
        let fetched = se.read(0, bytes_len);
        assert_eq!(fetched, bytes);
    });
    b.bytes = 2 * bytes_len;
}

#[bench]
fn write_then_read_range(b: &mut Bencher) {
    let storage = Arc::new(MyStorage::new());
    let string_range = vec![512 * 1024,
                            1 * 1024 * 1024,
                            2 * 1024 * 1024,
                            3 * 1024 * 1024,
                            4 * 1024 * 1024,
                            5 * 1024 * 1024,
                            6 * 1024 * 1024];
    for bytes_len in string_range {
        b.iter(|| {
            let data_map: DataMap;
            let the_bytes = random_bytes(bytes_len as usize);
            {
                let mut se = SelfEncryptor::new(storage.clone(), DataMap::None);
                se.write(&the_bytes, 0);
                data_map = se.close();
            }
            let mut new_se = SelfEncryptor::new(storage.clone(), data_map);
            let fetched = new_se.read(0, bytes_len);
            assert_eq!(fetched, the_bytes);
        });
        // write and read the data
        b.bytes = 2 * bytes_len;
    }
}
