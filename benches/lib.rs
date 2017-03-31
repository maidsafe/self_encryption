// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

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
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

#![feature(test)]

extern crate rand;
extern crate self_encryption;
extern crate test;

use rand::Rng;
use self_encryption::{DataMap, SelfEncryptor};
use self_encryption::test_helpers::SimpleStorage;
use test::Bencher;

fn random_bytes(size: usize) -> Vec<u8> {
    rand::thread_rng().gen_iter().take(size).collect()
}

fn write(bencher: &mut Bencher, bytes_len: u64) {
    let mut storage = SimpleStorage::new();
    let bytes = random_bytes(bytes_len as usize);
    bencher.iter(|| {
        let mut self_encryptor = SelfEncryptor::new(&mut storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        self_encryptor
            .write(&bytes, 0)
            .expect("Writing to encryptor shouldn't fail.");
        let _ = self_encryptor
            .close()
            .expect("Closing encryptor shouldn't fail.");
    });
    bencher.bytes = bytes_len;
}

fn read(bencher: &mut Bencher, bytes_len: u64) {
    let mut storage = SimpleStorage::new();
    let bytes = random_bytes(bytes_len as usize);
    let data_map: DataMap;
    {
        let mut self_encryptor = SelfEncryptor::new(&mut storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        self_encryptor
            .write(&bytes, 0)
            .expect("Writing to encryptor shouldn't fail.");
        data_map = self_encryptor
            .close()
            .expect("Closing encryptor shouldn't fail.");
    }
    bencher.iter(|| {
                     let mut self_encryptor = SelfEncryptor::new(&mut storage, data_map.clone())
                         .expect("Encryptor construction shouldn't fail.");
                     assert_eq!(self_encryptor
                                    .read(0, bytes_len)
                                    .expect("Reading from encryptor shouldn't fail."),
                                bytes);
                 });
    bencher.bytes = bytes_len;
}

#[bench]
fn write_200_bytes(bencher: &mut Bencher) {
    write(bencher, 200)
}

#[bench]
fn write_1_kilobyte(bencher: &mut Bencher) {
    write(bencher, 1024)
}

#[bench]
fn write_512_kilobytes(bencher: &mut Bencher) {
    write(bencher, 512 * 1024)
}

#[bench]
fn write_1_megabyte(bencher: &mut Bencher) {
    write(bencher, 1024 * 1024)
}

#[bench]
fn write_3_megabytes(bencher: &mut Bencher) {
    write(bencher, 3 * 1024 * 1024)
}

#[bench]
fn write_10_megabytes(bencher: &mut Bencher) {
    write(bencher, 10 * 1024 * 1024)
}

#[bench]
fn write_100_megabytes(bencher: &mut Bencher) {
    write(bencher, 100 * 1024 * 1024)
}

#[bench]
fn read_200_bytes(bencher: &mut Bencher) {
    read(bencher, 200)
}

#[bench]
fn read_1_kilobyte(bencher: &mut Bencher) {
    read(bencher, 1024)
}

#[bench]
fn read_512_kilobytes(bencher: &mut Bencher) {
    read(bencher, 512 * 1024)
}

#[bench]
fn read_1_megabyte(bencher: &mut Bencher) {
    read(bencher, 1024 * 1024)
}

#[bench]
fn read_3_megabytes(bencher: &mut Bencher) {
    read(bencher, 3 * 1024 * 1024)
}

#[bench]
fn read_10_megabytes(bencher: &mut Bencher) {
    read(bencher, 10 * 1024 * 1024)
}

#[bench]
fn read_100_megabytes(bencher: &mut Bencher) {
    read(bencher, 100 * 1024 * 1024)
}
