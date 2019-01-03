// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations
)]

extern crate futures;
extern crate rand;
extern crate self_encryption;
extern crate test;
#[macro_use]
extern crate unwrap;

use futures::Future;
use rand::Rng;
use self_encryption::test_helpers::SimpleStorage;
use self_encryption::{DataMap, SelfEncryptor};
use test::Bencher;

fn random_bytes(size: usize) -> Vec<u8> {
    rand::thread_rng().gen_iter().take(size).collect()
}

fn write(bencher: &mut Bencher, bytes_len: u64) {
    let bytes = random_bytes(bytes_len as usize);
    let mut storage = Some(SimpleStorage::new());

    bencher.iter(|| {
        let self_encryptor = unwrap!(SelfEncryptor::new(unwrap!(storage.take()), DataMap::None));
        unwrap!(self_encryptor.write(&bytes, 0).wait());
        storage = Some(unwrap!(self_encryptor.close().wait()).1);
    });
    bencher.bytes = bytes_len;
}

fn read(bencher: &mut Bencher, bytes_len: u64) {
    let bytes = random_bytes(bytes_len as usize);
    let (data_map, storage) = {
        let storage = SimpleStorage::new();
        let self_encryptor = unwrap!(SelfEncryptor::new(storage, DataMap::None));
        unwrap!(self_encryptor.write(&bytes, 0).wait());
        unwrap!(self_encryptor.close().wait())
    };

    let mut storage = Some(storage);

    bencher.iter(|| {
        let self_encryptor = unwrap!(SelfEncryptor::new(
            unwrap!(storage.take()),
            data_map.clone(),
        ));
        let read_bytes = unwrap!(self_encryptor.read(0, bytes_len).wait());
        assert_eq!(read_bytes, bytes);
        storage = Some(self_encryptor.into_storage());
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
