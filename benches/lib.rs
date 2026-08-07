// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    deprecated,
    improper_ctypes,
    non_shorthand_field_patterns,
    overflowing_literals,
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
    while_true,
    warnings
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    variant_size_differences
)]
#![allow(missing_copy_implementations, missing_debug_implementations)]

use criterion::{BatchSize, Bencher, Criterion};
use self_encryption::{decrypt, encrypt, test_helpers::random_bytes};
use std::time::Duration;

// sample size is _NOT_ the number of times the command is run...
// https://bheisler.github.io/criterion.rs/book/analysis.html#measurement
const SAMPLE_SIZE: usize = 20;

fn custom_criterion() -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(40))
        .sample_size(SAMPLE_SIZE)
}

fn write(b: &mut Bencher<'_>, bytes_len: usize) {
    b.iter_batched(
        // the setup
        || random_bytes(bytes_len),
        // actual benchmark
        |bytes| {
            let (_data_map, _encrypted_chunks) = encrypt(bytes).unwrap();
        },
        BatchSize::SmallInput,
    );
}

fn read(b: &mut Bencher, bytes_len: usize) {
    b.iter_batched(
        // the setup
        || encrypt(random_bytes(bytes_len)).unwrap(),
        // actual benchmark
        |(data_map, encrypted_chunks)| {
            let _raw_data = decrypt(&data_map, &encrypted_chunks).unwrap();
        },
        BatchSize::SmallInput,
    );
}

fn main() {
    let mut criterion = custom_criterion();
    bench_encryptor(&mut criterion);
}

fn bench_encryptor(c: &mut Criterion) {
    c.bench_function("write_3_kilobytes", |b| write(b, 3 * 1024));
    c.bench_function("write_512_kilobytes", |b| write(b, 512 * 1024));
    c.bench_function("write_1_megabyte", |b| write(b, 1024 * 1024));
    c.bench_function("write_3_megabytes", |b| write(b, 3 * 1024 * 1024));
    c.bench_function("write_10_megabytes", |b| write(b, 10 * 1024 * 1024));
    c.bench_function("write_100_megabytes", |b| write(b, 100 * 1024 * 1024));

    c.bench_function("read_3_kilobytes", |b| read(b, 3 * 1024));
    c.bench_function("read_512_kilobytes", |b| read(b, 512 * 1024));
    c.bench_function("read_1_megabyte", |b| read(b, 1024 * 1024));
    c.bench_function("read_3_megabytes", |b| read(b, 3 * 1024 * 1024));
    c.bench_function("read_10_megabytes", |b| read(b, 10 * 1024 * 1024));
    c.bench_function("read_100_megabytes", |b| read(b, 100 * 1024 * 1024));
}
