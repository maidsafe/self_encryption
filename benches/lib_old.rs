// // Copyright 2018 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// // Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// // under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// // KIND, either express or implied. Please review the Licences for the specific language governing
// // permissions and limitations relating to use of the SAFE Network Software.

// // For explanation of lint checks, run `rustc -W help` or see
// // https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
// #![forbid(
//     bad_style,
//     arithmetic_overflow,
//     mutable_transmutes,
//     no_mangle_const_items,
//     unknown_crate_types
// )]
// #![deny(
//     deprecated,
//     improper_ctypes,
//     non_shorthand_field_patterns,
//     overflowing_literals,
//     stable_features,
//     unconditional_recursion,
//     unknown_lints,
//     unsafe_code,
//     unused,
//     unused_allocation,
//     unused_attributes,
//     unused_comparisons,
//     unused_features,
//     unused_parens,
//     while_true,
//     warnings
// )]
// #![warn(
//     trivial_casts,
//     trivial_numeric_casts,
//     unused_extern_crates,
//     unused_import_braces,
//     unused_qualifications,
//     variant_size_differences
// )]
// #![allow(
//     box_pointers,
//     missing_copy_implementations,
//     missing_debug_implementations
// )]

// use criterion::{BatchSize, Bencher, Criterion};
// use self_encryption::{
//     test_helpers::{new_test_rng, random_bytes, SimpleStorage},
//     DataMap, SelfEncryptor,
// };
// use std::time::Duration;

// // sample size is _NOT_ the number of times the command is run...
// // https://bheisler.github.io/criterion.rs/book/analysis.html#measurement
// const SAMPLE_SIZE: usize = 10;

// fn custom_criterion() -> Criterion {
//     Criterion::default().sample_size(SAMPLE_SIZE)
// }

// fn write(b: &mut Bencher<'_>, bytes_len: usize) {
//     b.iter_batched(
//         // the setup
//         || {
//             let mut rng = new_test_rng().unwrap();
//             let bytes = random_bytes(&mut rng, bytes_len);
//             let storage = Some(SimpleStorage::new());

//             (bytes, storage)
//         },
//         // actual benchmark
//         |(bytes, mut storage)| {
//             let waiters = async {
//                 let self_encryptor =
//                     SelfEncryptor::new(storage.take().unwrap(), DataMap::None).unwrap();
//                 self_encryptor.write(&bytes.clone(), 0).await.unwrap();
//                 storage = Some(self_encryptor.close().await.unwrap().1)
//             };

//             futures::executor::block_on(waiters);
//         },
//         BatchSize::SmallInput,
//     );
// }

// fn read(b: &mut Bencher, bytes_len: usize) {
//     b.iter_batched(
//         // the setup
//         || {
//             let mut rng = new_test_rng().unwrap();
//             let bytes = random_bytes(&mut rng, bytes_len);
//             let storage = SimpleStorage::new();
//             let self_encryptor = SelfEncryptor::new(storage, DataMap::None).unwrap();

//             let waiters = async {
//                 self_encryptor.write(&bytes, 0).await.unwrap();
//                 self_encryptor.close().await.unwrap()
//             };
//             let (data_map, storage) = futures::executor::block_on(waiters);
//             let storage = Some(storage);
//             (data_map, storage, bytes)
//         },
//         // actual benchmark
//         |(data_map, mut storage, bytes)| {
//             let self_encryptor = SelfEncryptor::new(storage.take().unwrap(), data_map).unwrap();
//             let the_waiter = async {
//                 let read_bytes = self_encryptor.read(0, bytes_len).await.unwrap();
//                 assert_eq!(read_bytes, bytes);
//             };
//             futures::executor::block_on(the_waiter);
//             futures::executor::block_on(self_encryptor.into_storage());
//         },
//         BatchSize::SmallInput,
//     );
// }

// fn main() {
//     let mut criterion = custom_criterion();
//     criterion = criterion.measurement_time(Duration::from_millis(20_000));

//     bench_encryptor(&mut criterion);
// }

// fn bench_encryptor(c: &mut Criterion) {
//     c.bench_function("write_200", |b| write(b, 200));
//     c.bench_function("write_1_kilobyte", |b| write(b, 1024));
//     c.bench_function("write_512_kilobytes", |b| write(b, 512 * 1024));
//     c.bench_function("write_1_megabyte", |b| write(b, 1024 * 1024));
//     c.bench_function("write_3_megabytes", |b| write(b, 3 * 1024 * 1024));
//     c.bench_function("write_10_megabytes", |b| write(b, 10 * 1024 * 1024));
//     c.bench_function("write_100_megabytes", |b| write(b, 100 * 1024 * 1024));

//     c.bench_function("read_200", |b| read(b, 200));

//     c.bench_function("read_1_kilobyte", |b| read(b, 1024));
//     c.bench_function("read_512_kilobytes", |b| read(b, 512 * 1024));
//     c.bench_function("read_1_megabyte", |b| read(b, 1024 * 1024));
//     c.bench_function("read_3_megabytes", |b| read(b, 3 * 1024 * 1024));
//     c.bench_function("read_10_megabytes", |b| read(b, 10 * 1024 * 1024));
//     c.bench_function("read_100_megabytes", |b| read(b, 100 * 1024 * 1024));
// }
