// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{encrypt::encrypt, hash::hashes, DataReader, Error, FileReader, MemFileReader};
use crate::new::{
    get_num_chunks,
    test_helpers::{new_test_rng, random_bytes},
    Generator,
};
use bytes::Bytes;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn mem_reader() -> Result<(), Error> {
    let file_size = 3_000_000_000;

    let reader = get_mem_reader(file_size)?;

    run_test(file_size, reader)
}

#[test]
fn disk_reader() -> Result<(), Error> {
    let file_size = 30_000_000;

    let reader = get_disk_reader(file_size)?;

    run_test(file_size, reader)
}

fn run_test(file_size: usize, reader: impl DataReader) -> Result<(), Error> {
    assert_eq!(file_size, reader.size());

    let address_gen = Generator {};

    let total_timer = Instant::now();

    let batch_timer = Instant::now();
    let batches = hashes(reader, address_gen);
    let batch_time = batch_timer.elapsed();

    let encrypt_timer = Instant::now();
    let chunk_details = encrypt(batches);
    let encrypt_time = encrypt_timer.elapsed();

    let total_time = total_timer.elapsed();

    println!(
        "Batch time: {}, encrypt time: {}, total: {}",
        batch_time.as_millis(),
        encrypt_time.as_millis(),
        total_time.as_millis()
    );

    let num_chunks = get_num_chunks(file_size);
    assert_eq!(num_chunks, chunk_details.len());
    assert!(chunk_details.into_iter().all(|r| r.is_ok()));

    Ok(())
}

fn get_mem_reader(file_size: usize) -> Result<impl DataReader, Error> {
    let mut rng: rand_chacha::ChaCha20Rng = new_test_rng()?;
    let the_bytes = random_bytes(&mut rng, file_size);
    Ok(MemFileReader::new(Bytes::from(the_bytes)))
}

fn get_disk_reader(file_size: usize) -> Result<impl DataReader, Error> {
    let bytes = vec![0_u8; file_size];

    // Create a directory inside of `std::env::temp_dir()`.
    println!("Creating file of {} bytes..", file_size);
    let dir = tempdir()?;
    let file_path = dir.path().join("big-file.db");
    let file = std::fs::File::create(file_path.as_path())?;
    std::fs::write(file_path.as_path(), bytes)?;
    file.sync_all()?;
    println!("File created.");

    Ok(FileReader::new(file_path))
}
