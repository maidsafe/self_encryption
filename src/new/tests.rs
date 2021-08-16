// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::new::{
    decrypt::decrypt, encrypt::encrypt, get_num_chunks, hash::hashes, test_helpers::random_bytes,
    Error,
};
use itertools::Itertools;
use std::time::Instant;

#[test]
fn read_write() -> Result<(), Error> {
    let mb_100 = 100_000_000;

    run_test(mb_100)
}

fn run_test(data_size: usize) -> Result<(), Error> {
    let bytes = random_bytes(data_size);

    println!("Encrypting chunks..");

    let total_timer = Instant::now();

    let batch_timer = Instant::now();
    let batches = hashes(bytes.clone());
    let batch_time = batch_timer.elapsed();

    let encrypt_timer = Instant::now();
    let encrypted_chunks = encrypt(batches);
    let encrypt_time = encrypt_timer.elapsed();

    let total_time = total_timer.elapsed();

    println!(
        "Batch time: {}, encrypt time: {}, total: {}",
        batch_time.as_millis(),
        encrypt_time.as_millis(),
        total_time.as_millis()
    );

    let num_chunks = get_num_chunks(data_size);
    assert_eq!(num_chunks, encrypted_chunks.len());

    let encrypted_chunks = encrypted_chunks.into_iter().flatten().collect_vec();
    assert_eq!(num_chunks, encrypted_chunks.len());

    println!("Decrypting chunks..");

    let decrypt_timer = Instant::now();
    let raw_data = decrypt(&encrypted_chunks)?;
    let decrypt_time = decrypt_timer.elapsed();

    println!("Chunks decrypted in {} ms.", decrypt_time.as_millis());
    println!("Comparing results..");

    for (counter, (a, b)) in bytes.into_iter().zip(raw_data).enumerate() {
        if a != b {
            panic!("Not equal! Counter: {}", counter)
        }
    }

    Ok(())
}
