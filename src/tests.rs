// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    decrypt_full_set, decrypt_range, encrypt, get_chunk_size, get_num_chunks, overlapped_chunks,
    test_helpers::random_bytes, EncryptedChunk, Error, SecretKey,
};
use bytes::Bytes;
use itertools::Itertools;

#[test]
fn write_and_read() -> Result<(), Error> {
    let file_size = 10_000_000;
    let bytes = random_bytes(file_size);

    let (secret_key, encrypted_chunks) = encrypt_chunks(bytes.clone())?;
    let raw_data = decrypt_full_set(&secret_key, &encrypted_chunks)?;

    compare(bytes, raw_data)
}

#[test]
fn seek() -> Result<(), Error> {
    // Having first chunk being at index 1 starts at position: 4_194_304
    let start_size = 4_194_300;
    for i in 0..27 {
        let file_size = start_size + i;
        let bytes = random_bytes(file_size);

        let pos = file_size / 4;
        let len = file_size / 2;
        // this is what we expect to get back from the chunks
        let expected_data = bytes.slice(pos..len);
        // the chunks covering the bytes we want to read
        let (start_index, end_index) = overlapped_chunks(file_size, pos, len);

        // first encrypt the whole file
        let (secret_key, encrypted_chunks) = encrypt_chunks(bytes.clone())?;

        // select a subset of chunks; the ones covering the bytes we want to read
        let subset: Vec<_> = encrypted_chunks
            .into_iter()
            .filter(|c| c.index >= start_index && c.index <= end_index)
            .sorted_by_key(|c| c.index)
            .collect();

        // the start position within the first chunk (thus `relative`..)
        let relative_pos = pos % get_chunk_size(file_size, start_index);
        let read_data = decrypt_range(&secret_key, &subset, relative_pos, len)?;

        compare(expected_data, read_data)?;
    }

    Ok(())
}

fn compare(original: Bytes, result: Bytes) -> Result<(), Error> {
    for (counter, (a, b)) in original.into_iter().zip(result).enumerate() {
        if a != b {
            return Err(Error::Generic(format!("Not equal! Counter: {}", counter)));
        }
    }
    Ok(())
}

fn encrypt_chunks(bytes: Bytes) -> Result<(SecretKey, Vec<EncryptedChunk>), Error> {
    let num_chunks = get_num_chunks(bytes.len());
    let (secret_key, encrypted_chunks) = encrypt(bytes)?;

    assert_eq!(num_chunks, encrypted_chunks.len());

    Ok((secret_key, encrypted_chunks))
}
