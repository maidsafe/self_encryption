// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    decrypt_full_set, decrypt_range, encrypt, get_chunk_size, get_num_chunks, 
    test_helpers::random_bytes, DataMap, EncryptedChunk, Error, MIN_ENCRYPTABLE_BYTES,
};
use bytes::Bytes;



#[test]
fn write_and_read() -> Result<(), Error> {
    let file_size = 10_000_000;
    let bytes = random_bytes(file_size);

    let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;
    let raw_data = decrypt_full_set(&data_map, &encrypted_chunks)?;

    compare(bytes, raw_data)
}

#[test]
fn get_chunk_sizes() -> Result<(), Error> {
    let file_size = 969_265;

    assert_eq!(323088, get_chunk_size(file_size, 0));
    assert_eq!(323088, get_chunk_size(file_size, 1));
    assert_eq!(323089, get_chunk_size(file_size, 2));

    let file_size = 1024;

    assert_eq!(341, get_chunk_size(file_size, 0));
    assert_eq!(341, get_chunk_size(file_size, 1));
    assert_eq!(342, get_chunk_size(file_size, 2));

    let file_size = 1025;

    assert_eq!(341, get_chunk_size(file_size, 0));
    assert_eq!(341, get_chunk_size(file_size, 1));
    assert_eq!(343, get_chunk_size(file_size, 2));

    Ok(())
}

#[test]
fn seek_and_join() -> Result<(), Error> {
    // Create a file that's exactly 3 chunks in size
    let file_size = 3 * MIN_ENCRYPTABLE_BYTES;
    let original_data = random_bytes(file_size);

    // Encrypt the data into chunks
    let (data_map, encrypted_chunks) = encrypt_chunks(original_data.clone())?;

    // Get the size of each chunk
    let chunk_size = get_chunk_size(file_size, 0);

    // Read the first two chunks (0 and 1)
    let first_chunk = decrypt_range(&data_map, &encrypted_chunks, 0, chunk_size)?;
    let second_chunk = decrypt_range(&data_map, &encrypted_chunks, chunk_size, chunk_size)?;

    // Verify each chunk size
    assert_eq!(
        first_chunk.len(),
        chunk_size,
        "First chunk has incorrect size"
    );
    assert_eq!(
        second_chunk.len(),
        chunk_size,
        "Second chunk has incorrect size"
    );

    // Join the chunks
    let mut combined = Vec::with_capacity(2 * chunk_size);
    combined.extend_from_slice(&first_chunk);
    combined.extend_from_slice(&second_chunk);
    let combined = Bytes::from(combined);

    // Verify against original data
    let expected = original_data.slice(0..2 * chunk_size);
    assert_eq!(combined.len(), expected.len(), "Combined length mismatch");
    compare(expected, combined)?;

    Ok(())
}

#[test]
fn seek_with_length_over_data_size() -> Result<(), Error> {
    let file_size = 10_000_000;
    let bytes = random_bytes(file_size);
    let start_pos = 512;

    // Calculate length safely
    let remaining_bytes = file_size.saturating_sub(start_pos);
    let len = remaining_bytes.saturating_add(1); // Try to read one more byte than available

    let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;

    // We expect to get data from start_pos to end of file
    let expected_data = bytes.slice(start_pos..file_size);

    let read_data = decrypt_range(&data_map, &encrypted_chunks, start_pos, len)?;
    compare(expected_data, read_data)?;

    // Also verify reading beyond end returns empty
    let read_data = decrypt_range(&data_map, &encrypted_chunks, file_size + 1, 1)?;
    assert!(
        read_data.is_empty(),
        "Reading beyond end should return empty"
    );

    Ok(())
}

#[test]
fn seek_over_chunk_limit() -> Result<(), Error> {
    let start_size = 4_194_300;
    for i in 0..5 {
        // Reduced iterations
        let file_size = start_size + i;
        let bytes = random_bytes(file_size);
        let pos = file_size / 4;
        let len = std::cmp::min(file_size / 2, file_size - pos); // Ensure we don't read past end

        let expected_data = bytes.slice(pos..(pos + len));
        let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;

        let read_data = decrypt_range(&data_map, &encrypted_chunks, pos, len)?;
        compare(expected_data, read_data)?;
    }
    Ok(())
}

fn compare(original: Bytes, result: Bytes) -> Result<(), Error> {
    assert_eq!(original.len(), result.len());

    for (counter, (a, b)) in original.into_iter().zip(result).enumerate() {
        if a != b {
            return Err(Error::Generic(format!("Not equal! Counter: {}", counter)));
        }
    }
    Ok(())
}

fn encrypt_chunks(bytes: Bytes) -> Result<(DataMap, Vec<EncryptedChunk>), Error> {
    let num_chunks = get_num_chunks(bytes.len());
    let (data_map, encrypted_chunks) = encrypt(bytes)?;

    assert_eq!(num_chunks, encrypted_chunks.len());

    Ok((data_map, encrypted_chunks))
}
