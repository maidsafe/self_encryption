// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    decrypt_full_set, decrypt_range, encrypt, get_chunk_size, get_num_chunks, seek_info,
    test_helpers::random_bytes, DataMap, EncryptedChunk, Error, StreamSelfDecryptor,
    StreamSelfEncryptor, MIN_ENCRYPTABLE_BYTES,
};
use bytes::Bytes;
use rand::prelude::SliceRandom;
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
};
use tempfile::tempdir;

#[test]
fn test_stream_self_encryptor() -> Result<(), Error> {
    // Create a 10MB temporary file
    let dir = tempdir()?;
    let file_path = dir.path().join("tempfile");
    let mut file = File::create(&file_path)?;
    let file_size = 10 * 1024 * 1024; // 10MB
    let data = random_bytes(file_size);
    file.write_all(&data)?;

    let chunk_path = dir.path().join("chunk_path");
    create_dir_all(chunk_path.clone())?;

    // Encrypt the file using StreamSelfEncryptor
    let mut encryptor =
        StreamSelfEncryptor::encrypt_from_file(file_path, Some(chunk_path.clone()))?;
    let mut encrypted_chunks = Vec::new();
    let mut data_map = None;
    while let Ok((chunk, map)) = encryptor.next_encryption() {
        if let Some(c) = chunk {
            encrypted_chunks.push(c);
        }
        if let Some(m) = map {
            // Returning a data_map means file encryption is completed.
            data_map = Some(m);
            break;
        }
    }
    let data_map = data_map.unwrap();

    // Shuffle the encrypted chunks
    let mut rng = rand::thread_rng();
    encrypted_chunks.shuffle(&mut rng);

    // Decrypt the shuffled chunks using StreamSelfDecryptor
    let decrypted_file_path = dir.path().join("decrypted");

    // Write something to the decrypted file first to simulate it's corrupted.
    {
        let mut file = File::create(&decrypted_file_path)?;
        let file_size = 1024; // 1KB
        let data = random_bytes(file_size);
        file.write_all(&data)?;
    }

    let mut decryptor =
        StreamSelfDecryptor::decrypt_to_file(decrypted_file_path.clone(), &data_map)?;
    for chunk in encrypted_chunks {
        let _ = decryptor.next_encrypted(chunk)?;
    }

    // Read the decrypted file and verify that its content matches the original data
    let mut decrypted_file = File::open(decrypted_file_path)?;
    let mut decrypted_data = Vec::new();
    let _ = decrypted_file.read_to_end(&mut decrypted_data)?;
    assert_eq!(data, decrypted_data);

    // Use the flushed encrypted chunks to recover the file and verify with the original data
    let mut flushed_encrypted_chunks = Vec::new();
    for chunk_info in data_map.infos() {
        let file_path = chunk_path.join(hex::encode(chunk_info.dst_hash));
        let mut chunk_file = File::open(file_path)?;
        let mut chunk_data = Vec::new();
        let _ = chunk_file.read_to_end(&mut chunk_data)?;
        flushed_encrypted_chunks.push(EncryptedChunk {
            content: chunk_data.into(),
        });
    }
    let decrypted_flushed_data = decrypt_full_set(&data_map, &flushed_encrypted_chunks)?;
    assert_eq!(data, decrypted_flushed_data);

    Ok(())
}

#[test]
fn write_and_read() -> Result<(), Error> {
    let file_size = 10_000_000;
    let bytes = random_bytes(file_size);

    let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;
    let raw_data = decrypt_full_set(&data_map, &encrypted_chunks)?;

    compare(bytes, raw_data)
}

#[test]
fn seek_indices() -> Result<(), Error> {
    let file_size = 3072;
    let pos = 0;
    let len = file_size / 2;

    let info = seek_info(file_size, pos, len);

    assert_eq!(0, info.relative_pos);
    assert_eq!(0, info.index_range.start);
    assert_eq!(1, info.index_range.end);

    let pos = len;
    let info = seek_info(file_size, pos, len);

    assert_eq!(512, info.relative_pos);
    assert_eq!(1, info.index_range.start);
    assert_eq!(2, info.index_range.end);

    let info = seek_info(file_size, pos, len + 1);

    assert_eq!(512, info.relative_pos);
    assert_eq!(1, info.index_range.start);
    assert_eq!(2, info.index_range.end);

    Ok(())
}

#[test]
fn seek_indices_on_medium_size_file() -> Result<(), Error> {
    let file_size = 969_265;
    let pos = 0;
    let len = 131072;

    let info = seek_info(file_size, pos, len);

    assert_eq!(0, info.relative_pos);
    assert_eq!(0, info.index_range.start);
    assert_eq!(0, info.index_range.end);

    let info = seek_info(file_size, 131072, len);

    assert_eq!(131072, info.relative_pos);
    assert_eq!(0, info.index_range.start);
    assert_eq!(0, info.index_range.end);

    let info = seek_info(file_size, 393216, len);

    assert_eq!(70128, info.relative_pos);
    assert_eq!(1, info.index_range.start);
    assert_eq!(1, info.index_range.end);

    let info = seek_info(file_size, 655360, len);

    assert_eq!(9184, info.relative_pos);
    assert_eq!(2, info.index_range.start);
    assert_eq!(2, info.index_range.end);

    Ok(())
}

#[test]
fn seek_indices_on_small_size_file() -> Result<(), Error> {
    let file_size = 1024;

    // first byte of index 0
    let info = seek_info(file_size, 0, 340);

    assert_eq!(0, info.relative_pos);
    assert_eq!(0, info.index_range.start);
    assert_eq!(0, info.index_range.end);

    // first byte of index 1
    let info = seek_info(file_size, 341, 340);

    assert_eq!(0, info.relative_pos);
    assert_eq!(1, info.index_range.start);
    assert_eq!(1, info.index_range.end);

    // first byte of index 2
    let info = seek_info(file_size, 682, 340);

    assert_eq!(0, info.relative_pos);
    assert_eq!(2, info.index_range.start);
    assert_eq!(2, info.index_range.end);

    // last byte of index 2
    let info = seek_info(file_size, file_size - 1, 1);

    assert_eq!(341, info.relative_pos);
    assert_eq!(2, info.index_range.start);
    assert_eq!(2, info.index_range.end);

    // overflow - should this error?
    let info = seek_info(file_size, file_size, 1);

    assert_eq!(1, info.relative_pos);
    assert_eq!(0, info.index_range.start);
    assert_eq!(0, info.index_range.end);

    // last byte of index 2 (as 2 remainders in last chunk)
    let info = seek_info(file_size + 1, file_size, 1);

    assert_eq!(342, info.relative_pos);
    assert_eq!(2, info.index_range.start);
    assert_eq!(2, info.index_range.end);

    Ok(())
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
