// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    decrypt_full_set, decrypt_range, encrypt, get_chunk_size, get_num_chunks, overlapped_chunks,
    seek_info, test_helpers::random_bytes, DataMap, EncryptedChunk, Error, StreamSelfDecryptor,
    StreamSelfEncryptor, MIN_ENCRYPTABLE_BYTES,
};
use bytes::Bytes;
use itertools::Itertools;
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
            index: chunk_info.index,
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
    for i in 1..15 {
        let file_size = i * MIN_ENCRYPTABLE_BYTES;

        for divisor in 2..15 {
            let len = file_size / divisor;
            let data = random_bytes(file_size);
            let (data_map, encrypted_chunks) = encrypt_chunks(data.clone())?;

            // Read first part
            let read_data_1 = {
                let pos = 0;
                seek(data.clone(), &data_map, &encrypted_chunks, pos, len)?
            };

            // Read second part
            let read_data_2 = {
                let pos = len;
                seek(data.clone(), &data_map, &encrypted_chunks, pos, len)?
            };

            // Join parts
            let read_data: Bytes = [read_data_1, read_data_2]
                .iter()
                .flat_map(|bytes| bytes.clone())
                .collect();

            compare(data.slice(0..(2 * len)), read_data)?
        }
    }

    Ok(())
}

fn seek(
    bytes: Bytes,
    data_map: &DataMap,
    encrypted_chunks: &[EncryptedChunk],
    pos: usize,
    len: usize,
) -> Result<Bytes, Error> {
    let expected_data = bytes.slice(pos..(pos + len));
    let info = seek_info(data_map.file_size(), pos, len);

    // select a subset of chunks; the ones covering the bytes we want to read
    let subset: Vec<_> = encrypted_chunks
        .iter()
        .filter(|c| c.index >= info.index_range.start && c.index <= info.index_range.end)
        .sorted_by_key(|c| c.index)
        .cloned()
        .collect();

    let read_data = decrypt_range(data_map, &subset, info.relative_pos, len)?;

    compare(expected_data, read_data.clone())?;

    Ok(read_data)
}

#[test]
fn seek_over_chunk_limit() -> Result<(), Error> {
    // Having first chunk being at index 1 starts at position: 4_194_304
    let start_size = 4_194_300;
    for i in 0..27 {
        let file_size = start_size + i;
        let bytes = random_bytes(file_size);

        let pos = file_size / 4;
        let len = file_size / 2;

        // this is what we expect to get back from the chunks
        let expected_data = bytes.slice(pos..(pos + len));

        // the chunks covering the bytes we want to read
        let (start_index, end_index) = overlapped_chunks(file_size, pos, len);

        // first encrypt the whole file
        let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;

        // select a subset of chunks; the ones covering the bytes we want to read
        let subset: Vec<_> = encrypted_chunks
            .into_iter()
            .filter(|c| c.index >= start_index && c.index <= end_index)
            .sorted_by_key(|c| c.index)
            .collect();

        // the start position within the first chunk (thus `relative`..)
        let relative_pos = pos % get_chunk_size(file_size, start_index);
        let read_data = decrypt_range(&data_map, &subset, relative_pos, len)?;

        compare(expected_data, read_data)?;
    }

    Ok(())
}

#[test]
fn seek_with_length_over_data_size() -> Result<(), Error> {
    let file_size = 10_000_000;
    let mut bytes = random_bytes(file_size);
    let start_pos = 512;
    // we'll call length to be just one more byte than data's length
    let len = bytes.len() - start_pos + 1;

    // the chunks covering the bytes we want to read
    let (start_index, end_index) = overlapped_chunks(file_size, start_pos, len);

    // first encrypt the whole file
    let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;

    // select a subset of chunks; the ones covering the bytes we want to read
    let subset: Vec<_> = encrypted_chunks
        .into_iter()
        .filter(|c| c.index >= start_index && c.index <= end_index)
        .sorted_by_key(|c| c.index)
        .collect();

    // this is what we expect to get back from the chunks
    let expected_data = bytes.split_off(start_pos);

    let read_data = decrypt_range(&data_map, &subset, start_pos, len)?;
    compare(expected_data, read_data)?;

    let read_data = decrypt_range(&data_map, &subset, usize::MAX, 1)?;
    assert!(read_data.is_empty());

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
