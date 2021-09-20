// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    decrypt_full_set, decrypt_range, encrypt, get_chunk_size, get_num_chunks, overlapped_chunks,
    seek_info, test_helpers::random_bytes, DataMap, EncryptedChunk, Error, MIN_ENCRYPTABLE_BYTES,
};
use bytes::Bytes;
use itertools::Itertools;

#[test]
fn write_and_read() -> Result<(), Error> {
    let file_size = 10_000_000;
    let bytes = random_bytes(file_size);

    let (data_map, encrypted_chunks) = encrypt_chunks(bytes.clone())?;
    let raw_data = decrypt_full_set(&data_map, &encrypted_chunks)?;

    compare(bytes, raw_data)
}

/// this test is now superseded by `seek_and_join`
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
