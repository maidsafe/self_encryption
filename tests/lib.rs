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
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
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
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

use rand::{self, seq::SliceRandom, Rng};
use self_encryption::{
    test_helpers::{new_test_rng, random_bytes, SimpleStorage},
    DataMap, SelfEncryptionError, SelfEncryptor, MAX_CHUNK_SIZE,
};

const DATA_SIZE: usize = 20 * 1024 * 1024;

#[tokio::test]
async fn new_read() -> Result<(), SelfEncryptionError> {
    let read_size: usize = 4096;
    let mut read_position: usize = 0;
    let content_len: usize = 4 * MAX_CHUNK_SIZE;
    let storage = SimpleStorage::new();
    let mut rng = new_test_rng()?;
    let original = random_bytes(&mut rng, content_len);
    {
        let se = SelfEncryptor::new(storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        se.write(&original, 0)
            .await
            .expect("Writing to encryptor shouldn't fail.");
        {
            let mut decrypted = se
                .read(read_position, read_size)
                .await
                .expect("Reading part one from encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );

            // read next small part
            read_position += read_size;
            decrypted = se
                .read(read_position, read_size)
                .await
                .expect("Reading part two from encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );

            // try to read from end of file, moving the sliding window
            read_position = content_len - 3 * read_size;
            decrypted = se
                .read(read_position, read_size)
                .await
                .expect("Reading past end of encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );

            // read again at beginning of file
            read_position = 5usize;
            decrypted = se
                .read(read_position, read_size)
                .await
                .expect("Reading from start of encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );
        }

        {
            // Finish with many small reads
            let mut decrypted: Vec<u8> = Vec::with_capacity(content_len);
            read_position = 0usize;
            for i in 0..15 {
                decrypted.extend(
                    se.read(read_position, read_size)
                        .await
                        .unwrap_or_else(|_| {
                            panic!("Reading attempt {} from encryptor shouldn't fail", i)
                        })
                        .iter()
                        .cloned(),
                );
                assert_eq!(original[0..(read_position + read_size)].to_vec(), decrypted);
                read_position += read_size;
            }
        }
        let _ = se.close().await.expect("Closing encryptor shouldn't fail.");
    }
    Ok(())
}

#[tokio::test]
async fn write_and_close_random_sizes_at_random_positions() -> Result<(), SelfEncryptionError> {
    let mut rng = new_test_rng()?;
    let mut storage = SimpleStorage::new();
    let max_broken_size = 20 * 1024;
    let original = random_bytes(&mut rng, DATA_SIZE);
    // estimate number of broken pieces, not known in advance
    let mut broken_data: Vec<(usize, &[u8])> = Vec::with_capacity(DATA_SIZE / max_broken_size);

    let mut offset = 0;
    let mut last_piece = 0;
    while offset < DATA_SIZE {
        let size;
        if DATA_SIZE - offset < max_broken_size {
            size = DATA_SIZE - offset;
            last_piece = offset;
        } else {
            size = rand::random::<usize>() % max_broken_size;
        }
        let piece: (usize, &[u8]) = (offset, &original[offset..(offset + size)]);
        broken_data.push(piece);
        offset += size;
    }

    {
        let slice_broken_data = &mut broken_data[..];
        slice_broken_data.shuffle(&mut rng);
    }

    match broken_data.iter().filter(|&x| x.0 != last_piece).last() {
        None => panic!("Should never occur. Error in test itself."),
        Some(overlap) => {
            let mut extra: Vec<u8> = overlap.1.to_vec();
            extra.extend(random_bytes(&mut rng, 7usize)[..].iter().cloned());
            let post_overlap: (usize, &[u8]) = (overlap.0, &mut extra[..]);
            let post_position = overlap.0 + overlap.1.len();
            let mut wtotal = 0;
            let mut data_map_orig = DataMap::None;
            for element in &broken_data {
                let se = SelfEncryptor::new(storage, data_map_orig)
                    .expect("Encryptor construction shouldn't fail.");
                se.write(element.1, element.0)
                    .await
                    .expect("Writing broken data to encryptor shouldn't fail.");
                wtotal += element.1.len();
                let (data_map, storage_tmp) = se
                    .close()
                    .await
                    .expect("Closing broken data to encryptor shouldn't fail.");
                data_map_orig = data_map;
                storage = storage_tmp;
            }
            assert_eq!(wtotal, DATA_SIZE);
            let se = SelfEncryptor::new(storage, data_map_orig)
                .expect("Encryptor construction shouldn't fail.");
            let mut decrypted = se
                .read(0, DATA_SIZE)
                .await
                .expect("Reading broken data from encryptor shouldn't fail.");
            assert_eq!(original, decrypted);

            let mut overwrite = original[0..post_overlap.0].to_vec();
            overwrite.extend((post_overlap.1).to_vec().iter().cloned());
            overwrite.extend(original[post_position + 7..DATA_SIZE].iter().cloned());
            se.write(post_overlap.1, post_overlap.0)
                .await
                .expect("Writing overlap to encryptor shouldn't fail.");
            decrypted = se
                .read(0, DATA_SIZE)
                .await
                .expect("Reading all data from encryptor shouldn't fail.");
            assert_eq!(overwrite.len(), decrypted.len());
            assert_eq!(overwrite, decrypted);
        }
    }
    Ok(())
}

#[tokio::test]
async fn write_random_sizes_at_random_positions() -> Result<(), SelfEncryptionError> {
    let mut rng = new_test_rng()?;
    let storage = SimpleStorage::new();
    let max_broken_size = 20 * 1024;
    let original = random_bytes(&mut rng, DATA_SIZE);
    // estimate number of broken pieces, not known in advance
    let mut broken_data: Vec<(usize, &[u8])> = Vec::with_capacity(DATA_SIZE / max_broken_size);

    let mut offset = 0;
    let mut last_piece = 0;
    while offset < DATA_SIZE {
        let size;
        if DATA_SIZE - offset < max_broken_size {
            size = DATA_SIZE - offset;
            last_piece = offset;
        } else {
            size = rand::random::<usize>() % max_broken_size;
        }
        let piece: (usize, &[u8]) = (offset, &original[offset..(offset + size)]);
        broken_data.push(piece);
        offset += size;
    }

    {
        let slice_broken_data = &mut broken_data[..];
        slice_broken_data.shuffle(&mut rng);
    }

    match broken_data.iter().filter(|&x| x.0 != last_piece).last() {
        None => panic!("Should never occur. Error in test itself."),
        Some(overlap) => {
            let mut extra: Vec<u8> = overlap.1.to_vec();
            extra.extend(random_bytes(&mut rng, 7usize)[..].iter().cloned());
            let post_overlap: (usize, &[u8]) = (overlap.0, &mut extra[..]);
            let post_position = overlap.0 + overlap.1.len();
            let mut wtotal = 0;

            let se = SelfEncryptor::new(storage, DataMap::None)
                .expect("Encryptor construction shouldn't fail.");
            for element in &broken_data {
                se.write(element.1, element.0)
                    .await
                    .expect("Writing broken data to encryptor shouldn't fail.");
                wtotal += element.1.len();
            }
            assert_eq!(wtotal, DATA_SIZE);
            let mut decrypted = se
                .read(0, DATA_SIZE)
                .await
                .expect("Reading broken data from encryptor shouldn't fail.");
            assert_eq!(original, decrypted);

            let mut overwrite = original[0..post_overlap.0].to_vec();
            overwrite.extend((post_overlap.1).to_vec().iter().cloned());
            overwrite.extend(original[post_position + 7..DATA_SIZE].iter().cloned());
            se.write(post_overlap.1, post_overlap.0)
                .await
                .expect("Writing overlap to encryptor shouldn't fail.");
            decrypted = se
                .read(0, DATA_SIZE)
                .await
                .expect("Reading all data from encryptor shouldn't fail.");
            assert_eq!(overwrite.len(), decrypted.len());
            assert_eq!(overwrite, decrypted);
        }
    }
    Ok(())
}

#[tokio::test]
// The test writes random-sized pieces at random offsets and checks they can be read back.  The
// pieces may overlap or leave gaps in the file.  Gaps should be filled with 0s when read back.
async fn write_random_sizes_out_of_sequence_with_gaps_and_overlaps(
) -> Result<(), SelfEncryptionError> {
    let parts = 20usize;
    assert!((DATA_SIZE / MAX_CHUNK_SIZE) as u64 >= parts as u64);
    let mut rng = new_test_rng()?;
    let mut total_size = 0;
    let mut original = vec![0u8; DATA_SIZE];

    let (data_map, storage) = {
        let storage = SimpleStorage::new();
        let self_encryptor = SelfEncryptor::new(storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        for i in 0..parts {
            // Get random values for the piece size and intended offset
            let piece_size = rng.gen_range(1, MAX_CHUNK_SIZE + 1);
            let offset = rng.gen_range(0, DATA_SIZE - MAX_CHUNK_SIZE);
            total_size = std::cmp::max(total_size, offset + piece_size);
            assert!(DATA_SIZE >= total_size);

            // Create the random piece and copy to the comparison vector.
            let piece = random_bytes(&mut rng, piece_size);
            original[offset..(piece_size + offset)].clone_from_slice(&piece[..piece_size]);

            // Write the piece to the encryptor and check it can be read back.
            self_encryptor
                .write(&piece, offset)
                .await
                .unwrap_or_else(|_| panic!("Writing part {} to encryptor shouldn't fail.", i));
            let decrypted = self_encryptor
                .read(offset, piece_size)
                .await
                .unwrap_or_else(|_| panic!("Reading part {} from encryptor shouldn't fail.", i));
            assert_eq!(decrypted, piece);
            assert_eq!(total_size, self_encryptor.len().await);
        }

        // Read back DATA_SIZE from the encryptor.  This will contain all that was written, plus
        // likely will be reading past EOF.  Reading past the end shouldn't affect the file size.
        let decrypted = self_encryptor
            .read(0, DATA_SIZE)
            .await
            .expect("Reading all data from encryptor shouldn't fail.");
        assert_eq!(decrypted.len(), DATA_SIZE);
        assert_eq!(decrypted, original);
        assert_eq!(total_size, self_encryptor.len().await);

        // Close the encryptor, open a new one with the returned DataMap, and read back DATA_SIZE
        // again.
        self_encryptor
            .close()
            .await
            .expect("Closing encryptor shouldn't fail.")
    };

    let self_encryptor =
        SelfEncryptor::new(storage, data_map).expect("Encryptor construction shouldn't fail.");
    let decrypted = self_encryptor
        .read(0, DATA_SIZE)
        .await
        .expect("Reading all data again from encryptor shouldn't fail.");
    assert_eq!(decrypted.len(), DATA_SIZE);
    assert_eq!(decrypted, original);
    assert_eq!(total_size, self_encryptor.len().await);
    Ok(())
}

#[tokio::test]
async fn cross_platform_check() {
    #[rustfmt::skip]
    static EXPECTED_HASHES: [[u8; 32]; 3] = [
        [90, 123, 178, 77, 189, 56, 250, 228, 43, 186, 33, 61, 74, 91, 212, 16, 157, 230, 227, 31, 132, 167, 178, 127, 44, 33, 184, 3, 80, 29, 195, 41],
        [28, 140, 54, 94, 73, 131, 229, 215, 75, 243, 169, 19, 239, 219, 112, 252, 107, 16, 114, 249, 219, 17, 212, 110, 99, 192, 86, 182, 30, 208, 213, 64],
        [148, 67, 120, 59, 152, 244, 232, 6, 37, 187, 230, 153, 188, 190, 244, 156, 218, 116, 25, 129, 208, 78, 180, 236, 123, 14, 82, 255, 209, 231, 22, 129],
    ];

    let mut chars0 = Vec::<u8>::new();
    let mut chars1 = Vec::<u8>::new();
    let mut chars2 = Vec::<u8>::new();

    // 1Mb of data for each chunk...
    for _ in 0..8192 {
        for j in 0..128 {
            chars0.push(j);
            chars1.push(j);
            chars2.push(j);
        }
    }

    chars1[0] = 1;
    chars2[0] = 2;

    let (data_map, _) = {
        let storage = SimpleStorage::new();
        let self_encryptor = SelfEncryptor::new(storage, DataMap::None)
            .expect("Encryptor construction shouldn't fail.");
        self_encryptor
            .write(&chars0[..], 0)
            .await
            .expect("Writing first slice to encryptor shouldn't fail.");
        self_encryptor
            .write(&chars1[..], chars0.len())
            .await
            .expect("Writing second slice to encryptor shouldn't fail.");
        self_encryptor
            .write(&chars2[..], chars0.len() + chars1.len())
            .await
            .expect("Writing third slice to encryptor shouldn't fail.");
        self_encryptor
            .close()
            .await
            .expect("Closing encryptor shouldn't fail.")
    };

    assert_eq!(3, data_map.get_chunks().len());

    let chunks = data_map.get_chunks();

    for i in 0..chunks.len() {
        assert_eq!(&EXPECTED_HASHES[i][..], &chunks[i].hash[..]);
    }
}
