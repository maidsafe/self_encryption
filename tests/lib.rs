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
    ChunkDetails, DataMap, SelfEncryptionError, SelfEncryptor, MAX_CHUNK_SIZE,
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

#[tokio::test]
async fn cross_platform_check2() -> Result<(), SelfEncryptionError> {
    let storage = SimpleStorage::new();
    let se = SelfEncryptor::new(storage, DataMap::None)?;
    let content_size: usize = 20 * 1024 * 1024 + 100;
    let mut content = vec![0u8; content_size];
    for (i, c) in content.iter_mut().enumerate().take(content_size) {
        *c = (i % 17) as u8;
    }
    se.write(&content, 0).await?;
    let (dm, _) = se.close().await?;
    // update data map when algorithm changes
    let ref_datamap = vec![
        ChunkDetails {
            pre_hash: [
                219, 177, 84, 234, 189, 172, 82, 64, 169, 100, 5, 56, 3, 43, 142, 126, 51, 235,
                194, 243, 30, 130, 132, 197, 137, 36, 170, 62, 46, 44, 176, 201,
            ]
            .to_vec(),
            hash: [
                248, 130, 126, 24, 65, 196, 21, 116, 150, 177, 242, 95, 221, 83, 149, 182, 190,
                205, 67, 23, 123, 71, 198, 217, 210, 26, 108, 104, 226, 20, 218, 64,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                65, 81, 63, 82, 119, 126, 216, 9, 44, 18, 160, 174, 225, 8, 202, 32, 245, 140, 14,
                169, 252, 209, 97, 96, 134, 165, 102, 106, 250, 196, 27, 70,
            ]
            .to_vec(),
            hash: [
                18, 159, 244, 105, 187, 191, 246, 249, 87, 141, 67, 211, 58, 66, 134, 255, 150,
                208, 180, 171, 192, 111, 29, 186, 91, 148, 231, 45, 113, 105, 136, 202,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                80, 237, 26, 5, 69, 59, 53, 210, 44, 236, 191, 69, 92, 39, 113, 124, 206, 169, 5,
                126, 189, 2, 146, 80, 68, 186, 142, 219, 37, 170, 135, 61,
            ]
            .to_vec(),
            hash: [
                122, 136, 131, 108, 167, 36, 157, 132, 244, 145, 104, 32, 217, 12, 238, 220, 110,
                27, 50, 152, 172, 17, 66, 223, 251, 25, 212, 94, 142, 110, 132, 203,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                168, 223, 46, 4, 138, 115, 226, 112, 179, 67, 36, 186, 170, 199, 21, 195, 41, 17,
                99, 227, 30, 226, 46, 42, 78, 210, 189, 107, 185, 167, 32, 74,
            ]
            .to_vec(),
            hash: [
                95, 101, 4, 248, 190, 107, 61, 100, 154, 28, 217, 156, 80, 177, 100, 62, 205, 98,
                84, 234, 177, 29, 202, 153, 165, 201, 220, 48, 137, 69, 114, 30,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                41, 137, 66, 160, 103, 223, 72, 133, 180, 83, 8, 139, 180, 108, 20, 196, 106, 59,
                73, 6, 160, 187, 8, 16, 93, 157, 142, 155, 85, 118, 239, 192,
            ]
            .to_vec(),
            hash: [
                229, 205, 229, 159, 248, 80, 166, 205, 17, 198, 25, 160, 92, 222, 124, 245, 174,
                115, 130, 228, 117, 211, 61, 253, 82, 36, 197, 67, 106, 60, 33, 210,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                48, 226, 1, 203, 69, 49, 140, 152, 90, 232, 209, 42, 178, 241, 60, 11, 24, 2, 196,
                26, 14, 229, 127, 68, 119, 116, 135, 195, 248, 217, 227, 78,
            ]
            .to_vec(),
            hash: [
                72, 114, 190, 123, 137, 144, 19, 58, 46, 98, 42, 42, 32, 22, 250, 239, 40, 191, 85,
                193, 248, 243, 119, 35, 205, 131, 97, 106, 141, 241, 149, 245,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                92, 201, 208, 153, 241, 202, 111, 28, 118, 47, 47, 32, 121, 48, 203, 48, 230, 107,
                102, 195, 184, 106, 245, 173, 157, 171, 139, 50, 28, 56, 80, 225,
            ]
            .to_vec(),
            hash: [
                57, 85, 13, 143, 39, 227, 226, 221, 59, 104, 169, 74, 10, 232, 242, 131, 220, 126,
                4, 85, 84, 43, 81, 102, 148, 97, 165, 37, 118, 56, 189, 192,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                50, 8, 67, 204, 158, 4, 255, 227, 50, 18, 176, 150, 249, 233, 188, 72, 86, 217, 61,
                100, 161, 131, 124, 26, 245, 166, 44, 16, 125, 230, 153, 190,
            ]
            .to_vec(),
            hash: [
                93, 249, 109, 233, 188, 240, 18, 231, 63, 202, 255, 90, 160, 31, 54, 191, 36, 85,
                75, 29, 84, 141, 204, 112, 254, 11, 116, 129, 63, 15, 2, 66,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                132, 6, 224, 90, 168, 59, 66, 114, 199, 67, 140, 171, 226, 213, 141, 21, 32, 143,
                4, 192, 143, 64, 253, 216, 200, 76, 162, 121, 130, 169, 89, 229,
            ]
            .to_vec(),
            hash: [
                56, 110, 198, 24, 230, 120, 195, 219, 227, 31, 129, 221, 182, 202, 3, 146, 2, 223,
                67, 21, 114, 84, 65, 108, 18, 235, 239, 62, 175, 220, 138, 201,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                238, 37, 229, 233, 96, 228, 150, 41, 89, 130, 145, 198, 50, 165, 207, 108, 15, 167,
                122, 116, 209, 223, 68, 203, 24, 169, 74, 93, 44, 170, 24, 233,
            ]
            .to_vec(),
            hash: [
                176, 75, 146, 134, 244, 24, 27, 63, 160, 231, 223, 50, 124, 237, 115, 200, 213, 88,
                148, 205, 98, 22, 69, 146, 11, 228, 82, 29, 170, 82, 110, 45,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                70, 131, 32, 243, 131, 152, 215, 108, 51, 231, 184, 113, 117, 8, 164, 174, 151,
                152, 232, 29, 11, 58, 104, 46, 55, 81, 249, 207, 213, 77, 151, 237,
            ]
            .to_vec(),
            hash: [
                184, 133, 215, 104, 56, 111, 160, 119, 201, 247, 23, 236, 92, 28, 171, 221, 79,
                232, 237, 159, 27, 19, 177, 176, 15, 23, 161, 163, 66, 159, 242, 210,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                50, 175, 184, 213, 76, 189, 138, 227, 190, 200, 141, 26, 235, 78, 173, 171, 137,
                95, 43, 119, 8, 145, 253, 102, 189, 117, 247, 89, 246, 214, 129, 182,
            ]
            .to_vec(),
            hash: [
                49, 232, 225, 31, 240, 54, 141, 164, 15, 217, 164, 149, 222, 144, 11, 59, 134, 214,
                126, 179, 105, 30, 190, 131, 89, 27, 240, 190, 124, 226, 198, 150,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                160, 175, 104, 136, 24, 18, 192, 185, 147, 31, 227, 81, 212, 143, 214, 63, 52, 62,
                218, 48, 35, 220, 0, 184, 62, 137, 152, 35, 144, 149, 229, 86,
            ]
            .to_vec(),
            hash: [
                17, 219, 169, 42, 190, 205, 249, 126, 131, 68, 38, 223, 73, 115, 93, 112, 62, 36,
                183, 193, 140, 224, 55, 194, 89, 227, 69, 129, 251, 109, 214, 53,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                158, 201, 252, 234, 200, 107, 72, 126, 69, 234, 165, 203, 122, 90, 36, 46, 82, 183,
                61, 84, 128, 62, 118, 112, 222, 74, 164, 198, 20, 217, 96, 143,
            ]
            .to_vec(),
            hash: [
                165, 173, 226, 206, 228, 178, 246, 235, 26, 163, 155, 125, 0, 205, 205, 36, 64, 86,
                234, 222, 69, 114, 119, 7, 12, 196, 25, 126, 193, 205, 60, 114,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                208, 35, 197, 158, 225, 12, 21, 130, 132, 59, 227, 65, 238, 178, 232, 169, 186, 48,
                27, 106, 153, 46, 168, 196, 199, 70, 105, 236, 161, 167, 109, 43,
            ]
            .to_vec(),
            hash: [
                1, 63, 38, 182, 193, 210, 99, 152, 89, 107, 90, 17, 230, 73, 159, 81, 102, 57, 247,
                106, 68, 225, 33, 192, 209, 0, 196, 53, 242, 35, 108, 96,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                191, 47, 52, 224, 196, 196, 113, 118, 243, 7, 35, 213, 174, 114, 228, 229, 165,
                182, 217, 102, 55, 16, 174, 159, 197, 166, 75, 192, 182, 186, 173, 1,
            ]
            .to_vec(),
            hash: [
                23, 162, 40, 30, 19, 91, 183, 249, 44, 142, 229, 130, 88, 59, 48, 115, 117, 210,
                223, 201, 112, 61, 114, 209, 96, 133, 128, 150, 33, 234, 92, 67,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                116, 242, 114, 183, 140, 120, 52, 135, 104, 100, 112, 208, 10, 8, 99, 108, 78, 75,
                84, 111, 100, 57, 241, 143, 117, 172, 80, 19, 43, 142, 225, 227,
            ]
            .to_vec(),
            hash: [
                177, 48, 239, 237, 6, 81, 178, 34, 44, 125, 146, 74, 170, 12, 72, 237, 128, 157,
                43, 20, 70, 35, 246, 95, 240, 124, 236, 50, 211, 28, 253, 13,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                219, 177, 84, 234, 189, 172, 82, 64, 169, 100, 5, 56, 3, 43, 142, 126, 51, 235,
                194, 243, 30, 130, 132, 197, 137, 36, 170, 62, 46, 44, 176, 201,
            ]
            .to_vec(),
            hash: [
                75, 61, 6, 107, 79, 230, 247, 5, 216, 162, 59, 66, 230, 241, 190, 226, 105, 185,
                20, 191, 117, 79, 150, 152, 104, 202, 109, 124, 142, 177, 167, 23,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                65, 81, 63, 82, 119, 126, 216, 9, 44, 18, 160, 174, 225, 8, 202, 32, 245, 140, 14,
                169, 252, 209, 97, 96, 134, 165, 102, 106, 250, 196, 27, 70,
            ]
            .to_vec(),
            hash: [
                18, 159, 244, 105, 187, 191, 246, 249, 87, 141, 67, 211, 58, 66, 134, 255, 150,
                208, 180, 171, 192, 111, 29, 186, 91, 148, 231, 45, 113, 105, 136, 202,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                116, 92, 235, 203, 212, 105, 193, 148, 115, 246, 87, 227, 218, 75, 65, 238, 163,
                237, 235, 125, 249, 153, 21, 52, 162, 96, 47, 150, 30, 182, 208, 112,
            ]
            .to_vec(),
            hash: [
                42, 242, 254, 92, 95, 88, 84, 152, 206, 210, 173, 147, 63, 233, 12, 97, 179, 180,
                180, 161, 15, 55, 241, 163, 79, 123, 64, 234, 13, 157, 247, 100,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
        ChunkDetails {
            pre_hash: [
                214, 134, 86, 55, 215, 215, 208, 242, 178, 120, 200, 12, 212, 89, 92, 11, 93, 199,
                19, 166, 63, 134, 155, 51, 34, 171, 194, 220, 249, 78, 72, 22,
            ]
            .to_vec(),
            hash: [
                11, 138, 109, 122, 129, 132, 242, 156, 53, 48, 249, 168, 40, 130, 114, 195, 224,
                98, 246, 23, 129, 45, 220, 242, 140, 12, 168, 65, 234, 0, 40, 11,
            ]
            .to_vec(),
            chunk_num: 0,
            source_size: 0,
        },
    ];
    match dm {
        DataMap::Content(_) | DataMap::None => panic!("Should be chunks!"),
        DataMap::Chunks(chunks) => {
            for (i, c) in chunks.into_iter().enumerate() {
                assert_eq!(c.pre_hash, ref_datamap[i].pre_hash);
                assert_eq!(c.hash, ref_datamap[i].hash);
            }
        }
    };
    Ok(())
}
