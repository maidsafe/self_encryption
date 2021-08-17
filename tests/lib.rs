// Copyright 2021 MaidSafe.net limited.
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

use bytes::Bytes;
use itertools::Itertools;
use self_encryption::{encrypt, ChunkKey, DataMap, Result};

// const DATA_SIZE: usize = (if cfg!(target_pointer_width = "32") {
//     4
// } else {
//     20
// }) * 1024
//     * 1024;

// #[tokio::test]
// async fn new_read() -> Result<()> {
//     let read_size: usize = 4096;
//     let mut read_position: usize = 0;
//     let content_len: usize = 4 * MAX_CHUNK_SIZE;
//     let storage = SimpleStorage::new();
//     let mut rng = new_test_rng()?;
//     let original = random_bytes(&mut rng, content_len);
//     {
//         let se = SelfEncryptor::new(storage, DataMap::None)
//             .expect("Encryptor construction shouldn't fail.");
//         se.write(&original, 0)
//             .await
//             .expect("Writing to encryptor shouldn't fail.");
//         {
//             let mut decrypted = se
//                 .read(read_position, read_size)
//                 .await
//                 .expect("Reading part one from encryptor shouldn't fail.");
//             assert_eq!(
//                 original[read_position..(read_position + read_size)].to_vec(),
//                 decrypted
//             );

//             // read next small part
//             read_position += read_size;
//             decrypted = se
//                 .read(read_position, read_size)
//                 .await
//                 .expect("Reading part two from encryptor shouldn't fail.");
//             assert_eq!(
//                 original[read_position..(read_position + read_size)].to_vec(),
//                 decrypted
//             );

//             // try to read from end of file, moving the sliding window
//             read_position = content_len - 3 * read_size;
//             decrypted = se
//                 .read(read_position, read_size)
//                 .await
//                 .expect("Reading past end of encryptor shouldn't fail.");
//             assert_eq!(
//                 original[read_position..(read_position + read_size)].to_vec(),
//                 decrypted
//             );

//             // read again at beginning of file
//             read_position = 5usize;
//             decrypted = se
//                 .read(read_position, read_size)
//                 .await
//                 .expect("Reading from start of encryptor shouldn't fail.");
//             assert_eq!(
//                 original[read_position..(read_position + read_size)].to_vec(),
//                 decrypted
//             );
//         }

//         {
//             // Finish with many small reads
//             let mut decrypted: Vec<u8> = Vec::with_capacity(content_len);
//             read_position = 0usize;
//             for i in 0..15 {
//                 decrypted.extend(
//                     se.read(read_position, read_size)
//                         .await
//                         .unwrap_or_else(|_| {
//                             panic!("Reading attempt {} from encryptor shouldn't fail", i)
//                         })
//                         .iter()
//                         .cloned(),
//                 );
//                 assert_eq!(original[0..(read_position + read_size)].to_vec(), decrypted);
//                 read_position += read_size;
//             }
//         }
//         let _ = se.close().await.expect("Closing encryptor shouldn't fail.");
//     }
//     Ok(())
// }

// #[tokio::test]
// async fn write_and_close_random_sizes_at_random_positions() -> Result<()> {
//     let mut rng = new_test_rng()?;
//     let mut storage = SimpleStorage::new();
//     let max_broken_size = 20 * 1024;
//     let original = random_bytes(&mut rng, DATA_SIZE);
//     // estimate number of broken pieces, not known in advance
//     let mut broken_data: Vec<(usize, &[u8])> = Vec::with_capacity(DATA_SIZE / max_broken_size);

//     let mut offset = 0;
//     let mut last_piece = 0;
//     while offset < DATA_SIZE {
//         let size;
//         if DATA_SIZE - offset < max_broken_size {
//             size = DATA_SIZE - offset;
//             last_piece = offset;
//         } else {
//             size = rand::random::<usize>() % max_broken_size;
//         }
//         let piece: (usize, &[u8]) = (offset, &original[offset..(offset + size)]);
//         broken_data.push(piece);
//         offset += size;
//     }

//     {
//         let slice_broken_data = &mut broken_data[..];
//         slice_broken_data.shuffle(&mut rng);
//     }

//     match broken_data.iter().filter(|&x| x.0 != last_piece).last() {
//         None => panic!("Should never occur. Error in test itself."),
//         Some(overlap) => {
//             let mut extra: Vec<u8> = overlap.1.to_vec();
//             extra.extend(random_bytes(&mut rng, 7usize)[..].iter().cloned());
//             let post_overlap: (usize, &[u8]) = (overlap.0, &mut extra[..]);
//             let post_position = overlap.0 + overlap.1.len();
//             let mut wtotal = 0;
//             let mut data_map_orig = DataMap::None;
//             for element in &broken_data {
//                 let se = SelfEncryptor::new(storage.clone(), data_map_orig)
//                     .expect("Encryptor construction shouldn't fail.");
//                 se.write(element.1, element.0)
//                     .await
//                     .expect("Writing broken data to encryptor shouldn't fail.");
//                 wtotal += element.1.len();
//                 let (data_map, storage_tmp) = se
//                     .close()
//                     .await
//                     .expect("Closing broken data to encryptor shouldn't fail.");
//                 data_map_orig = data_map;
//                 storage = storage_tmp;
//             }
//             assert_eq!(wtotal, DATA_SIZE);
//             let se = SelfEncryptor::new(storage, data_map_orig)
//                 .expect("Encryptor construction shouldn't fail.");
//             let mut decrypted = se
//                 .read(0, DATA_SIZE)
//                 .await
//                 .expect("Reading broken data from encryptor shouldn't fail.");
//             assert_eq!(original, decrypted);

//             let mut overwrite = original[0..post_overlap.0].to_vec();
//             overwrite.extend((post_overlap.1).to_vec().iter().cloned());
//             overwrite.extend(original[post_position + 7..DATA_SIZE].iter().cloned());
//             se.write(post_overlap.1, post_overlap.0)
//                 .await
//                 .expect("Writing overlap to encryptor shouldn't fail.");
//             decrypted = se
//                 .read(0, DATA_SIZE)
//                 .await
//                 .expect("Reading all data from encryptor shouldn't fail.");
//             assert_eq!(overwrite.len(), decrypted.len());
//             assert_eq!(overwrite, decrypted);
//         }
//     }
//     Ok(())
// }

// #[tokio::test]
// async fn write_random_sizes_at_random_positions() -> Result<()> {
//     let mut rng = new_test_rng()?;
//     let storage = SimpleStorage::new();
//     let max_broken_size = 20 * 1024;
//     let original = random_bytes(&mut rng, DATA_SIZE);
//     // estimate number of broken pieces, not known in advance
//     let mut broken_data: Vec<(usize, &[u8])> = Vec::with_capacity(DATA_SIZE / max_broken_size);

//     let mut offset = 0;
//     let mut last_piece = 0;
//     while offset < DATA_SIZE {
//         let size;
//         if DATA_SIZE - offset < max_broken_size {
//             size = DATA_SIZE - offset;
//             last_piece = offset;
//         } else {
//             size = rand::random::<usize>() % max_broken_size;
//         }
//         let piece: (usize, &[u8]) = (offset, &original[offset..(offset + size)]);
//         broken_data.push(piece);
//         offset += size;
//     }

//     {
//         let slice_broken_data = &mut broken_data[..];
//         slice_broken_data.shuffle(&mut rng);
//     }

//     match broken_data.iter().filter(|&x| x.0 != last_piece).last() {
//         None => panic!("Should never occur. Error in test itself."),
//         Some(overlap) => {
//             let mut extra: Vec<u8> = overlap.1.to_vec();
//             extra.extend(random_bytes(&mut rng, 7usize)[..].iter().cloned());
//             let post_overlap: (usize, &[u8]) = (overlap.0, &mut extra[..]);
//             let post_position = overlap.0 + overlap.1.len();
//             let mut wtotal = 0;

//             let se = SelfEncryptor::new(storage, DataMap::None)
//                 .expect("Encryptor construction shouldn't fail.");
//             for element in &broken_data {
//                 se.write(element.1, element.0)
//                     .await
//                     .expect("Writing broken data to encryptor shouldn't fail.");
//                 wtotal += element.1.len();
//             }
//             assert_eq!(wtotal, DATA_SIZE);
//             let mut decrypted = se
//                 .read(0, DATA_SIZE)
//                 .await
//                 .expect("Reading broken data from encryptor shouldn't fail.");
//             assert_eq!(original, decrypted);

//             let mut overwrite = original[0..post_overlap.0].to_vec();
//             overwrite.extend((post_overlap.1).to_vec().iter().cloned());
//             overwrite.extend(original[post_position + 7..DATA_SIZE].iter().cloned());
//             se.write(post_overlap.1, post_overlap.0)
//                 .await
//                 .expect("Writing overlap to encryptor shouldn't fail.");
//             decrypted = se
//                 .read(0, DATA_SIZE)
//                 .await
//                 .expect("Reading all data from encryptor shouldn't fail.");
//             assert_eq!(overwrite.len(), decrypted.len());
//             assert_eq!(overwrite, decrypted);
//         }
//     }
//     Ok(())
// }

// #[tokio::test]
// // The test writes random-sized pieces at random offsets and checks they can be read back.  The
// // pieces may overlap or leave gaps in the file.  Gaps should be filled with 0s when read back.
// async fn write_random_sizes_out_of_sequence_with_gaps_and_overlaps(
// ) -> Result<()> {
//     let parts: usize = if cfg!(target_pointer_width = "32") {
//         4
//     } else {
//         20
//     };
//     assert!((DATA_SIZE / MAX_CHUNK_SIZE) as u64 >= parts as u64);
//     let mut rng = new_test_rng()?;
//     let mut total_size = 0;
//     let mut original = vec![0u8; DATA_SIZE];

//     let (data_map, storage) = {
//         let storage = SimpleStorage::new();
//         let self_encryptor = SelfEncryptor::new(storage, DataMap::None)
//             .expect("Encryptor construction shouldn't fail.");
//         for i in 0..parts {
//             // Get random values for the piece size and intended offset
//             let piece_size = rng.gen_range(1, MAX_CHUNK_SIZE + 1);
//             let offset = rng.gen_range(0, DATA_SIZE - MAX_CHUNK_SIZE);
//             total_size = std::cmp::max(total_size, offset + piece_size);
//             assert!(DATA_SIZE >= total_size);

//             // Create the random piece and copy to the comparison vector.
//             let piece = random_bytes(&mut rng, piece_size);
//             original[offset..(piece_size + offset)].clone_from_slice(&piece[..piece_size]);

//             // Write the piece to the encryptor and check it can be read back.
//             self_encryptor
//                 .write(&piece, offset)
//                 .await
//                 .unwrap_or_else(|_| panic!("Writing part {} to encryptor shouldn't fail.", i));
//             let decrypted = self_encryptor
//                 .read(offset, piece_size)
//                 .await
//                 .unwrap_or_else(|_| panic!("Reading part {} from encryptor shouldn't fail.", i));
//             assert_eq!(decrypted, piece);
//             assert_eq!(total_size, self_encryptor.len().await);
//         }

//         // Read back DATA_SIZE from the encryptor.  This will contain all that was written, plus
//         // likely will be reading past EOF.  Reading past the end shouldn't affect the file size.
//         let decrypted = self_encryptor
//             .read(0, DATA_SIZE)
//             .await
//             .expect("Reading all data from encryptor shouldn't fail.");
//         assert_eq!(decrypted.len(), DATA_SIZE);
//         assert_eq!(decrypted, original);
//         assert_eq!(total_size, self_encryptor.len().await);

//         // Close the encryptor, open a new one with the returned DataMap, and read back DATA_SIZE
//         // again.
//         self_encryptor
//             .close()
//             .await
//             .expect("Closing encryptor shouldn't fail.")
//     };

//     let self_encryptor =
//         SelfEncryptor::new(storage, data_map).expect("Encryptor construction shouldn't fail.");
//     let decrypted = self_encryptor
//         .read(0, DATA_SIZE)
//         .await
//         .expect("Reading all data again from encryptor shouldn't fail.");
//     assert_eq!(decrypted.len(), DATA_SIZE);
//     assert_eq!(decrypted, original);
//     assert_eq!(total_size, self_encryptor.len().await);
//     Ok(())
// }

// #[tokio::test]
// async fn cross_platform_check() {
//     #[rustfmt::skip]
//     static EXPECTED_HASHES: [[u8; 32]; 3] = [
//         [19, 108, 102, 255, 128, 233, 109, 189, 190, 233, 41, 63, 63, 138, 214, 249, 106, 84, 201, 23, 7, 58, 106, 78, 188, 172, 111, 148, 245, 160, 133, 186],
//         [114, 117, 152, 126, 135, 111, 36, 211, 180, 31, 218, 187, 110, 75, 78, 238, 69, 210, 84, 34, 101, 16, 111, 36, 244, 207, 142, 127, 105, 74, 229, 255],
//         [247, 254, 6, 213, 162, 170, 240, 233, 104, 210, 240, 176, 24, 102, 165, 192, 179, 134, 155, 232, 104, 23, 210, 123, 11, 198, 91, 89, 17, 162, 214, 64],
//     ];

//     let mut chars0 = Vec::<u8>::new();
//     let mut chars1 = Vec::<u8>::new();
//     let mut chars2 = Vec::<u8>::new();

//     // 1Mb of data for each chunk...
//     for _ in 0..8192 {
//         for j in 0..128 {
//             chars0.push(j);
//             chars1.push(j);
//             chars2.push(j);
//         }
//     }

//     chars1[0] = 1;
//     chars2[0] = 2;

//     let (data_map, _) = {
//         let storage = SimpleStorage::new();
//         let self_encryptor = SelfEncryptor::new(storage, DataMap::None)
//             .expect("Encryptor construction shouldn't fail.");
//         self_encryptor
//             .write(&chars0[..], 0)
//             .await
//             .expect("Writing first slice to encryptor shouldn't fail.");
//         self_encryptor
//             .write(&chars1[..], chars0.len())
//             .await
//             .expect("Writing second slice to encryptor shouldn't fail.");
//         self_encryptor
//             .write(&chars2[..], chars0.len() + chars1.len())
//             .await
//             .expect("Writing third slice to encryptor shouldn't fail.");
//         self_encryptor
//             .close()
//             .await
//             .expect("Closing encryptor shouldn't fail.")
//     };

//     assert_eq!(3, data_map.get_chunks().len());

//     let chunks = data_map.get_chunks();

//     for i in 0..chunks.len() {
//         assert_eq!(&EXPECTED_HASHES[i][..], &chunks[i].hash[..]);
//     }
// }

#[tokio::test]
async fn cross_platform_check2() -> Result<()> {
    let content_size: usize = 20 * 1024 * 1024 + 100;
    let mut content = vec![0u8; content_size];
    for (i, c) in content.iter_mut().enumerate().take(content_size) {
        *c = (i % 17) as u8;
    }

    let chunks = encrypt(Bytes::from(content))?;
    let data_map = DataMap::Chunks(
        chunks
            .into_iter()
            .sorted_by_key(|c| c.key.index)
            .map(|c| c.key)
            .collect(),
    );

    // update data map when algorithm changes
    let ref_datamap = vec![
        ChunkKey {
            src_hash: Bytes::from(
                [
                    219, 177, 84, 234, 189, 172, 82, 64, 169, 100, 5, 56, 3, 43, 142, 126, 51, 235,
                    194, 243, 30, 130, 132, 197, 137, 36, 170, 62, 46, 44, 176, 201,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    130, 129, 210, 14, 124, 211, 239, 103, 149, 16, 206, 197, 81, 0, 41, 239, 38,
                    254, 192, 5, 173, 35, 19, 29, 133, 251, 44, 204, 57, 237, 37, 124,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    65, 81, 63, 82, 119, 126, 216, 9, 44, 18, 160, 174, 225, 8, 202, 32, 245, 140,
                    14, 169, 252, 209, 97, 96, 134, 165, 102, 106, 250, 196, 27, 70,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    42, 62, 224, 152, 136, 214, 91, 160, 125, 249, 229, 115, 81, 220, 213, 34, 29,
                    173, 235, 99, 67, 210, 234, 160, 79, 254, 208, 174, 117, 127, 205, 36,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    80, 237, 26, 5, 69, 59, 53, 210, 44, 236, 191, 69, 92, 39, 113, 124, 206, 169,
                    5, 126, 189, 2, 146, 80, 68, 186, 142, 219, 37, 170, 135, 61,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    200, 203, 81, 29, 131, 156, 60, 140, 166, 254, 103, 60, 212, 223, 22, 41, 85,
                    192, 140, 154, 33, 34, 188, 94, 84, 101, 62, 254, 164, 81, 209, 154,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    168, 223, 46, 4, 138, 115, 226, 112, 179, 67, 36, 186, 170, 199, 21, 195, 41,
                    17, 99, 227, 30, 226, 46, 42, 78, 210, 189, 107, 185, 167, 32, 74,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    42, 138, 132, 73, 12, 78, 47, 136, 153, 177, 25, 247, 202, 227, 145, 31, 193,
                    9, 33, 63, 89, 160, 240, 51, 189, 72, 94, 193, 75, 144, 58, 233,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    41, 137, 66, 160, 103, 223, 72, 133, 180, 83, 8, 139, 180, 108, 20, 196, 106,
                    59, 73, 6, 160, 187, 8, 16, 93, 157, 142, 155, 85, 118, 239, 192,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    220, 162, 48, 182, 212, 178, 139, 207, 231, 191, 209, 53, 187, 22, 66, 221,
                    242, 66, 220, 19, 96, 201, 137, 25, 101, 184, 1, 178, 80, 204, 253, 179,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    48, 226, 1, 203, 69, 49, 140, 152, 90, 232, 209, 42, 178, 241, 60, 11, 24, 2,
                    196, 26, 14, 229, 127, 68, 119, 116, 135, 195, 248, 217, 227, 78,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    168, 232, 79, 142, 149, 51, 198, 62, 224, 177, 45, 203, 243, 51, 12, 23, 104,
                    80, 174, 5, 246, 234, 54, 70, 58, 11, 100, 117, 60, 67, 65, 64,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    92, 201, 208, 153, 241, 202, 111, 28, 118, 47, 47, 32, 121, 48, 203, 48, 230,
                    107, 102, 195, 184, 106, 245, 173, 157, 171, 139, 50, 28, 56, 80, 225,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    199, 114, 193, 185, 26, 6, 140, 71, 142, 73, 45, 198, 110, 126, 232, 182, 226,
                    85, 137, 210, 69, 24, 139, 163, 236, 47, 155, 130, 43, 229, 148, 172,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    50, 8, 67, 204, 158, 4, 255, 227, 50, 18, 176, 150, 249, 233, 188, 72, 86, 217,
                    61, 100, 161, 131, 124, 26, 245, 166, 44, 16, 125, 230, 153, 190,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    151, 255, 185, 86, 239, 216, 199, 233, 149, 16, 247, 122, 156, 66, 178, 95, 32,
                    219, 218, 228, 63, 23, 34, 207, 140, 20, 75, 2, 225, 3, 243, 193,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    132, 6, 224, 90, 168, 59, 66, 114, 199, 67, 140, 171, 226, 213, 141, 21, 32,
                    143, 4, 192, 143, 64, 253, 216, 200, 76, 162, 121, 130, 169, 89, 229,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    126, 221, 146, 123, 252, 37, 250, 160, 75, 182, 9, 39, 80, 87, 93, 229, 173,
                    203, 31, 203, 208, 190, 226, 111, 87, 78, 246, 141, 85, 237, 82, 87,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    238, 37, 229, 233, 96, 228, 150, 41, 89, 130, 145, 198, 50, 165, 207, 108, 15,
                    167, 122, 116, 209, 223, 68, 203, 24, 169, 74, 93, 44, 170, 24, 233,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    109, 123, 118, 55, 228, 175, 144, 231, 103, 223, 51, 185, 146, 37, 47, 46, 185,
                    208, 140, 202, 231, 18, 70, 47, 48, 245, 254, 93, 185, 120, 17, 143,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    70, 131, 32, 243, 131, 152, 215, 108, 51, 231, 184, 113, 117, 8, 164, 174, 151,
                    152, 232, 29, 11, 58, 104, 46, 55, 81, 249, 207, 213, 77, 151, 237,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    85, 8, 26, 126, 9, 32, 28, 70, 112, 134, 226, 170, 46, 25, 115, 222, 131, 175,
                    117, 141, 96, 45, 201, 108, 148, 142, 12, 27, 184, 109, 44, 70,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    50, 175, 184, 213, 76, 189, 138, 227, 190, 200, 141, 26, 235, 78, 173, 171,
                    137, 95, 43, 119, 8, 145, 253, 102, 189, 117, 247, 89, 246, 214, 129, 182,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    240, 135, 94, 165, 73, 209, 176, 218, 159, 232, 76, 254, 32, 84, 238, 245, 226,
                    2, 227, 194, 95, 48, 125, 227, 42, 118, 85, 160, 39, 83, 2, 124,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    160, 175, 104, 136, 24, 18, 192, 185, 147, 31, 227, 81, 212, 143, 214, 63, 52,
                    62, 218, 48, 35, 220, 0, 184, 62, 137, 152, 35, 144, 149, 229, 86,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    198, 136, 45, 128, 93, 197, 174, 93, 27, 19, 218, 211, 184, 14, 214, 97, 182,
                    149, 36, 161, 66, 19, 118, 105, 240, 100, 104, 1, 192, 87, 236, 132,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    158, 201, 252, 234, 200, 107, 72, 126, 69, 234, 165, 203, 122, 90, 36, 46, 82,
                    183, 61, 84, 128, 62, 118, 112, 222, 74, 164, 198, 20, 217, 96, 143,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    187, 81, 209, 66, 106, 200, 142, 130, 197, 102, 170, 211, 120, 197, 65, 210,
                    229, 57, 27, 231, 120, 217, 180, 231, 34, 155, 32, 41, 78, 74, 193, 115,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    208, 35, 197, 158, 225, 12, 21, 130, 132, 59, 227, 65, 238, 178, 232, 169, 186,
                    48, 27, 106, 153, 46, 168, 196, 199, 70, 105, 236, 161, 167, 109, 43,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    145, 170, 97, 191, 204, 99, 185, 85, 4, 199, 204, 34, 104, 219, 97, 0, 184,
                    167, 32, 173, 83, 249, 254, 42, 251, 10, 168, 231, 211, 67, 70, 120,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    191, 47, 52, 224, 196, 196, 113, 118, 243, 7, 35, 213, 174, 114, 228, 229, 165,
                    182, 217, 102, 55, 16, 174, 159, 197, 166, 75, 192, 182, 186, 173, 1,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    130, 233, 29, 245, 160, 80, 144, 117, 139, 251, 91, 240, 232, 173, 233, 168,
                    61, 138, 88, 0, 92, 133, 16, 118, 29, 118, 131, 218, 42, 197, 132, 54,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    116, 242, 114, 183, 140, 120, 52, 135, 104, 100, 112, 208, 10, 8, 99, 108, 78,
                    75, 84, 111, 100, 57, 241, 143, 117, 172, 80, 19, 43, 142, 225, 227,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    0, 52, 220, 168, 128, 29, 228, 70, 0, 29, 73, 244, 83, 7, 171, 237, 31, 236,
                    231, 24, 148, 14, 100, 16, 117, 82, 41, 11, 216, 126, 209, 127,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    219, 177, 84, 234, 189, 172, 82, 64, 169, 100, 5, 56, 3, 43, 142, 126, 51, 235,
                    194, 243, 30, 130, 132, 197, 137, 36, 170, 62, 46, 44, 176, 201,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    77, 246, 174, 53, 36, 156, 19, 157, 46, 142, 60, 60, 122, 133, 52, 118, 73, 80,
                    40, 205, 174, 231, 211, 110, 38, 8, 189, 206, 102, 252, 166, 34,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    65, 81, 63, 82, 119, 126, 216, 9, 44, 18, 160, 174, 225, 8, 202, 32, 245, 140,
                    14, 169, 252, 209, 97, 96, 134, 165, 102, 106, 250, 196, 27, 70,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    42, 62, 224, 152, 136, 214, 91, 160, 125, 249, 229, 115, 81, 220, 213, 34, 29,
                    173, 235, 99, 67, 210, 234, 160, 79, 254, 208, 174, 117, 127, 205, 36,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    116, 92, 235, 203, 212, 105, 193, 148, 115, 246, 87, 227, 218, 75, 65, 238,
                    163, 237, 235, 125, 249, 153, 21, 52, 162, 96, 47, 150, 30, 182, 208, 112,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    105, 178, 124, 23, 220, 180, 219, 83, 254, 79, 65, 107, 122, 98, 193, 172, 222,
                    160, 246, 13, 251, 141, 220, 254, 135, 181, 52, 194, 43, 136, 100, 101,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
        ChunkKey {
            src_hash: Bytes::from(
                [
                    214, 134, 86, 55, 215, 215, 208, 242, 178, 120, 200, 12, 212, 89, 92, 11, 93,
                    199, 19, 166, 63, 134, 155, 51, 34, 171, 194, 220, 249, 78, 72, 22,
                ]
                .to_vec(),
            ),
            dst_hash: Bytes::from(
                [
                    68, 132, 63, 86, 220, 69, 168, 139, 77, 35, 192, 220, 250, 13, 169, 144, 99,
                    212, 253, 136, 192, 107, 77, 209, 211, 14, 222, 78, 151, 149, 226, 34,
                ]
                .to_vec(),
            ),
            index: 0,
            src_size: 0,
        },
    ];
    match data_map {
        DataMap::Content(_) => panic!("Should be chunks!"),
        DataMap::Chunks(chunks) => {
            for (i, c) in chunks.into_iter().enumerate() {
                assert_eq!(c.src_hash, ref_datamap[i].src_hash);
                assert_eq!(c.dst_hash, ref_datamap[i].dst_hash);
            }
        }
    };
    Ok(())
}
