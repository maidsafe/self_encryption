// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

extern crate futures;
extern crate rand;
extern crate self_encryption;

use futures::Future;
use rand::Rng;
use self_encryption::{DataMap, MAX_CHUNK_SIZE, SelfEncryptor};
use self_encryption::test_helpers::SimpleStorage;

const DATA_SIZE: u32 = 20 * 1024 * 1024;

fn random_bytes(size: usize) -> Vec<u8> {
    rand::thread_rng().gen_iter().take(size).collect()
}

#[test]
fn new_read() {
    let read_size: usize = 4096;
    let mut read_position: usize = 0;
    let content_len: usize = 4 * MAX_CHUNK_SIZE as usize;
    let storage = SimpleStorage::new();
    let original = random_bytes(content_len);
    {
        let se = SelfEncryptor::new(storage, DataMap::None).expect(
            "Encryptor construction shouldn't fail.",
        );
        se.write(&original, 0).wait().expect(
            "Writing to encryptor shouldn't fail.",
        );
        {
            let mut decrypted = se.read(read_position as u64, read_size as u64)
                .wait()
                .expect("Reading part one from encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );

            // read next small part
            read_position += read_size;
            decrypted = se.read(read_position as u64, read_size as u64)
                .wait()
                .expect("Reading part two from encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );

            // try to read from end of file, moving the sliding window
            read_position = content_len - 3 * read_size;
            decrypted = se.read(read_position as u64, read_size as u64)
                .wait()
                .expect("Reading past end of encryptor shouldn't fail.");
            assert_eq!(
                original[read_position..(read_position + read_size)].to_vec(),
                decrypted
            );

            // read again at beginning of file
            read_position = 5usize;
            decrypted = se.read(read_position as u64, read_size as u64)
                .wait()
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
                    se.read(read_position as u64, read_size as u64)
                        .wait()
                        .expect(&format!(
                            "Reading attempt {} from encryptor shouldn't fail",
                            i
                        ))
                        .iter()
                        .cloned(),
                );
                assert_eq!(original[0..(read_position + read_size)].to_vec(), decrypted);
                read_position += read_size;
            }
        }
        let _ = se.close().wait().expect(
            "Closing encryptor shouldn't fail.",
        );
    }
}

#[test]
fn write_random_sizes_at_random_positions() {
    let mut rng = rand::thread_rng();
    let storage = SimpleStorage::new();
    let max_broken_size = 20 * 1024;
    let original = random_bytes(DATA_SIZE as usize);
    // estimate number of broken pieces, not known in advance
    let mut broken_data: Vec<(u32, &[u8])> =
        Vec::with_capacity((DATA_SIZE / max_broken_size) as usize);

    let mut offset = 0;
    let mut last_piece = 0;
    while offset < DATA_SIZE {
        let size;
        if DATA_SIZE - offset < max_broken_size {
            size = DATA_SIZE - offset;
            last_piece = offset;
        } else {
            size = rand::random::<u32>() % max_broken_size;
        }
        let piece: (u32, &[u8]) = (offset, &original[offset as usize..(offset + size) as usize]);
        broken_data.push(piece);
        offset += size;
    }

    {
        let slice_broken_data = &mut broken_data[..];
        rng.shuffle(slice_broken_data);
    }

    match broken_data.iter().filter(|&x| x.0 != last_piece).last() {
        None => panic!("Should never occur. Error in test itself."),
        Some(overlap) => {
            let mut extra: Vec<u8> = overlap.1.to_vec();
            extra.extend(random_bytes(7usize)[..].iter().cloned());
            let post_overlap: (u32, &[u8]) = (overlap.0, &mut extra[..]);
            let post_position = overlap.0 as usize + overlap.1.len();
            let mut wtotal = 0;

            let se = SelfEncryptor::new(storage, DataMap::None).expect(
                "Encryptor construction shouldn't fail.",
            );
            for element in &broken_data {
                se.write(element.1, element.0 as u64).wait().expect(
                    "Writing broken data to encryptor shouldn't fail.",
                );
                wtotal += element.1.len();
            }
            assert_eq!(wtotal, DATA_SIZE as usize);
            let mut decrypted = se.read(0u64, DATA_SIZE as u64).wait().expect(
                "Reading broken data from encryptor shouldn't fail.",
            );
            assert_eq!(original, decrypted);

            let mut overwrite = original[0..post_overlap.0 as usize].to_vec();
            overwrite.extend((post_overlap.1).to_vec().iter().cloned());
            overwrite.extend(
                original[post_position + 7..DATA_SIZE as usize]
                    .iter()
                    .cloned(),
            );
            se.write(post_overlap.1, post_overlap.0 as u64)
                .wait()
                .expect("Writing overlap to encryptor shouldn't fail.");
            decrypted = se.read(0u64, DATA_SIZE as u64).wait().expect(
                "Reading all data from encryptor shouldn't fail.",
            );
            assert_eq!(overwrite.len(), decrypted.len());
            assert_eq!(overwrite, decrypted);
        }
    }
}

#[test]
// The test writes random-sized pieces at random offsets and checks they can be read back.  The
// pieces may overlap or leave gaps in the file.  Gaps should be filled with 0s when read back.
fn write_random_sizes_out_of_sequence_with_gaps_and_overlaps() {
    let parts = 20usize;
    assert!((DATA_SIZE / MAX_CHUNK_SIZE) as u64 >= parts as u64);
    let mut rng = rand::thread_rng();
    let mut total_size = 0u64;
    let mut original = vec![0u8; DATA_SIZE as usize];

    let (data_map, storage) = {
        let storage = SimpleStorage::new();
        let self_encryptor = SelfEncryptor::new(storage, DataMap::None).expect(
            "Encryptor construction shouldn't fail.",
        );
        for i in 0..parts {
            // Get random values for the piece size and intended offset
            let piece_size = rng.gen_range(1, MAX_CHUNK_SIZE + 1);
            let offset = rng.gen_range(0, DATA_SIZE - MAX_CHUNK_SIZE);
            total_size = std::cmp::max(total_size, (offset + piece_size) as u64);
            assert!(DATA_SIZE as u64 >= total_size);

            // Create the random piece and copy to the comparison vector.
            let piece = random_bytes(piece_size as usize);
            for a in 0..piece_size {
                original[(offset + a) as usize] = piece[a as usize];
            }

            // Write the piece to the encryptor and check it can be read back.
            self_encryptor.write(&piece, offset as u64).wait().expect(
                &format!(
                    "Writing part {} to encryptor shouldn't fail.",
                    i
                ),
            );
            let decrypted = self_encryptor
                .read(offset as u64, piece_size as u64)
                .wait()
                .expect(&format!(
                    "Reading part {} from encryptor shouldn't fail.",
                    i
                ));
            assert_eq!(decrypted, piece);
            assert_eq!(total_size, self_encryptor.len());
        }

        // Read back DATA_SIZE from the encryptor.  This will contain all that was written, plus
        // likely will be reading past EOF.  Reading past the end shouldn't affect the file size.
        let decrypted = self_encryptor.read(0u64, DATA_SIZE as u64).wait().expect(
            "Reading all data from encryptor shouldn't fail.",
        );
        assert_eq!(decrypted.len(), DATA_SIZE as usize);
        assert_eq!(decrypted, original);
        assert_eq!(total_size, self_encryptor.len());

        // Close the encryptor, open a new one with the returned DataMap, and read back DATA_SIZE
        // again.
        self_encryptor.close().wait().expect(
            "Closing encryptor shouldn't fail.",
        )
    };

    let self_encryptor =
        SelfEncryptor::new(storage, data_map).expect("Encryptor construction shouldn't fail.");
    let decrypted = self_encryptor.read(0u64, DATA_SIZE as u64).wait().expect(
        "Reading all data again from encryptor shouldn't fail.",
    );
    assert_eq!(decrypted.len(), DATA_SIZE as usize);
    assert_eq!(decrypted, original);
    assert_eq!(total_size, self_encryptor.len());
}

#[test]
fn cross_platform_check() {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    static EXPECTED_HASHES: [[u8; 32]; 3] = [
        [112, 163, 2, 140, 28, 160, 116, 206, 51, 61, 221, 27, 149, 102, 99, 108, 113, 91, 173, 22,
         220, 25, 201, 33, 134, 33, 143, 144, 42, 122, 84, 168],
        [252, 228, 181, 29, 49, 24, 146, 77, 195, 138, 81, 227, 196, 199, 178, 147, 207, 111, 193,
         132, 78, 98, 23, 191, 132, 4, 197, 171, 152, 121, 123, 237],
        [143, 195, 109, 18, 136, 189, 34, 127, 149, 196, 184, 187, 5, 118, 223, 210, 111, 130, 75,
         89, 45, 177, 4, 172, 117, 10, 46, 40, 91, 69, 52, 149]
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
        let self_encryptor = SelfEncryptor::new(storage, DataMap::None).expect(
            "Encryptor construction shouldn't fail.",
        );
        self_encryptor.write(&chars0[..], 0).wait().expect(
            "Writing first slice to encryptor shouldn't fail.",
        );
        self_encryptor
            .write(&chars1[..], chars0.len() as u64)
            .wait()
            .expect("Writing second slice to encryptor shouldn't fail.");
        self_encryptor
            .write(&chars2[..], chars0.len() as u64 + chars1.len() as u64)
            .wait()
            .expect("Writing third slice to encryptor shouldn't fail.");
        self_encryptor.close().wait().expect(
            "Closing encryptor shouldn't fail.",
        )
    };

    assert_eq!(3, data_map.get_chunks().len());

    let chunks = data_map.get_chunks();

    for i in 0..chunks.len() {
        assert_eq!(&EXPECTED_HASHES[i][..], &chunks[i].hash[..]);
    }
}
