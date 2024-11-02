// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Tests for the self-encryption crate

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
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

use bytes::Bytes;
use self_encryption::{encrypt, ChunkInfo, DataMap, Result, MAX_CHUNK_SIZE};
use xor_name::XorName;

#[tokio::test]
async fn cross_platform_check() -> Result<()> {
    let content_size: usize = 20 * *MAX_CHUNK_SIZE + 100;
    let mut content = vec![0u8; content_size];
    for (i, c) in content.iter_mut().enumerate().take(content_size) {
        *c = (i % 17) as u8;
    }

    let (data_map, _) = encrypt(Bytes::from(content))?;

    // (NB: this hard-coded ref needs update if algorithm changes)
    let ref_data_map = vec![
        ChunkInfo {
            src_hash: XorName([
                219, 177, 84, 234, 189, 172, 82, 64, 169, 100, 5, 56, 3, 43, 142, 126, 51, 235,
                194, 243, 30, 130, 132, 197, 137, 36, 170, 62, 46, 44, 176, 201,
            ]),
            dst_hash: XorName([
                248, 155, 46, 153, 173, 52, 226, 212, 133, 172, 107, 200, 72, 150, 41, 50, 116, 77,
                85, 92, 67, 168, 25, 56, 93, 61, 209, 194, 65, 172, 227, 130,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                65, 81, 63, 82, 119, 126, 216, 9, 44, 18, 160, 174, 225, 8, 202, 32, 245, 140, 14,
                169, 252, 209, 97, 96, 134, 165, 102, 106, 250, 196, 27, 70,
            ]),
            dst_hash: XorName([
                42, 62, 224, 152, 136, 214, 91, 160, 125, 249, 229, 115, 81, 220, 213, 34, 29, 173,
                235, 99, 67, 210, 234, 160, 79, 254, 208, 174, 117, 127, 205, 36,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                80, 237, 26, 5, 69, 59, 53, 210, 44, 236, 191, 69, 92, 39, 113, 124, 206, 169, 5,
                126, 189, 2, 146, 80, 68, 186, 142, 219, 37, 170, 135, 61,
            ]),
            dst_hash: XorName([
                200, 203, 81, 29, 131, 156, 60, 140, 166, 254, 103, 60, 212, 223, 22, 41, 85, 192,
                140, 154, 33, 34, 188, 94, 84, 101, 62, 254, 164, 81, 209, 154,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                168, 223, 46, 4, 138, 115, 226, 112, 179, 67, 36, 186, 170, 199, 21, 195, 41, 17,
                99, 227, 30, 226, 46, 42, 78, 210, 189, 107, 185, 167, 32, 74,
            ]),
            dst_hash: XorName([
                42, 138, 132, 73, 12, 78, 47, 136, 153, 177, 25, 247, 202, 227, 145, 31, 193, 9,
                33, 63, 89, 160, 240, 51, 189, 72, 94, 193, 75, 144, 58, 233,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                41, 137, 66, 160, 103, 223, 72, 133, 180, 83, 8, 139, 180, 108, 20, 196, 106, 59,
                73, 6, 160, 187, 8, 16, 93, 157, 142, 155, 85, 118, 239, 192,
            ]),
            dst_hash: XorName([
                220, 162, 48, 182, 212, 178, 139, 207, 231, 191, 209, 53, 187, 22, 66, 221, 242,
                66, 220, 19, 96, 201, 137, 25, 101, 184, 1, 178, 80, 204, 253, 179,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                48, 226, 1, 203, 69, 49, 140, 152, 90, 232, 209, 42, 178, 241, 60, 11, 24, 2, 196,
                26, 14, 229, 127, 68, 119, 116, 135, 195, 248, 217, 227, 78,
            ]),
            dst_hash: XorName([
                168, 232, 79, 142, 149, 51, 198, 62, 224, 177, 45, 203, 243, 51, 12, 23, 104, 80,
                174, 5, 246, 234, 54, 70, 58, 11, 100, 117, 60, 67, 65, 64,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                92, 201, 208, 153, 241, 202, 111, 28, 118, 47, 47, 32, 121, 48, 203, 48, 230, 107,
                102, 195, 184, 106, 245, 173, 157, 171, 139, 50, 28, 56, 80, 225,
            ]),
            dst_hash: XorName([
                199, 114, 193, 185, 26, 6, 140, 71, 142, 73, 45, 198, 110, 126, 232, 182, 226, 85,
                137, 210, 69, 24, 139, 163, 236, 47, 155, 130, 43, 229, 148, 172,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                50, 8, 67, 204, 158, 4, 255, 227, 50, 18, 176, 150, 249, 233, 188, 72, 86, 217, 61,
                100, 161, 131, 124, 26, 245, 166, 44, 16, 125, 230, 153, 190,
            ]),
            dst_hash: XorName([
                151, 255, 185, 86, 239, 216, 199, 233, 149, 16, 247, 122, 156, 66, 178, 95, 32,
                219, 218, 228, 63, 23, 34, 207, 140, 20, 75, 2, 225, 3, 243, 193,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                132, 6, 224, 90, 168, 59, 66, 114, 199, 67, 140, 171, 226, 213, 141, 21, 32, 143,
                4, 192, 143, 64, 253, 216, 200, 76, 162, 121, 130, 169, 89, 229,
            ]),
            dst_hash: XorName([
                126, 221, 146, 123, 252, 37, 250, 160, 75, 182, 9, 39, 80, 87, 93, 229, 173, 203,
                31, 203, 208, 190, 226, 111, 87, 78, 246, 141, 85, 237, 82, 87,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                238, 37, 229, 233, 96, 228, 150, 41, 89, 130, 145, 198, 50, 165, 207, 108, 15, 167,
                122, 116, 209, 223, 68, 203, 24, 169, 74, 93, 44, 170, 24, 233,
            ]),
            dst_hash: XorName([
                109, 123, 118, 55, 228, 175, 144, 231, 103, 223, 51, 185, 146, 37, 47, 46, 185,
                208, 140, 202, 231, 18, 70, 47, 48, 245, 254, 93, 185, 120, 17, 143,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                70, 131, 32, 243, 131, 152, 215, 108, 51, 231, 184, 113, 117, 8, 164, 174, 151,
                152, 232, 29, 11, 58, 104, 46, 55, 81, 249, 207, 213, 77, 151, 237,
            ]),
            dst_hash: XorName([
                85, 8, 26, 126, 9, 32, 28, 70, 112, 134, 226, 170, 46, 25, 115, 222, 131, 175, 117,
                141, 96, 45, 201, 108, 148, 142, 12, 27, 184, 109, 44, 70,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                50, 175, 184, 213, 76, 189, 138, 227, 190, 200, 141, 26, 235, 78, 173, 171, 137,
                95, 43, 119, 8, 145, 253, 102, 189, 117, 247, 89, 246, 214, 129, 182,
            ]),
            dst_hash: XorName([
                240, 135, 94, 165, 73, 209, 176, 218, 159, 232, 76, 254, 32, 84, 238, 245, 226, 2,
                227, 194, 95, 48, 125, 227, 42, 118, 85, 160, 39, 83, 2, 124,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                160, 175, 104, 136, 24, 18, 192, 185, 147, 31, 227, 81, 212, 143, 214, 63, 52, 62,
                218, 48, 35, 220, 0, 184, 62, 137, 152, 35, 144, 149, 229, 86,
            ]),
            dst_hash: XorName([
                198, 136, 45, 128, 93, 197, 174, 93, 27, 19, 218, 211, 184, 14, 214, 97, 182, 149,
                36, 161, 66, 19, 118, 105, 240, 100, 104, 1, 192, 87, 236, 132,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                158, 201, 252, 234, 200, 107, 72, 126, 69, 234, 165, 203, 122, 90, 36, 46, 82, 183,
                61, 84, 128, 62, 118, 112, 222, 74, 164, 198, 20, 217, 96, 143,
            ]),
            dst_hash: XorName([
                187, 81, 209, 66, 106, 200, 142, 130, 197, 102, 170, 211, 120, 197, 65, 210, 229,
                57, 27, 231, 120, 217, 180, 231, 34, 155, 32, 41, 78, 74, 193, 115,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                208, 35, 197, 158, 225, 12, 21, 130, 132, 59, 227, 65, 238, 178, 232, 169, 186, 48,
                27, 106, 153, 46, 168, 196, 199, 70, 105, 236, 161, 167, 109, 43,
            ]),
            dst_hash: XorName([
                145, 170, 97, 191, 204, 99, 185, 85, 4, 199, 204, 34, 104, 219, 97, 0, 184, 167,
                32, 173, 83, 249, 254, 42, 251, 10, 168, 231, 211, 67, 70, 120,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                191, 47, 52, 224, 196, 196, 113, 118, 243, 7, 35, 213, 174, 114, 228, 229, 165,
                182, 217, 102, 55, 16, 174, 159, 197, 166, 75, 192, 182, 186, 173, 1,
            ]),
            dst_hash: XorName([
                130, 233, 29, 245, 160, 80, 144, 117, 139, 251, 91, 240, 232, 173, 233, 168, 61,
                138, 88, 0, 92, 133, 16, 118, 29, 118, 131, 218, 42, 197, 132, 54,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                116, 242, 114, 183, 140, 120, 52, 135, 104, 100, 112, 208, 10, 8, 99, 108, 78, 75,
                84, 111, 100, 57, 241, 143, 117, 172, 80, 19, 43, 142, 225, 227,
            ]),
            dst_hash: XorName([
                0, 52, 220, 168, 128, 29, 228, 70, 0, 29, 73, 244, 83, 7, 171, 237, 31, 236, 231,
                24, 148, 14, 100, 16, 117, 82, 41, 11, 216, 126, 209, 127,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                219, 177, 84, 234, 189, 172, 82, 64, 169, 100, 5, 56, 3, 43, 142, 126, 51, 235,
                194, 243, 30, 130, 132, 197, 137, 36, 170, 62, 46, 44, 176, 201,
            ]),
            dst_hash: XorName([
                77, 246, 174, 53, 36, 156, 19, 157, 46, 142, 60, 60, 122, 133, 52, 118, 73, 80, 40,
                205, 174, 231, 211, 110, 38, 8, 189, 206, 102, 252, 166, 34,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                65, 81, 63, 82, 119, 126, 216, 9, 44, 18, 160, 174, 225, 8, 202, 32, 245, 140, 14,
                169, 252, 209, 97, 96, 134, 165, 102, 106, 250, 196, 27, 70,
            ]),
            dst_hash: XorName([
                42, 62, 224, 152, 136, 214, 91, 160, 125, 249, 229, 115, 81, 220, 213, 34, 29, 173,
                235, 99, 67, 210, 234, 160, 79, 254, 208, 174, 117, 127, 205, 36,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                80, 237, 26, 5, 69, 59, 53, 210, 44, 236, 191, 69, 92, 39, 113, 124, 206, 169, 5,
                126, 189, 2, 146, 80, 68, 186, 142, 219, 37, 170, 135, 61,
            ]),
            dst_hash: XorName([
                200, 203, 81, 29, 131, 156, 60, 140, 166, 254, 103, 60, 212, 223, 22, 41, 85, 192,
                140, 154, 33, 34, 188, 94, 84, 101, 62, 254, 164, 81, 209, 154,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                176, 37, 236, 132, 229, 46, 239, 66, 127, 19, 235, 251, 254, 140, 231, 120, 170,
                173, 169, 2, 98, 159, 72, 160, 215, 103, 243, 7, 179, 63, 61, 173,
            ]),
            dst_hash: XorName([
                160, 38, 187, 68, 9, 245, 147, 175, 244, 167, 195, 133, 79, 231, 89, 53, 165, 222,
                24, 162, 83, 158, 227, 193, 103, 232, 230, 209, 244, 58, 44, 208,
            ]),
            index: 0,
            src_size: 0,
        },
    ];

    for (i, c) in data_map.infos().into_iter().enumerate() {
        println!("expected[i].src_hash {:?}", ref_data_map[i].src_hash.0);
        println!("got            .src_hash {:?}", c.src_hash.0);
        println!("expected[i].dst_hash {:?}", ref_data_map[i].dst_hash.0);
        println!("got            .dst_hash {:?}", c.dst_hash.0);

        assert_eq!(c.src_hash, ref_data_map[i].src_hash);
        assert_eq!(c.dst_hash, ref_data_map[i].dst_hash);
    }

    Ok(())
}

// Add this test to verify the new child functionality
#[test]
fn data_map_with_child() {
    let chunk_infos = vec![ChunkInfo {
        index: 0,
        dst_hash: XorName([1; 32]),
        src_hash: XorName([2; 32]),
        src_size: 1024,
    }];

    // Test DataMap without child
    let data_map = DataMap::new(chunk_infos.clone());
    assert_eq!(data_map.child(), None);
    assert_eq!(data_map.infos(), chunk_infos);

    // Test DataMap with child
    let child_value = 42;
    let data_map_with_child = DataMap::with_child(chunk_infos.clone(), child_value);
    assert_eq!(data_map_with_child.child(), Some(child_value));
    assert_eq!(data_map_with_child.infos(), chunk_infos);
}

#[test]
fn test_data_map_serialization() {
    let chunk_infos = vec![ChunkInfo {
        index: 0,
        dst_hash: XorName([1; 32]),
        src_hash: XorName([2; 32]),
        src_size: 1024,
    }];

    // Test serialization without child
    let data_map = DataMap::new(chunk_infos.clone());
    let serialized = bincode::serialize(&data_map).unwrap();
    let deserialized: DataMap = bincode::deserialize(&serialized).unwrap();
    assert_eq!(data_map, deserialized);
    assert_eq!(deserialized.child(), None);

    // Test serialization with child
    let data_map = DataMap::with_child(chunk_infos, 42);
    let serialized = bincode::serialize(&data_map).unwrap();
    let deserialized: DataMap = bincode::deserialize(&serialized).unwrap();
    assert_eq!(data_map, deserialized);
    assert_eq!(deserialized.child(), Some(42));
}

#[test]
fn test_data_map_debug() {
    let chunk_infos = vec![ChunkInfo {
        index: 0,
        dst_hash: XorName([1; 32]),
        src_hash: XorName([2; 32]),
        src_size: 1024,
    }];

    // Test Debug output without child
    let data_map = DataMap::new(chunk_infos.clone());
    let debug_str = format!("{:?}", data_map);
    assert!(!debug_str.contains("child:"));

    // Test Debug output with child
    let data_map = DataMap::with_child(chunk_infos, 42);
    let debug_str = format!("{:?}", data_map);
    assert!(debug_str.contains("child: 42"));
}

#[test]
fn test_data_map_len_and_is_child() {
    let chunk_infos = vec![
        ChunkInfo {
            index: 0,
            dst_hash: XorName([1; 32]),
            src_hash: XorName([2; 32]),
            src_size: 1024,
        },
        ChunkInfo {
            index: 1,
            dst_hash: XorName([3; 32]),
            src_hash: XorName([4; 32]),
            src_size: 1024,
        },
    ];

    // Test len() and is_child() for DataMap without child
    let data_map = DataMap::new(chunk_infos.clone());
    assert_eq!(data_map.len(), 2);
    assert!(!data_map.is_child());

    // Test len() and is_child() for DataMap with child
    let data_map_with_child = DataMap::with_child(chunk_infos, 42);
    assert_eq!(data_map_with_child.len(), 2);
    assert!(data_map_with_child.is_child());

    // Test len() for empty DataMap
    let empty_data_map = DataMap::new(vec![]);
    assert_eq!(empty_data_map.len(), 0);
    assert!(!empty_data_map.is_child());
}
