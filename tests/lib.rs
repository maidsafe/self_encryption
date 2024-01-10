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
use self_encryption::{encrypt, ChunkInfo, Result, MAX_CHUNK_SIZE};
use xor_name::XorName;

#[tokio::test]
async fn cross_platform_check() -> Result<()> {
    let content_size: usize = 20 * MAX_CHUNK_SIZE + 100;
    let mut content = vec![0u8; content_size];
    for (i, c) in content.iter_mut().enumerate().take(content_size) {
        *c = (i % 17) as u8;
    }

    let (data_map, _) = encrypt(Bytes::from(content))?;

    // (NB: this hard-coded ref needs update if algorithm changes)
    let ref_data_map = vec![
        ChunkInfo {
            src_hash: XorName([
                248, 242, 229, 119, 92, 211, 180, 222, 177, 34, 82, 94, 51, 178, 62, 12, 185, 77,
                145, 206, 168, 75, 176, 141, 46, 197, 1, 83, 199, 165, 37, 28,
            ]),
            dst_hash: XorName([
                160, 57, 64, 193, 147, 235, 173, 54, 53, 206, 248, 12, 40, 147, 119, 107, 154, 21,
                50, 57, 151, 18, 151, 0, 95, 157, 103, 220, 160, 79, 248, 85,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                68, 137, 10, 147, 116, 198, 83, 144, 156, 198, 68, 195, 94, 96, 125, 162, 213, 218,
                179, 255, 177, 143, 232, 48, 99, 204, 118, 246, 67, 243, 190, 96,
            ]),
            dst_hash: XorName([
                30, 212, 77, 155, 165, 236, 65, 212, 88, 181, 48, 138, 226, 135, 144, 227, 132,
                195, 223, 199, 172, 235, 51, 146, 109, 209, 54, 63, 34, 169, 91, 55,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                227, 224, 98, 89, 131, 120, 169, 214, 165, 171, 189, 187, 15, 7, 80, 133, 16, 63,
                74, 197, 17, 127, 22, 137, 171, 117, 34, 195, 186, 185, 51, 2,
            ]),
            dst_hash: XorName([
                166, 232, 206, 232, 6, 23, 232, 20, 105, 230, 249, 86, 35, 117, 181, 65, 192, 245,
                65, 130, 238, 50, 188, 82, 193, 115, 172, 113, 237, 33, 248, 102,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                48, 157, 209, 23, 176, 114, 223, 155, 203, 103, 11, 52, 211, 111, 167, 33, 13, 77,
                71, 6, 188, 152, 179, 76, 155, 59, 4, 92, 3, 9, 67, 227,
            ]),
            dst_hash: XorName([
                156, 144, 25, 237, 84, 230, 81, 90, 205, 79, 203, 161, 113, 141, 59, 138, 117, 157,
                50, 9, 46, 76, 68, 64, 254, 250, 59, 11, 27, 134, 114, 175,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                53, 238, 190, 32, 115, 7, 143, 124, 163, 186, 189, 137, 50, 118, 2, 232, 57, 223,
                124, 10, 239, 109, 31, 4, 77, 67, 150, 92, 207, 26, 53, 0,
            ]),
            dst_hash: XorName([
                146, 0, 118, 252, 165, 0, 60, 204, 12, 126, 121, 68, 193, 237, 32, 58, 78, 125,
                110, 49, 215, 140, 37, 90, 141, 80, 8, 205, 206, 94, 115, 91,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                208, 239, 194, 163, 28, 94, 172, 182, 163, 69, 43, 242, 76, 157, 70, 10, 49, 228,
                153, 45, 154, 149, 111, 131, 132, 48, 67, 149, 198, 188, 147, 187,
            ]),
            dst_hash: XorName([
                138, 105, 198, 150, 73, 205, 0, 204, 67, 235, 102, 199, 152, 47, 215, 34, 230, 6,
                211, 6, 72, 38, 102, 74, 161, 22, 201, 229, 73, 179, 241, 183,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                127, 180, 215, 240, 32, 8, 203, 232, 31, 47, 232, 156, 181, 145, 96, 189, 228, 127,
                8, 243, 144, 169, 251, 212, 128, 243, 90, 159, 209, 101, 22, 26,
            ]),
            dst_hash: XorName([
                163, 215, 111, 245, 3, 80, 107, 218, 200, 254, 69, 43, 230, 168, 85, 162, 65, 230,
                46, 203, 49, 1, 99, 25, 102, 218, 105, 129, 215, 124, 132, 104,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                79, 17, 134, 221, 54, 248, 197, 215, 92, 180, 23, 186, 143, 71, 41, 138, 151, 174,
                241, 128, 212, 7, 63, 136, 61, 132, 177, 198, 129, 20, 168, 87,
            ]),
            dst_hash: XorName([
                207, 109, 164, 0, 68, 241, 197, 210, 209, 143, 239, 76, 198, 12, 225, 162, 159, 37,
                175, 0, 159, 239, 160, 178, 18, 75, 206, 126, 208, 0, 142, 213,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                119, 172, 206, 200, 245, 153, 32, 24, 14, 70, 123, 251, 75, 66, 0, 50, 44, 145,
                126, 243, 42, 39, 232, 208, 117, 190, 105, 120, 169, 193, 192, 228,
            ]),
            dst_hash: XorName([
                243, 107, 119, 61, 216, 70, 121, 241, 109, 84, 231, 232, 220, 177, 230, 158, 168,
                204, 215, 19, 185, 45, 178, 225, 103, 198, 119, 238, 144, 175, 38, 147,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                52, 10, 82, 208, 199, 46, 246, 175, 107, 245, 168, 201, 212, 133, 79, 187, 24, 226,
                10, 241, 43, 148, 84, 103, 153, 32, 66, 36, 146, 87, 60, 37,
            ]),
            dst_hash: XorName([
                77, 167, 37, 235, 4, 230, 211, 221, 27, 211, 207, 32, 23, 202, 118, 100, 8, 199,
                67, 28, 195, 87, 141, 11, 24, 138, 34, 233, 63, 68, 123, 236,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                234, 15, 144, 252, 29, 7, 78, 150, 66, 143, 174, 179, 66, 68, 42, 120, 8, 164, 46,
                52, 160, 207, 208, 231, 27, 130, 21, 85, 37, 208, 47, 244,
            ]),
            dst_hash: XorName([
                207, 20, 30, 153, 250, 15, 151, 131, 100, 211, 67, 43, 61, 243, 191, 134, 242, 134,
                57, 183, 213, 94, 7, 240, 252, 121, 250, 158, 97, 246, 149, 112,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                19, 159, 237, 131, 18, 84, 26, 161, 106, 99, 30, 134, 241, 30, 186, 36, 119, 74,
                59, 254, 246, 37, 96, 24, 200, 211, 236, 79, 53, 174, 252, 32,
            ]),
            dst_hash: XorName([
                97, 110, 47, 182, 255, 22, 193, 218, 28, 21, 118, 43, 163, 189, 60, 14, 48, 88,
                197, 236, 146, 105, 40, 25, 53, 0, 90, 168, 159, 115, 143, 168,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                185, 120, 111, 228, 41, 75, 228, 6, 222, 23, 163, 157, 32, 254, 96, 15, 210, 204,
                1, 147, 238, 121, 11, 33, 57, 5, 45, 54, 79, 237, 135, 139,
            ]),
            dst_hash: XorName([
                52, 40, 33, 121, 186, 17, 252, 107, 128, 67, 227, 187, 86, 57, 142, 200, 119, 201,
                141, 120, 246, 70, 169, 99, 84, 208, 167, 233, 13, 125, 224, 168,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                183, 193, 139, 225, 128, 162, 132, 138, 184, 75, 153, 229, 203, 147, 49, 174, 96,
                73, 135, 218, 79, 235, 79, 135, 162, 223, 248, 58, 82, 35, 196, 153,
            ]),
            dst_hash: XorName([
                129, 161, 112, 120, 153, 202, 222, 238, 92, 86, 180, 251, 231, 79, 103, 59, 158,
                156, 53, 126, 49, 0, 223, 72, 66, 83, 34, 154, 249, 74, 147, 147,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                53, 1, 114, 234, 6, 112, 255, 8, 148, 43, 130, 202, 155, 114, 99, 246, 81, 204, 77,
                60, 119, 237, 100, 198, 159, 144, 203, 60, 157, 246, 205, 22,
            ]),
            dst_hash: XorName([
                235, 170, 170, 154, 173, 162, 71, 155, 236, 208, 97, 41, 167, 62, 209, 5, 255, 65,
                75, 239, 235, 133, 161, 30, 152, 3, 221, 99, 140, 207, 31, 64,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                24, 147, 188, 118, 102, 72, 207, 163, 202, 63, 40, 237, 169, 100, 8, 190, 23, 67,
                243, 179, 196, 232, 214, 36, 76, 83, 220, 76, 241, 238, 107, 23,
            ]),
            dst_hash: XorName([
                115, 143, 30, 6, 239, 108, 101, 10, 213, 216, 75, 254, 13, 110, 10, 245, 50, 189,
                83, 39, 63, 72, 11, 160, 107, 139, 123, 181, 64, 233, 190, 200,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                100, 94, 19, 195, 150, 133, 161, 134, 150, 106, 44, 152, 201, 113, 171, 176, 147,
                244, 165, 93, 46, 227, 247, 118, 188, 29, 130, 19, 130, 137, 244, 15,
            ]),
            dst_hash: XorName([
                120, 86, 200, 233, 111, 96, 122, 72, 234, 77, 181, 205, 248, 56, 175, 55, 124, 174,
                152, 163, 125, 67, 25, 33, 90, 151, 57, 103, 27, 123, 100, 148,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                248, 242, 229, 119, 92, 211, 180, 222, 177, 34, 82, 94, 51, 178, 62, 12, 185, 77,
                145, 206, 168, 75, 176, 141, 46, 197, 1, 83, 199, 165, 37, 28,
            ]),
            dst_hash: XorName([
                148, 17, 25, 147, 128, 108, 212, 70, 12, 32, 68, 96, 192, 215, 241, 123, 162, 224,
                223, 52, 230, 27, 100, 122, 97, 85, 148, 53, 103, 230, 21, 11,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                68, 137, 10, 147, 116, 198, 83, 144, 156, 198, 68, 195, 94, 96, 125, 162, 213, 218,
                179, 255, 177, 143, 232, 48, 99, 204, 118, 246, 67, 243, 190, 96,
            ]),
            dst_hash: XorName([
                30, 212, 77, 155, 165, 236, 65, 212, 88, 181, 48, 138, 226, 135, 144, 227, 132,
                195, 223, 199, 172, 235, 51, 146, 109, 209, 54, 63, 34, 169, 91, 55,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                227, 224, 98, 89, 131, 120, 169, 214, 165, 171, 189, 187, 15, 7, 80, 133, 16, 63,
                74, 197, 17, 127, 22, 137, 171, 117, 34, 195, 186, 185, 51, 2,
            ]),
            dst_hash: XorName([
                166, 232, 206, 232, 6, 23, 232, 20, 105, 230, 249, 86, 35, 117, 181, 65, 192, 245,
                65, 130, 238, 50, 188, 82, 193, 115, 172, 113, 237, 33, 248, 102,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                199, 77, 9, 166, 29, 63, 254, 6, 165, 71, 110, 151, 121, 199, 60, 144, 197, 6, 92,
                182, 237, 202, 223, 171, 20, 80, 193, 237, 148, 96, 190, 70,
            ]),
            dst_hash: XorName([
                221, 131, 122, 148, 84, 180, 72, 155, 240, 84, 4, 189, 156, 65, 164, 204, 215, 198,
                118, 227, 41, 95, 185, 117, 152, 128, 119, 205, 173, 180, 155, 86,
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
