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
                219, 126, 234, 157, 168, 33, 205, 18, 204, 78, 149, 18, 22, 54, 103, 73, 141, 12,
                117, 17, 35, 254, 53, 150, 79, 197, 88, 114, 238, 177, 48, 93,
            ]),
            dst_hash: XorName([
                204, 240, 217, 132, 100, 215, 171, 33, 90, 1, 108, 6, 172, 62, 8, 60, 208, 224,
                116, 207, 161, 122, 91, 214, 251, 42, 35, 154, 77, 236, 213, 253,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                219, 47, 201, 219, 216, 145, 224, 77, 241, 157, 51, 40, 242, 41, 35, 113, 17, 119,
                219, 73, 255, 216, 109, 53, 186, 124, 120, 18, 249, 186, 15, 148,
            ]),
            dst_hash: XorName([
                37, 179, 49, 19, 60, 7, 225, 53, 15, 235, 172, 236, 119, 138, 221, 166, 189, 85,
                179, 77, 156, 176, 129, 44, 98, 12, 219, 33, 253, 176, 49, 103,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                42, 138, 223, 201, 28, 93, 24, 185, 59, 200, 204, 22, 200, 132, 240, 164, 187, 180,
                202, 125, 203, 80, 69, 81, 21, 166, 41, 84, 98, 72, 206, 203,
            ]),
            dst_hash: XorName([
                89, 25, 248, 114, 79, 140, 181, 47, 244, 185, 221, 171, 183, 67, 237, 112, 0, 37,
                110, 147, 41, 17, 75, 17, 153, 86, 162, 69, 66, 87, 123, 35,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                116, 203, 36, 151, 223, 185, 147, 241, 165, 77, 35, 251, 112, 42, 178, 36, 20, 89,
                89, 5, 98, 68, 172, 151, 206, 187, 239, 250, 118, 155, 244, 207,
            ]),
            dst_hash: XorName([
                241, 142, 204, 80, 198, 99, 88, 36, 210, 93, 219, 252, 38, 142, 173, 6, 157, 229,
                39, 45, 0, 179, 59, 151, 60, 131, 185, 63, 202, 132, 162, 17,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                95, 173, 127, 179, 190, 53, 69, 45, 11, 154, 226, 209, 45, 246, 159, 96, 32, 249,
                216, 235, 19, 41, 250, 191, 215, 224, 176, 14, 34, 191, 160, 106,
            ]),
            dst_hash: XorName([
                103, 69, 255, 226, 146, 17, 231, 154, 90, 38, 210, 75, 162, 201, 2, 59, 215, 182,
                150, 95, 177, 198, 219, 209, 228, 188, 126, 250, 27, 54, 56, 99,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                163, 241, 229, 93, 242, 155, 72, 211, 238, 58, 111, 154, 146, 49, 182, 133, 171,
                225, 221, 56, 65, 67, 9, 139, 100, 86, 232, 85, 79, 180, 186, 108,
            ]),
            dst_hash: XorName([
                189, 113, 141, 61, 111, 116, 244, 147, 212, 24, 208, 153, 233, 190, 254, 162, 197,
                130, 131, 131, 255, 72, 208, 89, 159, 111, 158, 158, 224, 28, 46, 147,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                46, 200, 113, 112, 165, 81, 235, 239, 206, 160, 187, 237, 135, 106, 175, 209, 221,
                210, 98, 211, 109, 139, 148, 51, 69, 194, 59, 164, 233, 114, 97, 243,
            ]),
            dst_hash: XorName([
                179, 88, 79, 6, 239, 240, 23, 116, 172, 95, 114, 121, 235, 69, 113, 49, 110, 203,
                140, 30, 113, 81, 216, 20, 161, 90, 89, 144, 13, 3, 138, 68,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                174, 217, 199, 201, 49, 242, 175, 7, 34, 239, 171, 251, 62, 82, 35, 63, 222, 214,
                164, 11, 231, 124, 111, 103, 212, 96, 91, 37, 142, 231, 170, 130,
            ]),
            dst_hash: XorName([
                15, 201, 129, 212, 144, 106, 28, 18, 203, 252, 184, 192, 227, 103, 205, 84, 64,
                213, 216, 219, 143, 159, 165, 193, 52, 107, 131, 201, 202, 233, 6, 217,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                159, 102, 70, 141, 68, 186, 107, 206, 249, 129, 2, 70, 143, 122, 78, 205, 39, 186,
                164, 142, 131, 56, 117, 175, 137, 186, 138, 241, 79, 3, 75, 154,
            ]),
            dst_hash: XorName([
                113, 87, 27, 67, 52, 142, 146, 226, 92, 145, 51, 229, 63, 106, 114, 57, 135, 250,
                152, 243, 245, 78, 119, 87, 212, 180, 183, 112, 99, 152, 200, 176,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                239, 251, 194, 216, 97, 235, 196, 255, 59, 222, 207, 27, 35, 73, 250, 32, 201, 140,
                175, 43, 101, 174, 62, 153, 145, 2, 217, 33, 233, 161, 127, 107,
            ]),
            dst_hash: XorName([
                29, 195, 244, 233, 138, 41, 172, 69, 156, 153, 87, 14, 190, 138, 255, 255, 129, 43,
                63, 96, 194, 160, 41, 191, 171, 119, 160, 152, 200, 243, 246, 36,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                25, 175, 98, 0, 134, 36, 139, 245, 80, 92, 27, 143, 202, 77, 217, 143, 44, 36, 87,
                62, 182, 135, 14, 120, 226, 225, 161, 138, 110, 177, 235, 54,
            ]),
            dst_hash: XorName([
                172, 33, 245, 100, 121, 102, 140, 62, 178, 240, 93, 147, 167, 17, 46, 21, 35, 229,
                30, 8, 209, 234, 22, 150, 204, 128, 68, 236, 191, 219, 171, 249,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                57, 241, 164, 14, 86, 68, 167, 140, 170, 14, 165, 107, 238, 236, 132, 209, 58, 28,
                45, 236, 254, 44, 82, 109, 192, 224, 20, 11, 111, 202, 179, 130,
            ]),
            dst_hash: XorName([
                160, 36, 218, 188, 0, 156, 21, 167, 57, 68, 179, 236, 76, 171, 59, 132, 46, 110,
                107, 201, 222, 26, 81, 30, 91, 44, 107, 214, 70, 67, 117, 120,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                68, 196, 12, 207, 232, 16, 29, 151, 155, 96, 58, 204, 252, 230, 226, 158, 20, 184,
                118, 135, 192, 47, 178, 188, 109, 12, 152, 182, 146, 159, 47, 33,
            ]),
            dst_hash: XorName([
                19, 39, 174, 89, 12, 246, 59, 67, 9, 153, 193, 93, 220, 65, 7, 102, 36, 165, 130,
                249, 77, 19, 201, 11, 15, 54, 59, 7, 142, 45, 175, 36,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                212, 159, 140, 147, 119, 151, 242, 165, 245, 125, 54, 65, 146, 27, 236, 131, 155,
                104, 229, 101, 52, 79, 163, 115, 125, 229, 132, 126, 193, 130, 179, 224,
            ]),
            dst_hash: XorName([
                141, 222, 194, 2, 170, 29, 133, 118, 201, 211, 212, 197, 47, 22, 19, 28, 113, 237,
                20, 56, 84, 231, 220, 117, 4, 179, 20, 37, 182, 172, 5, 255,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                136, 62, 136, 215, 197, 71, 206, 117, 90, 53, 112, 112, 207, 30, 142, 21, 37, 205,
                133, 27, 79, 56, 206, 133, 56, 143, 101, 85, 67, 221, 189, 89,
            ]),
            dst_hash: XorName([
                81, 255, 154, 128, 180, 35, 54, 38, 8, 92, 122, 222, 48, 76, 42, 128, 97, 133, 183,
                235, 100, 153, 31, 203, 9, 98, 230, 151, 159, 21, 36, 45,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                209, 69, 131, 15, 104, 163, 253, 48, 229, 151, 1, 210, 195, 41, 13, 161, 178, 38,
                20, 251, 181, 108, 61, 130, 244, 248, 13, 102, 172, 114, 233, 188,
            ]),
            dst_hash: XorName([
                64, 12, 24, 206, 112, 190, 170, 66, 54, 224, 196, 20, 147, 67, 68, 159, 149, 66,
                253, 41, 135, 206, 218, 251, 158, 141, 49, 73, 251, 239, 205, 83,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                26, 4, 13, 18, 246, 160, 41, 103, 30, 143, 23, 14, 158, 36, 8, 59, 202, 142, 207,
                168, 106, 101, 183, 129, 131, 46, 129, 105, 140, 138, 165, 129,
            ]),
            dst_hash: XorName([
                223, 62, 102, 183, 190, 193, 57, 221, 227, 141, 71, 155, 190, 233, 203, 52, 120,
                125, 187, 172, 192, 122, 219, 30, 54, 225, 228, 228, 29, 124, 241, 114,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                219, 126, 234, 157, 168, 33, 205, 18, 204, 78, 149, 18, 22, 54, 103, 73, 141, 12,
                117, 17, 35, 254, 53, 150, 79, 197, 88, 114, 238, 177, 48, 93,
            ]),
            dst_hash: XorName([
                61, 155, 171, 186, 161, 248, 186, 173, 56, 243, 48, 22, 58, 1, 214, 20, 86, 65,
                159, 25, 31, 91, 4, 134, 235, 95, 201, 1, 142, 251, 214, 233,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                219, 47, 201, 219, 216, 145, 224, 77, 241, 157, 51, 40, 242, 41, 35, 113, 17, 119,
                219, 73, 255, 216, 109, 53, 186, 124, 120, 18, 249, 186, 15, 148,
            ]),
            dst_hash: XorName([
                37, 179, 49, 19, 60, 7, 225, 53, 15, 235, 172, 236, 119, 138, 221, 166, 189, 85,
                179, 77, 156, 176, 129, 44, 98, 12, 219, 33, 253, 176, 49, 103,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                17, 231, 255, 196, 4, 112, 171, 213, 233, 184, 84, 58, 146, 133, 168, 80, 157, 152,
                173, 116, 168, 60, 119, 68, 148, 0, 222, 168, 83, 118, 80, 139,
            ]),
            dst_hash: XorName([
                80, 192, 98, 37, 201, 54, 113, 3, 31, 180, 161, 210, 6, 214, 34, 170, 249, 207, 89,
                144, 74, 126, 55, 120, 51, 111, 43, 162, 255, 32, 124, 33,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                189, 122, 160, 132, 187, 5, 7, 64, 97, 132, 57, 135, 236, 221, 96, 195, 147, 154,
                80, 127, 54, 243, 229, 18, 140, 91, 76, 43, 109, 113, 44, 107,
            ]),
            dst_hash: XorName([
                2, 130, 159, 7, 43, 155, 187, 168, 152, 0, 42, 163, 216, 125, 34, 109, 126, 62,
                189, 28, 201, 61, 157, 191, 32, 235, 170, 155, 181, 211, 69, 43,
            ]),
            index: 0,
            src_size: 0,
        },
    ];

    for (i, c) in data_map.infos().into_iter().enumerate() {
        assert_eq!(c.src_hash, ref_data_map[i].src_hash);
        assert_eq!(c.dst_hash, ref_data_map[i].dst_hash);
    }

    Ok(())
}
