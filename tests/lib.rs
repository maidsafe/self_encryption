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
                1, 191, 37, 82, 168, 139, 50, 27, 119, 217, 158, 88, 244, 118, 4, 71, 49, 15, 172,
                227, 214, 105, 81, 11, 50, 58, 96, 156, 147, 219, 236, 186,
            ]),
            dst_hash: XorName([
                152, 155, 244, 65, 217, 201, 52, 237, 24, 106, 191, 243, 228, 165, 66, 14, 72, 114,
                180, 157, 179, 236, 253, 21, 134, 212, 188, 101, 240, 217, 174, 201,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                70, 167, 175, 234, 129, 244, 96, 51, 158, 113, 71, 88, 84, 169, 239, 15, 85, 111,
                44, 3, 249, 126, 57, 118, 26, 153, 43, 74, 159, 41, 147, 57,
            ]),
            dst_hash: XorName([
                229, 147, 217, 103, 109, 191, 187, 217, 110, 14, 21, 146, 148, 43, 114, 207, 198,
                102, 207, 87, 42, 139, 38, 196, 135, 12, 77, 12, 248, 13, 181, 134,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                171, 194, 73, 240, 87, 29, 132, 220, 54, 218, 201, 196, 14, 183, 237, 208, 198,
                117, 134, 74, 233, 247, 253, 71, 207, 159, 187, 51, 37, 31, 44, 135,
            ]),
            dst_hash: XorName([
                30, 132, 41, 165, 119, 139, 39, 196, 206, 114, 184, 222, 113, 135, 233, 86, 155,
                174, 10, 3, 95, 169, 98, 101, 100, 159, 233, 136, 251, 240, 74, 245,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                82, 3, 95, 123, 115, 59, 210, 194, 41, 42, 72, 62, 121, 230, 166, 61, 52, 92, 53,
                238, 210, 170, 83, 19, 200, 230, 44, 38, 218, 215, 211, 130,
            ]),
            dst_hash: XorName([
                25, 43, 75, 200, 115, 37, 103, 31, 215, 117, 163, 200, 173, 251, 150, 103, 39, 98,
                203, 94, 46, 31, 210, 28, 81, 42, 225, 50, 26, 188, 95, 211,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                196, 135, 172, 214, 39, 191, 73, 66, 60, 250, 142, 59, 111, 247, 134, 149, 242,
                119, 197, 45, 47, 203, 149, 119, 73, 134, 228, 190, 16, 18, 174, 91,
            ]),
            dst_hash: XorName([
                150, 110, 79, 50, 140, 107, 239, 132, 11, 251, 100, 244, 25, 135, 179, 200, 163,
                218, 219, 194, 135, 157, 1, 192, 100, 168, 5, 233, 98, 94, 99, 245,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                229, 175, 80, 150, 164, 236, 125, 226, 35, 114, 123, 124, 80, 156, 150, 199, 90,
                42, 63, 64, 176, 58, 91, 124, 202, 57, 17, 190, 14, 145, 101, 177,
            ]),
            dst_hash: XorName([
                113, 44, 23, 7, 203, 108, 244, 2, 93, 201, 237, 215, 137, 152, 155, 242, 82, 3,
                193, 81, 138, 172, 26, 92, 123, 82, 235, 55, 134, 137, 79, 245,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                85, 130, 20, 22, 144, 89, 93, 223, 30, 25, 187, 79, 177, 216, 155, 160, 167, 6, 47,
                129, 71, 161, 173, 217, 229, 166, 49, 166, 80, 7, 47, 216,
            ]),
            dst_hash: XorName([
                184, 22, 139, 2, 133, 170, 115, 78, 75, 240, 143, 229, 150, 198, 139, 36, 211, 123,
                176, 90, 175, 222, 125, 215, 192, 186, 99, 76, 50, 183, 47, 132,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                226, 20, 206, 139, 247, 215, 247, 241, 83, 85, 72, 4, 155, 12, 55, 46, 135, 248,
                93, 0, 64, 102, 185, 175, 7, 225, 224, 73, 169, 227, 7, 242,
            ]),
            dst_hash: XorName([
                12, 129, 199, 237, 73, 14, 99, 230, 8, 200, 185, 63, 188, 34, 48, 91, 153, 252, 12,
                95, 156, 98, 24, 232, 158, 150, 89, 114, 19, 201, 7, 222,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                208, 9, 236, 192, 3, 130, 111, 148, 115, 100, 165, 213, 95, 65, 82, 114, 78, 128,
                94, 143, 23, 16, 191, 92, 192, 55, 93, 78, 156, 57, 156, 7,
            ]),
            dst_hash: XorName([
                125, 117, 173, 97, 248, 10, 206, 154, 21, 24, 31, 235, 125, 5, 255, 64, 218, 208,
                133, 74, 24, 70, 43, 192, 49, 98, 81, 48, 76, 248, 37, 235,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                244, 213, 10, 128, 97, 150, 216, 70, 247, 25, 10, 209, 63, 213, 201, 113, 131, 90,
                228, 187, 131, 88, 168, 83, 157, 18, 30, 196, 179, 186, 86, 218,
            ]),
            dst_hash: XorName([
                159, 53, 116, 45, 41, 216, 2, 252, 125, 155, 131, 16, 153, 32, 4, 104, 126, 80,
                126, 235, 49, 250, 159, 246, 12, 236, 85, 58, 0, 116, 112, 123,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                45, 81, 75, 131, 22, 23, 134, 196, 95, 93, 110, 38, 68, 162, 114, 11, 194, 67, 89,
                139, 176, 13, 101, 250, 105, 72, 103, 238, 153, 73, 87, 102,
            ]),
            dst_hash: XorName([
                14, 114, 127, 47, 202, 63, 59, 123, 133, 217, 69, 231, 84, 222, 244, 170, 193, 157,
                122, 215, 74, 142, 82, 134, 164, 88, 135, 105, 232, 133, 46, 151,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                151, 239, 191, 106, 97, 105, 35, 25, 160, 88, 65, 51, 13, 175, 79, 213, 105, 165,
                58, 180, 247, 34, 98, 119, 216, 254, 142, 224, 88, 17, 181, 4,
            ]),
            dst_hash: XorName([
                134, 225, 14, 21, 55, 56, 192, 39, 220, 186, 127, 3, 135, 207, 110, 167, 145, 72,
                223, 53, 62, 92, 244, 9, 179, 48, 188, 91, 168, 44, 221, 25,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                174, 22, 58, 229, 150, 108, 14, 92, 224, 190, 13, 146, 209, 17, 238, 8, 162, 166,
                22, 217, 200, 0, 155, 252, 180, 151, 150, 106, 180, 222, 37, 23,
            ]),
            dst_hash: XorName([
                216, 219, 227, 102, 123, 92, 103, 254, 240, 70, 201, 183, 80, 74, 31, 149, 25, 220,
                30, 128, 102, 218, 58, 77, 133, 230, 136, 10, 144, 157, 170, 185,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                8, 86, 173, 107, 33, 53, 203, 103, 110, 36, 68, 111, 248, 54, 21, 80, 54, 82, 65,
                254, 75, 222, 170, 44, 93, 5, 159, 111, 145, 73, 208, 115,
            ]),
            dst_hash: XorName([
                71, 169, 76, 125, 170, 224, 49, 102, 125, 32, 121, 116, 201, 179, 157, 49, 139,
                108, 47, 200, 7, 10, 167, 126, 57, 245, 96, 87, 105, 21, 219, 56,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                245, 249, 241, 93, 232, 128, 212, 73, 136, 134, 122, 122, 112, 35, 8, 152, 20, 49,
                160, 86, 235, 160, 159, 208, 132, 92, 159, 103, 25, 83, 241, 26,
            ]),
            dst_hash: XorName([
                241, 159, 137, 242, 139, 3, 149, 100, 63, 239, 201, 220, 61, 158, 16, 188, 2, 48,
                85, 177, 63, 147, 144, 138, 168, 119, 30, 60, 95, 241, 234, 96,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                61, 74, 30, 216, 212, 230, 181, 65, 89, 10, 70, 209, 61, 45, 198, 83, 151, 47, 56,
                156, 120, 94, 65, 189, 176, 225, 157, 9, 176, 207, 117, 70,
            ]),
            dst_hash: XorName([
                92, 132, 135, 60, 124, 231, 237, 9, 245, 249, 136, 98, 173, 224, 218, 96, 131, 216,
                250, 189, 201, 200, 208, 114, 132, 231, 230, 36, 53, 224, 218, 177,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                4, 180, 185, 139, 161, 52, 207, 1, 34, 69, 2, 65, 121, 151, 13, 155, 221, 165, 244,
                39, 212, 249, 224, 89, 138, 146, 10, 168, 117, 128, 108, 32,
            ]),
            dst_hash: XorName([
                201, 161, 31, 226, 8, 76, 163, 123, 194, 189, 219, 68, 69, 203, 234, 72, 88, 246,
                222, 148, 232, 234, 150, 242, 117, 78, 158, 125, 8, 111, 129, 99,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                1, 191, 37, 82, 168, 139, 50, 27, 119, 217, 158, 88, 244, 118, 4, 71, 49, 15, 172,
                227, 214, 105, 81, 11, 50, 58, 96, 156, 147, 219, 236, 186,
            ]),
            dst_hash: XorName([
                47, 113, 172, 168, 113, 125, 67, 65, 33, 69, 215, 52, 208, 122, 23, 223, 171, 207,
                111, 238, 65, 161, 235, 117, 192, 92, 53, 222, 210, 17, 207, 38,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                70, 167, 175, 234, 129, 244, 96, 51, 158, 113, 71, 88, 84, 169, 239, 15, 85, 111,
                44, 3, 249, 126, 57, 118, 26, 153, 43, 74, 159, 41, 147, 57,
            ]),
            dst_hash: XorName([
                229, 147, 217, 103, 109, 191, 187, 217, 110, 14, 21, 146, 148, 43, 114, 207, 198,
                102, 207, 87, 42, 139, 38, 196, 135, 12, 77, 12, 248, 13, 181, 134,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                81, 24, 231, 238, 151, 30, 30, 65, 201, 238, 178, 5, 168, 84, 73, 40, 24, 202, 30,
                40, 50, 235, 162, 226, 166, 181, 45, 203, 200, 222, 214, 222,
            ]),
            dst_hash: XorName([
                77, 106, 171, 254, 135, 104, 146, 25, 103, 116, 130, 34, 187, 154, 91, 127, 127,
                133, 114, 248, 11, 145, 32, 60, 13, 59, 169, 130, 130, 154, 211, 15,
            ]),
            index: 0,
            src_size: 0,
        },
        ChunkInfo {
            src_hash: XorName([
                60, 69, 19, 98, 36, 184, 240, 192, 211, 97, 144, 237, 117, 232, 238, 236, 163, 69,
                91, 48, 18, 7, 8, 10, 229, 226, 193, 185, 154, 127, 112, 174,
            ]),
            dst_hash: XorName([
                100, 178, 213, 138, 164, 122, 179, 228, 178, 223, 216, 12, 105, 216, 34, 50, 91,
                117, 110, 68, 65, 225, 137, 137, 33, 115, 95, 177, 208, 63, 81, 120,
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
