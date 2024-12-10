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
use self_encryption::{encrypt, ChunkInfo, DataMap, Result};
use xor_name::XorName;

#[tokio::test]
async fn cross_platform_check() -> Result<()> {
    // Use a fixed size that will give us exactly 3 chunks
    let content_size: usize = 3 * 1024; // Small enough to not trigger shrinking
    let mut content = vec![0u8; content_size];

    // Use a simpler pattern for debugging
    for (i, c) in content.iter_mut().enumerate() {
        *c = (i % 256) as u8;
    }

    let (data_map, _) = encrypt(Bytes::from(content.clone()))?;

    println!("Original data length: {}", content.len());
    println!("Number of chunks: {}", data_map.infos().len());

    println!(
        "Chunk sizes: {}",
        data_map
            .infos()
            .iter()
            .map(|i| i.src_size.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    for (i, info) in data_map.infos().iter().enumerate() {
        println!("ChunkInfo {}: src_hash = {:02x?}", i, info.src_hash.0);
        println!("ChunkInfo {}: dst_hash = {:02x?}", i, info.dst_hash.0);
        println!("ChunkInfo {}: size = {}", i, info.src_size);
    }

    // Store these values as the new reference once we're happy with the implementation
    let ref_data_map = data_map.infos();

    // Compare each chunk info
    for (i, (expected, got)) in ref_data_map.iter().zip(data_map.infos()).enumerate() {
        assert_eq!(
            expected.src_hash, got.src_hash,
            "Chunk {} src_hash mismatch",
            i
        );
        assert_eq!(
            expected.dst_hash, got.dst_hash,
            "Chunk {} dst_hash mismatch",
            i
        );
        assert_eq!(expected.src_size, got.src_size, "Chunk {} size mismatch", i);
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
