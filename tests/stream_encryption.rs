// Copyright 2025 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

//! Tests for streaming encryption functionality.

use bytes::Bytes;
use self_encryption::{stream_encrypt, test_helpers::random_bytes, DataMap, Error, Result};
use std::collections::HashMap;
use xor_name::XorName;

/// Helper function to collect chunks from stream_encrypt
fn collect_stream_encrypt_chunks(
    data_size: usize,
    data_iter: impl Iterator<Item = Bytes>,
) -> Result<(DataMap, HashMap<XorName, Vec<u8>>)> {
    let mut stream = stream_encrypt(data_size, data_iter)?;
    let mut chunks = HashMap::new();

    // Collect all chunks
    for chunk_result in stream.chunks() {
        let (hash, content) = chunk_result?;
        chunks.insert(hash, content.to_vec());
    }

    // Get the datamap
    let datamap = stream
        .datamap()
        .ok_or_else(|| Error::Generic("Should have DataMap after iteration".to_string()))?
        .clone();

    Ok((datamap, chunks))
}

/// Test that stream_encrypt works on its own (encrypt then decrypt)
fn test_stream_encrypt_roundtrip(file_size: usize) -> Result<()> {
    println!("\n=== Testing stream_encrypt roundtrip for {file_size} bytes ===");

    let test_data = random_bytes(file_size);

    let data_iter = test_data
        .chunks(8192)
        .map(|chunk| Bytes::from(chunk.to_vec()));
    let (stream_datamap, stream_chunks) = collect_stream_encrypt_chunks(file_size, data_iter)?;

    println!(
        "Stream encrypt: {} chunks collected, DataMap references {} chunks, child level: {:?}",
        stream_chunks.len(),
        stream_datamap.len(),
        stream_datamap.child()
    );

    // Verify that all DataMap-referenced chunks are available
    for info in stream_datamap.infos() {
        if !stream_chunks.contains_key(&info.dst_hash) {
            return Err(Error::Generic(format!(
                "Missing chunk: {}",
                hex::encode(info.dst_hash)
            )));
        }
    }

    // Convert chunks to EncryptedChunk format for decryption
    let mut encrypted_chunks = Vec::new();
    for content in stream_chunks.values() {
        use self_encryption::EncryptedChunk;
        encrypted_chunks.push(EncryptedChunk {
            content: Bytes::from(content.clone()),
        });
    }

    // Decrypt using the stream_encrypt results
    let decrypted = self_encryption::decrypt(&stream_datamap, &encrypted_chunks)?;

    assert_eq!(
        decrypted, test_data,
        "Stream encrypt roundtrip should match original data"
    );

    println!("✓ Stream encrypt roundtrip verified for {file_size} bytes");
    Ok(())
}

/// Test that stream_encrypt produces consistent results with standard encrypt
fn test_encryption_consistency(file_size: usize) -> Result<()> {
    println!("\n=== Testing encryption consistency for {file_size} bytes ===");

    let test_data = random_bytes(file_size);

    // Method 1: standard encrypt
    let (std_datamap, std_chunks) = self_encryption::encrypt(test_data.clone())?;

    // Method 2: stream_encrypt
    let data_iter = test_data
        .chunks(8192)
        .map(|chunk| Bytes::from(chunk.to_vec()));
    let (stream_datamap, stream_chunks) = collect_stream_encrypt_chunks(file_size, data_iter)?;

    // Both should produce same DataMap structure
    assert_eq!(
        std_datamap.len(),
        stream_datamap.len(),
        "DataMap lengths must be identical"
    );

    assert_eq!(
        std_datamap.child(),
        stream_datamap.child(),
        "DataMap child levels must be identical"
    );

    // Both should decrypt to the original data
    let mut std_encrypted = Vec::new();
    for chunk in &std_chunks {
        std_encrypted.push(chunk.clone());
    }

    let mut stream_encrypted = Vec::new();
    for content in stream_chunks.values() {
        stream_encrypted.push(self_encryption::EncryptedChunk {
            content: Bytes::from(content.clone()),
        });
    }

    let std_decrypted = self_encryption::decrypt(&std_datamap, &std_encrypted)?;
    let stream_decrypted = self_encryption::decrypt(&stream_datamap, &stream_encrypted)?;

    assert_eq!(
        std_decrypted, test_data,
        "Standard encrypt decryption mismatch"
    );
    assert_eq!(
        stream_decrypted, test_data,
        "Stream encrypt decryption mismatch"
    );

    println!("✅ Encryption consistency verified for {file_size} bytes");
    Ok(())
}

#[test]
fn test_5mb_stream_encrypt_roundtrip() -> Result<()> {
    test_stream_encrypt_roundtrip(5 * 1024 * 1024)
}

#[test]
fn test_5mb_encryption_consistency() -> Result<()> {
    test_encryption_consistency(5 * 1024 * 1024)
}

#[test]
fn test_10mb_encryption_consistency() -> Result<()> {
    test_encryption_consistency(10 * 1024 * 1024)
}

#[test]
fn test_100mb_encryption_consistency() -> Result<()> {
    test_encryption_consistency(100 * 1024 * 1024)
}

/// Comprehensive test that runs all consistency checks for multiple file sizes
#[test]
fn test_all_encryption_methods_consistency() -> Result<()> {
    let test_sizes = vec![
        5 * 1024 * 1024,   // 5MB
        10 * 1024 * 1024,  // 10MB
        100 * 1024 * 1024, // 100MB
    ];

    for &size in &test_sizes {
        println!(
            "\n Testing file size: {} bytes ({:.1} MB)",
            size,
            size as f64 / (1024.0 * 1024.0)
        );

        test_stream_encrypt_roundtrip(size)?;
        test_encryption_consistency(size)?;

        println!("All consistency checks passed for {size} bytes");
    }

    println!("\nAll encryption method consistency tests passed!");
    Ok(())
}
