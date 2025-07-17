use self_encryption::{encrypt, streaming_encrypt_from_file, test_helpers::random_bytes};
use std::fs;
use tempfile::tempdir;

/// Test that confirms chunks obtained through streaming_encrypt_from_file are the same as those obtained through the encrypt function.
#[test]
fn test_streaming_encrypt_vs_memory_encryption_consistency() {
    // Create test data of sufficient size to generate multiple chunks
    let file_size = 5 * 1024 * 1024; // 5MB to ensure multiple chunks
    let test_data = random_bytes(file_size);

    // Create temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let input_file_path = temp_dir.path().join("input.dat");

    // Write test data to file
    fs::write(&input_file_path, &test_data).expect("Failed to write test data");

    // Method 1: Use the encrypt function (memory-based)
    let (memory_data_map, memory_chunks) =
        encrypt(test_data.clone()).expect("Memory encryption failed");

    // Method 2: Use streaming_encrypt_from_file (streaming-based)
    let mut streaming_chunks = Vec::new();
    let streaming_data_map = streaming_encrypt_from_file(&input_file_path, |_, content| {
        // Store chunk in memory for comparison
        streaming_chunks.push(self_encryption::EncryptedChunk { content });
        Ok(())
    })
    .expect("Streaming encryption failed");

    // Verify both methods produced the same amount of chunks
    assert_eq!(
        memory_chunks.len(),
        streaming_chunks.len(),
        "Memory and streaming encryption should produce the same number of chunks"
    );

    // Verify both methods produced the same chunks
    assert_eq!(
        memory_chunks, streaming_chunks,
        "Memory and streaming encryption should produce the same chunks"
    );

    // Verify data maps are identical
    assert_eq!(
        memory_data_map, streaming_data_map,
        "Data maps should be identical"
    );
}

/// Test with different file sizes to ensure consistency across various scenarios
#[test]
fn test_streaming_encrypt_vs_memory_encryption_different_sizes() {
    let test_sizes = vec![
        3 * 1024 * 1024,  // 3MB - minimum size for multiple chunks
        10 * 1024 * 1024, // 10MB - medium size
        50 * 1024 * 1024, // 50MB - large size
    ];

    for file_size in test_sizes {
        let test_data = random_bytes(file_size);

        // Create temporary directory for test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let input_file_path = temp_dir.path().join("input.dat");

        // Write test data to file
        fs::write(&input_file_path, &test_data).expect("Failed to write test data");

        // Memory-based encryption
        let (memory_data_map, memory_chunks) =
            encrypt(test_data.clone()).expect("Memory encryption failed");

        // Streaming-based encryption
        let mut streaming_chunks = Vec::new();
        let streaming_data_map = streaming_encrypt_from_file(&input_file_path, |_hash, content| {
            // Store chunk in memory for comparison
            streaming_chunks.push(self_encryption::EncryptedChunk { content });
            Ok(())
        })
        .expect("Streaming encryption failed");

        // Verify chunk counts match
        assert_eq!(
            memory_chunks.len(),
            streaming_chunks.len(),
            "Chunk counts should match for file size {file_size}"
        );

        // Verify chunk values match
        assert_eq!(
            memory_chunks, streaming_chunks,
            "Chunks should match for file size {file_size}"
        );

        assert_eq!(
            memory_data_map, streaming_data_map,
            "Data map should have identical hashes for file size {file_size}"
        );

        // Verify decrypted data matches
        let memory_decrypted = self_encryption::decrypt(&memory_data_map, &memory_chunks)
            .expect("Failed to decrypt memory-encrypted data");

        let streaming_decrypted = self_encryption::decrypt(&streaming_data_map, &streaming_chunks)
            .expect("Failed to decrypt streaming-encrypted data");

        assert_eq!(
            memory_decrypted, streaming_decrypted,
            "Decrypted data should be identical for file size {file_size}"
        );

        assert_eq!(
            test_data, memory_decrypted,
            "Decrypted data should match original for file size {file_size}"
        );
    }
}

/// Test that verifies the streaming encryption works with actual file storage
#[test]
fn test_streaming_encrypt_with_file_storage() {
    let file_size = 5 * 1024 * 1024; // 5MB
    let test_data = random_bytes(file_size);

    // Create temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let input_file_path = temp_dir.path().join("input.dat");
    let chunk_dir = temp_dir.path().join("chunks");

    // Create chunk directory
    fs::create_dir_all(&chunk_dir).expect("Failed to create chunk directory");

    // Write test data to file
    fs::write(&input_file_path, &test_data).expect("Failed to write test data");

    // Memory-based encryption
    let (memory_data_map, memory_chunks) =
        encrypt(test_data.clone()).expect("Memory encryption failed");

    // Streaming-based encryption with file storage
    let mut streaming_chunks = Vec::new();
    let streaming_data_map = streaming_encrypt_from_file(&input_file_path, |hash, content| {
        // Store chunk to file
        let chunk_path = chunk_dir.join(hex::encode(hash));
        fs::write(&chunk_path, &content).expect("Failed to write chunk to file");
        
        // Also store in memory for comparison
        streaming_chunks.push(self_encryption::EncryptedChunk { content });
        Ok(())
    })
    .expect("Streaming encryption failed");

    // Verify chunks match
    assert_eq!(
        memory_chunks, streaming_chunks,
        "Memory and streaming encryption should produce the same chunks"
    );

    // Verify data maps are identical
    assert_eq!(
        memory_data_map, streaming_data_map,
        "Data maps should have identical hashes"
    );

    // Verify that chunks were actually written to disk
    for chunk in &streaming_chunks {
        let chunk_hash = self_encryption::XorName::from_content(&chunk.content);
        let chunk_path = chunk_dir.join(hex::encode(chunk_hash));
        assert!(
            chunk_path.exists(),
            "Chunk file should exist on disk: {:?}",
            chunk_path
        );
    }
}

