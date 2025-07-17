use self_encryption::{encrypt, test_helpers::random_bytes, StreamSelfEncryptor};
use std::fs;
use tempfile::tempdir;

/// Test that confirms chunks obtained through StreamSelfEncryptor are the same as those obtained through the encrypt function.
#[test]
fn test_stream_vs_memory_encryption_consistency() {
    // Create test data of sufficient size to generate multiple chunks
    let file_size = 5 * 1024 * 1024; // 5MB to ensure multiple chunks
    let test_data = random_bytes(file_size);

    // Create temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let input_file_path = temp_dir.path().join("input.dat");
    let chunk_dir = temp_dir.path().join("chunks");

    // Write test data to file
    fs::write(&input_file_path, &test_data).expect("Failed to write test data");

    // Method 1: Use the encrypt function (memory-based)
    let (memory_data_map, memory_chunks) =
        encrypt(test_data.clone()).expect("Memory encryption failed");

    // Method 2: Use StreamSelfEncryptor (stream-based)
    let mut stream_encryptor =
        StreamSelfEncryptor::encrypt_from_file(input_file_path.clone(), Some(chunk_dir.clone()))
            .expect("Failed to create stream encryptor");

    let mut stream_chunks = Vec::new();
    let stream_data_map = loop {
        let (chunk_opt, map_opt) = stream_encryptor
            .next_encryption()
            .expect("Stream encryption failed");

        if let Some(chunk) = chunk_opt {
            stream_chunks.push(chunk);
        }

        if let Some(map) = map_opt {
            break map;
        }
    };

    // Verify both methods produced the same amount of chunks
    assert_eq!(
        memory_chunks.len(),
        stream_chunks.len(),
        "Memory and stream encryption should produce the same number of chunks"
    );

    // Verify both methods produced the same chunks
    assert_eq!(
        memory_chunks, stream_chunks,
        "Memory and stream encryption should produce the same chunks"
    );

    // Verify data maps are identical
    assert_eq!(
        memory_data_map, stream_data_map,
        "Data maps should be identical"
    );
}

/// Test with different file sizes to ensure consistency across various scenarios
#[test]
fn test_stream_vs_memory_encryption_different_sizes() {
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
        let chunk_dir = temp_dir.path().join("chunks");

        // Write test data to file
        fs::write(&input_file_path, &test_data).expect("Failed to write test data");

        // Memory-based encryption
        let (memory_data_map, memory_chunks) =
            encrypt(test_data.clone()).expect("Memory encryption failed");

        // Stream-based encryption
        let mut stream_encryptor = StreamSelfEncryptor::encrypt_from_file(
            input_file_path.clone(),
            Some(chunk_dir.clone()),
        )
        .expect("Failed to create stream encryptor");

        let mut stream_chunks = Vec::new();
        let stream_data_map = loop {
            let (chunk_opt, map_opt) = stream_encryptor
                .next_encryption()
                .expect("Stream encryption failed");

            if let Some(chunk) = chunk_opt {
                stream_chunks.push(chunk);
            }

            if let Some(map) = map_opt {
                break map;
            }
        };

        // Verify chunk counts match
        assert_eq!(
            memory_chunks.len(),
            stream_chunks.len(),
            "Chunk counts should match for file size {file_size}"
        );

        // Verify chunk values match
        assert_eq!(
            memory_chunks, stream_chunks,
            "Chunk should match for file size {file_size}"
        );

        // Verify data map sizes match
        assert_eq!(
            memory_data_map, stream_data_map,
            "Data map should be identical for file size {file_size}"
        );

        // Verify decrypted data matches
        let memory_decrypted = self_encryption::decrypt(&memory_data_map, &memory_chunks)
            .expect("Failed to decrypt memory-encrypted data");

        let stream_decrypted = self_encryption::decrypt(&stream_data_map, &stream_chunks)
            .expect("Failed to decrypt stream-encrypted data");

        assert_eq!(
            memory_decrypted, stream_decrypted,
            "Decrypted data should be identical for file size {file_size}"
        );

        assert_eq!(
            test_data, memory_decrypted,
            "Decrypted data should match original for file size {file_size}"
        );
    }
}
