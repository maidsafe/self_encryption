use super::*;
use crate::test_helpers::random_bytes;
use std::fs;

fn verify_dir_exists(path: &std::path::Path, context: &str) {
    if !path.exists() {
        panic!("{} directory does not exist: {:?}", context, path);
    }
    if !path.is_dir() {
        panic!("{} path exists but is not a directory: {:?}", context, path);
    }
    println!("{} directory verified at: {:?}", context, path);
}

#[tokio::test]
async fn test_stream_self_encryptor() {
    // Create temp directory structure with debug output
    println!("Creating temporary directory...");
    let temp_dir = tempfile::tempdir().unwrap();
    println!("Temp dir created at: {:?}", temp_dir.path());
    
    let input_path = temp_dir.path().join("input_file");
    let chunk_dir = temp_dir.path().join("chunks");
    
    // Create chunk directory with debug output
    println!("Creating chunk directory at: {:?}", chunk_dir);
    fs::create_dir_all(&chunk_dir).unwrap();
    println!("Chunk directory created successfully");

    // Verify directories exist
    assert!(chunk_dir.exists(), "Chunk directory does not exist");
    assert!(temp_dir.path().exists(), "Temp directory does not exist");

    // Create and write test data with debug output
    let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
    println!("Writing test data to: {:?}", input_path);
    
    // Create parent directory for input file if needed
    if let Some(parent) = input_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    
    fs::write(&input_path, &test_data).unwrap();
    println!("Test data written successfully");
    assert!(input_path.exists(), "Input file does not exist");

    // Initialize encryptor
    let mut encryptor = StreamSelfEncryptor::encrypt_from_file(
        input_path.clone(),
        Some(chunk_dir.clone()),
    ).unwrap();

    // Collect encrypted chunks and data map
    let mut encrypted_chunks = Vec::new();
    let data_map = loop {
        let (chunk_opt, map_opt) = encryptor.next_encryption().unwrap();
        
        if let Some(chunk) = chunk_opt {
            encrypted_chunks.push(chunk);
        }
        if let Some(map) = map_opt {
            break map;
        }
    };

    // Setup decryption with debug output
    let output_path = temp_dir.path().join("output_file");
    println!("Creating decryptor with output path: {:?}", output_path);
    let mut decryptor = StreamSelfDecryptor::decrypt_to_file(output_path.clone(), &data_map).unwrap();
    println!("Decryptor created successfully");

    // Process chunks with debug output
    println!("Processing {} chunks", encrypted_chunks.len());
    for (i, chunk) in encrypted_chunks.into_iter().enumerate() {
        println!("Processing chunk {}", i);
        let done = decryptor.next_encrypted(chunk).unwrap();
        if done {
            println!("Decryption completed at chunk {}", i);
            break;
        }
    }

    // Verify results with debug output
    println!("Reading decrypted file from: {:?}", output_path);
    let decrypted_content = fs::read(&output_path).unwrap();
    println!("Successfully read decrypted file");

    assert_eq!(test_data.to_vec(), decrypted_content, "Decrypted content does not match original");
}

#[tokio::test]
async fn test_stream_self_decryptor_basic() {
    // Create temp directory structure
    let temp_dir = tempfile::tempdir().unwrap();
    let input_path = temp_dir.path().join("input_file");
    let chunk_dir = temp_dir.path().join("chunks");
    
    // Create chunk directory
    fs::create_dir_all(&chunk_dir).unwrap();

    // Create test data
    let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
    fs::write(&input_path, &test_data).unwrap();

    // Initialize encryptor
    let mut encryptor = StreamSelfEncryptor::encrypt_from_file(
        input_path.clone(),
        Some(chunk_dir.clone()),
    ).unwrap();

    // Collect encrypted chunks and data map
    let mut encrypted_chunks = Vec::new();
    let data_map = loop {
        let (chunk_opt, map_opt) = encryptor.next_encryption().unwrap();
        
        if let Some(chunk) = chunk_opt {
            encrypted_chunks.push(chunk);
        }
        if let Some(map) = map_opt {
            break map;
        }
    };

    // Setup decryption
    let output_path = temp_dir.path().join("output_file");
    let mut decryptor = StreamSelfDecryptor::decrypt_to_file(output_path.clone(), &data_map).unwrap();

    // Process chunks
    for chunk in encrypted_chunks {
        let done = decryptor.next_encrypted(chunk).unwrap();
        if done {
            break;
        }
    }

    let decrypted_content = fs::read(&output_path).unwrap();
    assert_eq!(test_data.to_vec(), decrypted_content, "Decrypted content does not match original");
}

#[tokio::test]
async fn test_stream_self_decryptor_out_of_order() {
    // Create temp directory structure
    let temp_dir = tempfile::tempdir().unwrap();
    let input_path = temp_dir.path().join("input_file");
    let chunk_dir = temp_dir.path().join("chunks");
    
    // Create chunk directory
    fs::create_dir_all(&chunk_dir).unwrap();

    // Create test data
    let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
    fs::write(&input_path, &test_data).unwrap();

    // Initialize encryptor
    let mut encryptor = StreamSelfEncryptor::encrypt_from_file(
        input_path.clone(),
        Some(chunk_dir.clone()),
    ).unwrap();

    // Collect encrypted chunks and data map
    let mut encrypted_chunks = Vec::new();
    let data_map = loop {
        let (chunk_opt, map_opt) = encryptor.next_encryption().unwrap();
        
        if let Some(chunk) = chunk_opt {
            encrypted_chunks.push(chunk);
        }
        if let Some(map) = map_opt {
            break map;
        }
    };

    // Setup decryption
    let output_path = temp_dir.path().join("output_file");
    let mut decryptor = StreamSelfDecryptor::decrypt_to_file(output_path.clone(), &data_map).unwrap();

    // Process chunks in reverse order
    for chunk in encrypted_chunks.into_iter().rev() {
        let done = decryptor.next_encrypted(chunk).unwrap();
        if done {
            break;
        }
    }

    let decrypted_content = fs::read(&output_path).unwrap();
    assert_eq!(test_data.to_vec(), decrypted_content, "Decrypted content does not match original");
} 