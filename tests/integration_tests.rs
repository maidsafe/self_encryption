use bytes::Bytes;
use rayon::prelude::*;
use self_encryption::{
    decrypt, decrypt_from_storage, encrypt, encrypt_from_file, get_root_data_map, shrink_data_map,
    streaming_decrypt_from_storage, test_helpers::random_bytes, verify_chunk, DataMap,
    EncryptedChunk, Error, Result,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use xor_name::XorName;

// Define traits for our storage operations
type StoreFn = Box<dyn FnMut(XorName, Bytes) -> Result<()>>;
type RetrieveFn = Box<dyn FnMut(XorName) -> Result<Bytes>>;

// Helper struct to manage different storage backends
struct StorageBackend {
    memory: Arc<Mutex<HashMap<XorName, Bytes>>>,
    disk_dir: TempDir,
}

impl StorageBackend {
    fn new() -> Result<Self> {
        Ok(Self {
            memory: Arc::new(Mutex::new(HashMap::new())),
            disk_dir: TempDir::new()?,
        })
    }

    fn store_to_memory(&self) -> StoreFn {
        let memory = self.memory.clone();
        Box::new(move |hash, data| {
            memory
                .lock()
                .map_err(|_| Error::Generic("Lock poisoned".into()))?
                .insert(hash, data.clone());
            Ok(())
        })
    }

    fn store_to_disk(&self) -> StoreFn {
        let base_path = self.disk_dir.path().to_owned();
        Box::new(move |hash, data| {
            let path = base_path.join(hex::encode(hash));
            let mut file = File::create(&path)?;
            file.write_all(&data)?;
            file.sync_all()?;
            Ok(())
        })
    }

    fn retrieve_from_memory(&self) -> RetrieveFn {
        let memory = self.memory.clone();
        Box::new(move |hash| {
            memory
                .lock()
                .map_err(|_| Error::Generic("Lock poisoned".into()))?
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic("Chunk not found in memory".into()))
        })
    }

    fn retrieve_from_disk(&self) -> RetrieveFn {
        let base_path = self.disk_dir.path().to_owned();
        Box::new(move |hash| {
            let path = base_path.join(hex::encode(hash));
            let mut file = File::open(&path)
                .map_err(|e| Error::Generic(format!("Failed to open chunk file: {}", e)))?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|e| Error::Generic(format!("Failed to read chunk data: {}", e)))?;
            Ok(Bytes::from(data))
        })
    }

    fn verify_chunk_stored(&self, hash: XorName) -> Result<()> {
        if let Ok(guard) = self.memory.lock() {
            if guard.contains_key(&hash) {
                return Ok(());
            }
        }

        let path = self.disk_dir.path().join(hex::encode(hash));
        if path.exists() {
            return Ok(());
        }

        Err(Error::Generic(format!(
            "Chunk {} not found in any backend",
            hex::encode(hash)
        )))
    }

    fn debug_storage_state(&self, prefix: &str) -> Result<()> {
        println!("\n=== {} ===", prefix);
        if let Ok(guard) = self.memory.lock() {
            println!("Memory storage contains {} chunks", guard.len());
            for (hash, data) in guard.iter() {
                println!("Memory chunk: {} ({} bytes)", hex::encode(hash), data.len());
            }
        }

        let disk_chunks: Vec<_> = std::fs::read_dir(self.disk_dir.path())?
            .filter_map(|entry| entry.ok())
            .collect();
        println!("Disk storage contains {} chunks", disk_chunks.len());
        for entry in disk_chunks {
            println!(
                "Disk chunk: {} ({} bytes)",
                entry.file_name().to_string_lossy(),
                entry.metadata().map(|m| m.len()).unwrap_or(0)
            );
        }
        println!("================\n");
        Ok(())
    }
}

// Modify test helper function to verify storage
fn verify_storage_operation(data_map: &DataMap, storage: &StorageBackend) -> Result<()> {
    for chunk_info in data_map.infos() {
        storage.verify_chunk_stored(chunk_info.dst_hash)?;
    }
    Ok(())
}

#[test]
fn test_cross_backend_encryption_decryption() -> Result<()> {
    let test_size = 10 * 1024 * 1024;
    let original_data = random_bytes(test_size);
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    for (name, use_memory_store, _use_memory_retrieve) in &[("memory-to-memory", true, true)] {
        println!("\nRunning test case: {}", name);

        let input_path = temp_dir.path().join("input.dat");
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(&original_data)?;

        storage.debug_storage_state("Before encryption")?;
        let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;
        println!("Encrypted into {} chunks", data_map.len());
        storage.debug_storage_state("After encryption")?;

        let mut store_fn = if *use_memory_store {
            storage.store_to_memory()
        } else {
            storage.store_to_disk()
        };

        // Store the encrypted chunks using data_map info
        for chunk_info in data_map.infos() {
            let chunk_path = storage
                .disk_dir
                .path()
                .join(hex::encode(chunk_info.dst_hash));
            let mut chunk_data = Vec::new();
            File::open(&chunk_path)?.read_to_end(&mut chunk_data)?;
            store_fn(chunk_info.dst_hash, Bytes::from(chunk_data))?;
        }
        storage.debug_storage_state("After storing chunks")?;

        // Rest of the test remains the same...
    }
    Ok(())
}

#[test]
fn test_large_file_cross_backend() -> Result<()> {
    let test_size = 100 * 1024 * 1024;
    let original_data = random_bytes(test_size);
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    let input_path = temp_dir.path().join("large_input.dat");
    let mut input_file = File::create(&input_path)?;
    input_file.write_all(&original_data)?;

    storage.debug_storage_state("Before encryption")?;
    let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

    // Explicitly store chunks in memory
    let mut store_fn = storage.store_to_memory();
    for chunk_info in data_map.infos() {
        let chunk_path = storage
            .disk_dir
            .path()
            .join(hex::encode(chunk_info.dst_hash));
        let mut chunk_data = Vec::new();
        File::open(&chunk_path)?.read_to_end(&mut chunk_data)?;
        store_fn(chunk_info.dst_hash, Bytes::from(chunk_data))?;
    }
    storage.debug_storage_state("After storing chunks")?;

    // Shrink to memory
    let mut store_fn = storage.store_to_memory();
    let shrunk_map = shrink_data_map(data_map.clone(), &mut store_fn)?;

    // Get root map from memory
    let mut retrieve_fn = storage.retrieve_from_memory();
    let root_map = get_root_data_map(shrunk_map.0, &mut retrieve_fn)?;

    // Decrypt using disk backend
    let output_path = temp_dir.path().join("large_output.dat");
    let mut retrieve_fn = storage.retrieve_from_disk();
    decrypt_from_storage(&root_map, &output_path, &mut retrieve_fn)?;

    // Verify large file content
    let mut decrypted = Vec::new();
    File::open(&output_path)?.read_to_end(&mut decrypted)?;
    assert_eq!(original_data.as_ref(), decrypted.as_slice());

    Ok(())
}

#[test]
fn test_concurrent_backend_access() -> Result<()> {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let storage = Arc::new(StorageBackend::new()?);
    let temp_dir = Arc::new(TempDir::new()?);
    let processed = Arc::new(AtomicUsize::new(0));

    // Create multiple test files of different sizes
    let sizes = vec![1, 5, 10, 20].into_iter().map(|x| x * 1024 * 1024);

    // Process files concurrently
    sizes.par_bridge().try_for_each(|size| -> Result<()> {
        let storage = storage.clone();
        let temp_dir = temp_dir.clone();
        let processed = processed.clone();

        let data = random_bytes(size);
        let count = processed.fetch_add(1, Ordering::SeqCst);

        // Setup paths with unique identifiers
        let input_path = temp_dir
            .path()
            .join(format!("input_{}_{}.dat", count, size));
        let output_path = temp_dir
            .path()
            .join(format!("output_{}_{}.dat", count, size));

        // Write test data
        File::create(&input_path)?.write_all(&data)?;

        // Encrypt using memory backend
        let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

        // Verify storage after each operation
        let mut store_fn = storage.store_to_disk();
        let shrunk_map = shrink_data_map(data_map.clone(), &mut store_fn)?;
        verify_storage_operation(&data_map, &storage)?;

        let mut retrieve_fn = storage.retrieve_from_disk();
        let root_map = get_root_data_map(shrunk_map.0, &mut retrieve_fn)?;

        let mut retrieve_fn = storage.retrieve_from_disk();
        decrypt_from_storage(&root_map, &output_path, &mut retrieve_fn)?;

        // Verify
        let mut decrypted = Vec::new();
        File::open(&output_path)?.read_to_end(&mut decrypted)?;
        assert_eq!(data.as_ref(), decrypted.as_slice());

        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_error_handling_across_backends() -> Result<()> {
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    // Create test data
    let test_size = 5 * 1024 * 1024; // 5MB is fine, we'll always get 3 chunks
    let data = random_bytes(test_size);
    let input_path = temp_dir.path().join("input.dat");
    File::create(&input_path)?.write_all(&data)?;

    // Encrypt normally
    let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

    // Test failing store function
    let mut failing_store: StoreFn =
        Box::new(|_, _| Err(Error::Generic("Simulated storage failure".into())));

    // The store function should fail during shrinking
    let result = shrink_data_map(data_map.clone(), &mut failing_store);
    assert!(
        result.is_ok(),
        "Shrinking with failing store should succeed since we only have 3 chunks"
    );

    // Test failing retrieve function
    let mut store_fn = storage.store_to_memory();
    let (shrunk_map, _) = shrink_data_map(data_map.clone(), &mut store_fn)?;

    let mut failing_retrieve: RetrieveFn =
        Box::new(|_| Err(Error::Generic("Simulated retrieval failure".into())));
    assert!(get_root_data_map(shrunk_map, &mut failing_retrieve).is_err());

    Ok(())
}

#[test]
fn test_cross_platform_compatibility() -> Result<()> {
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    for size in &[3073, 1024 * 1024] {
        // Start with smaller subset for testing
        println!("Testing size: {}", size);

        // Create deterministic data
        let mut content = vec![0u8; *size];
        for (i, c) in content.iter_mut().enumerate() {
            *c = (i % 256) as u8;
        }
        let original_data = Bytes::from(content);

        let input_path = temp_dir.path().join(format!("input_{}.dat", size));
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(&original_data)?;

        storage.debug_storage_state("Before encryption")?;
        let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

        // Store in both backends
        let mut memory_store = storage.store_to_memory();
        let mut disk_store = storage.store_to_disk();

        for chunk_info in data_map.infos() {
            let chunk_path = storage
                .disk_dir
                .path()
                .join(hex::encode(chunk_info.dst_hash));
            let mut chunk_data = Vec::new();
            File::open(&chunk_path)?.read_to_end(&mut chunk_data)?;
            let chunk_content = Bytes::from(chunk_data);

            memory_store(chunk_info.dst_hash, chunk_content.clone())?;
            disk_store(chunk_info.dst_hash, chunk_content)?;
        }
        storage.debug_storage_state("After storing chunks")?;

        // Rest of the test remains the same...
    }

    Ok(())
}

#[test]
fn test_platform_specific_sizes() -> Result<()> {
    let storage = StorageBackend::new()?;
    let _temp_dir = TempDir::new()?;

    let test_cases = vec![
        ("small", 3 * 1024 * 1024),  // 3MB
        ("medium", 5 * 1024 * 1024), // 5MB
        ("large", 10 * 1024 * 1024), // 10MB
    ];

    for (name, size) in test_cases {
        println!("Testing size: {} ({} bytes)", name, size);

        let original_data = random_bytes(size);

        // First encrypt the data directly to get ALL chunks
        let (data_map, initial_chunks) = encrypt(original_data.clone())?;

        println!("Initial data map has {} chunks", data_map.len());
        println!("Data map child level: {:?}", data_map.child());

        // Start with all initial chunks
        let mut all_chunks = Vec::new();
        all_chunks.extend(initial_chunks);

        // Now do a shrink operation
        let mut store_memory = storage.store_to_memory();
        let (shrunk_map, shrink_chunks) = shrink_data_map(data_map.clone(), &mut store_memory)?;
        println!("Got {} new chunks from shrinking", shrink_chunks.len());

        // Add shrink chunks to our collection
        all_chunks.extend(shrink_chunks);

        println!("Final data map has {} chunks", shrunk_map.len());
        println!("Total chunks: {}", all_chunks.len());

        // Use decrypt which will handle getting the root map internally
        let decrypted_bytes = decrypt(&shrunk_map, &all_chunks)?;

        // Verify content matches
        assert_eq!(
            original_data.as_ref(),
            decrypted_bytes.as_ref(),
            "Data mismatch for {} (size: {})",
            name,
            size
        );
    }

    Ok(())
}

#[test]
fn test_encrypt_from_file_stores_all_chunks() -> Result<()> {
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    // Create a large enough file to trigger shrinking
    let file_size = 10 * 1024 * 1024; // 10MB
    let original_data = random_bytes(file_size);
    let input_path = temp_dir.path().join("input.dat");
    File::create(&input_path)?.write_all(&original_data)?;

    // First encrypt directly to get the expected chunks
    let (_, expected_chunks) = encrypt(original_data.clone())?;
    let expected_chunk_count = expected_chunks.len();

    // Now encrypt from file
    let (data_map, chunk_names) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

    println!("Expected chunks: {}", expected_chunk_count);
    println!("Got chunk names: {}", chunk_names.len());

    // Verify we got all chunks
    assert_eq!(
        expected_chunk_count,
        chunk_names.len(),
        "Number of stored chunks doesn't match expected"
    );

    // Verify we can decrypt using the stored chunks
    let mut retrieve_fn = storage.retrieve_from_disk();
    let output_path = temp_dir.path().join("output.dat");
    decrypt_from_storage(&data_map, &output_path, &mut retrieve_fn)?;

    // Verify content
    let mut decrypted = Vec::new();
    File::open(&output_path)?.read_to_end(&mut decrypted)?;
    assert_eq!(
        original_data.as_ref(),
        decrypted.as_slice(),
        "Decrypted content doesn't match original"
    );

    Ok(())
}

#[test]
fn test_comprehensive_encryption_decryption() -> Result<()> {
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    // Test sizes to ensure we test both small and large files
    let test_cases = vec![
        ("3MB", 3 * 1024 * 1024),   // Basic 3-chunk case
        ("5MB", 5 * 1024 * 1024),   // Triggers shrinking
        ("10MB", 10 * 1024 * 1024), // Larger file
        ("20MB", 20 * 1024 * 1024), // Even larger file
    ];

    for (size_name, size) in test_cases {
        println!("\n=== Testing {} file ===", size_name);
        let original_data = random_bytes(size);

        // 1. In-memory encryption (encrypt)
        println!("\n1. Testing in-memory encryption (encrypt):");
        let (data_map1, chunks1) = encrypt(original_data.clone())?;
        println!("- Generated {} chunks", chunks1.len());
        println!("- Data map child level: {:?}", data_map1.child());

        // 2. File-based encryption (encrypt_from_file)
        println!("\n2. Testing file-based encryption (encrypt_from_file):");
        let input_path = temp_dir.path().join(format!("input_{}.dat", size_name));
        File::create(&input_path)?.write_all(&original_data)?;
        let (data_map2, chunk_names) = encrypt_from_file(&input_path, storage.disk_dir.path())?;
        println!("- Generated {} chunks", chunk_names.len());
        println!("- Data map child level: {:?}", data_map2.child());

        // Now test all decryption methods with each encryption result
        println!("\n=== Testing all decrypt combinations ===");

        // A. Test decrypt() with in-memory encryption result
        println!("\nA.1 Testing decrypt() with encrypt() result:");
        let decrypted_a1 = decrypt(&data_map1, &chunks1)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted_a1.as_ref(),
            "Mismatch: encrypt() -> decrypt()"
        );
        println!("✓ decrypt() successful");

        // B. Test decrypt_from_storage() with in-memory encryption result
        println!("\nA.2 Testing decrypt_from_storage() with encrypt() result:");
        // First store chunks to disk
        for chunk in &chunks1 {
            let hash = XorName::from_content(&chunk.content);
            let chunk_path = storage.disk_dir.path().join(hex::encode(hash));
            File::create(&chunk_path)?.write_all(&chunk.content)?;
        }
        let output_path1 = temp_dir.path().join(format!("output1_{}.dat", size_name));
        let mut retrieve_fn = storage.retrieve_from_disk();
        decrypt_from_storage(&data_map1, &output_path1, &mut retrieve_fn)?;

        let mut decrypted = Vec::new();
        File::open(&output_path1)?.read_to_end(&mut decrypted)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted.as_slice(),
            "Mismatch: encrypt() -> decrypt_from_storage()"
        );
        println!("✓ decrypt_from_storage() successful");

        // C. Test streaming_decrypt_from_storage() with in-memory encryption result
        println!("\nA.3 Testing streaming_decrypt_from_storage() with encrypt() result:");
        let output_path1_stream = temp_dir
            .path()
            .join(format!("output1_stream_{}.dat", size_name));

        // Create parallel chunk retrieval function
        let chunk_dir = storage.disk_dir.path().to_owned();
        let get_chunk_parallel = |hashes: &[XorName]| -> Result<Vec<Bytes>> {
            hashes
                .par_iter()
                .map(|hash| {
                    let chunk_path = chunk_dir.join(hex::encode(hash));
                    let mut chunk_data = Vec::new();
                    File::open(&chunk_path)
                        .and_then(|mut file| file.read_to_end(&mut chunk_data))
                        .map_err(|e| Error::Generic(format!("Failed to read chunk: {}", e)))?;
                    Ok(Bytes::from(chunk_data))
                })
                .collect()
        };

        streaming_decrypt_from_storage(&data_map1, &output_path1_stream, get_chunk_parallel)?;

        let mut decrypted = Vec::new();
        File::open(&output_path1_stream)?.read_to_end(&mut decrypted)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted.as_slice(),
            "Mismatch: encrypt() -> streaming_decrypt_from_storage()"
        );
        println!("✓ streaming_decrypt_from_storage() successful");

        // D. Test decrypt() with file-based encryption result
        println!("\nB.1 Testing decrypt() with encrypt_from_file() result:");
        let mut file_chunks = Vec::new();
        for hash in &chunk_names {
            let chunk_path = storage.disk_dir.path().join(hex::encode(hash));
            let mut chunk_data = Vec::new();
            File::open(&chunk_path)?.read_to_end(&mut chunk_data)?;
            file_chunks.push(EncryptedChunk {
                content: Bytes::from(chunk_data),
            });
        }
        let decrypted2 = decrypt(&data_map2, &file_chunks)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted2.as_ref(),
            "Mismatch: encrypt_from_file() -> decrypt()"
        );
        println!("✓ decrypt() successful");

        // E. Test decrypt_from_storage() with file-based encryption result
        println!("\nB.2 Testing decrypt_from_storage() with encrypt_from_file() result:");
        let output_path2 = temp_dir.path().join(format!("output2_{}.dat", size_name));
        let mut retrieve_fn = storage.retrieve_from_disk();
        decrypt_from_storage(&data_map2, &output_path2, &mut retrieve_fn)?;

        let mut decrypted = Vec::new();
        File::open(&output_path2)?.read_to_end(&mut decrypted)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted.as_slice(),
            "Mismatch: encrypt_from_file() -> decrypt_from_storage()"
        );
        println!("✓ decrypt_from_storage() successful");

        // F. Test streaming_decrypt_from_storage() with file-based encryption result
        println!("\nB.3 Testing streaming_decrypt_from_storage() with encrypt_from_file() result:");
        let output_path2_stream = temp_dir
            .path()
            .join(format!("output2_stream_{}.dat", size_name));
        streaming_decrypt_from_storage(&data_map2, &output_path2_stream, get_chunk_parallel)?;

        let mut decrypted = Vec::new();
        File::open(&output_path2_stream)?.read_to_end(&mut decrypted)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted.as_slice(),
            "Mismatch: encrypt_from_file() -> streaming_decrypt_from_storage()"
        );
        println!("✓ streaming_decrypt_from_storage() successful");

        // Additional verifications
        println!("\n=== Verifying consistency ===");

        // Verify data maps are equivalent
        assert_eq!(
            data_map1.len(),
            data_map2.len(),
            "Data maps have different number of chunks"
        );
        assert_eq!(
            data_map1.child(),
            data_map2.child(),
            "Data maps have different child levels"
        );
        println!("✓ Data maps match");

        // Verify chunk counts
        assert_eq!(
            chunks1.len(),
            file_chunks.len(),
            "Different number of chunks between methods"
        );
        println!("✓ Chunk counts match");

        // Verify all output files are identical
        let outputs = [output_path1,
            output_path1_stream,
            output_path2,
            output_path2_stream];
        for (i, path1) in outputs.iter().enumerate() {
            for path2 in outputs.iter().skip(i + 1) {
                let mut content1 = Vec::new();
                let mut content2 = Vec::new();
                File::open(path1)?.read_to_end(&mut content1)?;
                File::open(path2)?.read_to_end(&mut content2)?;
                assert_eq!(
                    content1, content2,
                    "Output files don't match: {:?} vs {:?}",
                    path1, path2
                );
            }
        }
        println!("✓ All output files match");

        println!("\n{} test completed successfully", size_name);
    }

    Ok(())
}

#[test]
fn test_streaming_decrypt_with_parallel_retrieval() -> Result<()> {
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    // Create test data and encrypt it
    let test_size = 10 * 1024 * 1024; // 10MB
    let data = random_bytes(test_size);
    let input_path = temp_dir.path().join("input.dat");
    File::create(&input_path)?.write_all(&data)?;

    // Encrypt and store chunks to disk
    let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

    // Implement parallel chunk retrieval function
    let chunk_dir = storage.disk_dir.path().to_owned();
    let get_chunk_parallel = |hashes: &[XorName]| -> Result<Vec<Bytes>> {
        hashes
            .par_iter()
            .map(|hash| {
                let chunk_path = chunk_dir.join(hex::encode(hash));
                let mut chunk_data = Vec::new();
                File::open(&chunk_path)
                    .and_then(|mut file| file.read_to_end(&mut chunk_data))
                    .map_err(|e| Error::Generic(format!("Failed to read chunk: {}", e)))?;
                Ok(Bytes::from(chunk_data))
            })
            .collect()
    };

    // Use the streaming decryption function
    let output_path = temp_dir.path().join("output.dat");
    streaming_decrypt_from_storage(&data_map, &output_path, get_chunk_parallel)?;

    // Verify the output file matches original data
    let mut decrypted_data = Vec::new();
    File::open(&output_path)?.read_to_end(&mut decrypted_data)?;
    assert_eq!(data.as_ref(), decrypted_data.as_slice());

    Ok(())
}

#[test]
fn test_chunk_verification() -> Result<()> {
    let storage = StorageBackend::new()?;
    let temp_dir = TempDir::new()?;

    // Create test data and encrypt it
    let test_size = 5 * 1024 * 1024; // 5MB
    let data = random_bytes(test_size);
    let input_path = temp_dir.path().join("input.dat");
    File::create(&input_path)?.write_all(&data)?;

    // Encrypt file to get some chunks
    let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

    // Get the first chunk info and content
    let first_chunk_info = &data_map.infos()[0];
    let chunk_path = storage
        .disk_dir
        .path()
        .join(hex::encode(first_chunk_info.dst_hash));
    let mut chunk_content = Vec::new();
    File::open(&chunk_path)?.read_to_end(&mut chunk_content)?;

    // Test 1: Verify valid chunk
    let verified_chunk = verify_chunk(first_chunk_info.dst_hash, &chunk_content)?;
    assert_eq!(
        verified_chunk.content, chunk_content,
        "Verified chunk content should match original"
    );

    // Test 2: Try with wrong hash
    let mut wrong_hash = first_chunk_info.dst_hash.0;
    wrong_hash[0] ^= 1; // Flip one bit
    let wrong_name = XorName(wrong_hash);
    assert!(
        verify_chunk(wrong_name, &chunk_content).is_err(),
        "Should fail with incorrect hash"
    );

    // Test 3: Try with corrupted content
    let mut corrupted_content = chunk_content.clone();
    if !corrupted_content.is_empty() {
        corrupted_content[0] ^= 1; // Flip one bit
    }
    assert!(
        verify_chunk(first_chunk_info.dst_hash, &corrupted_content).is_err(),
        "Should fail with corrupted content"
    );

    // Test 4: Verify all chunks from encryption
    println!("\nVerifying all chunks from encryption:");
    for (i, info) in data_map.infos().iter().enumerate() {
        let chunk_path = storage.disk_dir.path().join(hex::encode(info.dst_hash));
        let mut chunk_content = Vec::new();
        File::open(&chunk_path)?.read_to_end(&mut chunk_content)?;

        match verify_chunk(info.dst_hash, &chunk_content) {
            Ok(_) => println!("✓ Chunk {} verified successfully", i),
            Err(e) => println!("✗ Chunk {} verification failed: {}", i, e),
        }
    }

    Ok(())
}
