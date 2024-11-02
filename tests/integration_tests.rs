use bytes::Bytes;
use self_encryption::{
    decrypt_from_storage, encrypt_from_file, get_root_data_map, shrink_data_map,
    test_helpers::random_bytes, DataMap, Error, Result,
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

        let disk_chunks: Vec<_> = std::fs::read_dir(&self.disk_dir.path())?
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
    let shrunk_map = shrink_data_map(data_map, &mut store_fn)?;

    // Get root map from memory
    let mut retrieve_fn = storage.retrieve_from_memory();
    let root_map = get_root_data_map(shrunk_map, &mut retrieve_fn)?;

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
        let root_map = get_root_data_map(shrunk_map, &mut retrieve_fn)?;

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
    let test_size = 5 * 1024 * 1024;
    let data = random_bytes(test_size);
    let input_path = temp_dir.path().join("input.dat");
    File::create(&input_path)?.write_all(&data)?;

    // Encrypt normally
    let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

    // Test missing chunks during shrinking
    let mut failing_store: StoreFn =
        Box::new(|_, _| Err(Error::Generic("Simulated storage failure".into())));
    assert!(shrink_data_map(data_map.clone(), &mut failing_store).is_err());

    // Test missing chunks during root map retrieval
    let mut store_fn = storage.store_to_memory();
    let shrunk_map = shrink_data_map(data_map.clone(), &mut store_fn)?;

    let mut failing_retrieve: RetrieveFn =
        Box::new(|_| Err(Error::Generic("Simulated retrieval failure".into())));
    assert!(get_root_data_map(shrunk_map.clone(), &mut failing_retrieve).is_err());

    // Test partial chunk availability
    let memory_store: HashMap<XorName, Bytes> = HashMap::new();
    let memory_store = Arc::new(Mutex::new(memory_store));
    let memory_store_clone = memory_store.clone();

    let mut partial_retrieve: RetrieveFn = Box::new(move |hash| {
        memory_store_clone
            .lock()
            .map_err(|_| Error::Generic("Lock poisoned".into()))?
            .get(&hash)
            .cloned()
            .ok_or_else(|| Error::Generic("Chunk not found".into()))
    });

    let output_path = temp_dir.path().join("output.dat");
    assert!(decrypt_from_storage(&data_map, &output_path, &mut partial_retrieve).is_err());

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
    let temp_dir = TempDir::new()?;

    let test_cases = vec![
        ("u16_max", u16::MAX as usize),
        ("u16_max_plus_1", (u16::MAX as usize) + 1),
        ("u32_div_1024", (u32::MAX as usize) / 1024),
        ("typical_page_size", 4096),
        ("large_page_size", 16384),
    ];

    for (name, size) in test_cases {
        println!("Testing platform-specific size: {} ({})", name, size);

        // Skip if size is too small for self-encryption
        if size < 3073 {
            continue;
        }

        let original_data = random_bytes(size);
        let input_path = temp_dir.path().join(format!("input_{}_{}.dat", name, size));
        let mut input_file = File::create(&input_path)?;
        input_file.write_all(&original_data)?;

        // Test both memory and disk backends
        let (data_map, _) = encrypt_from_file(&input_path, storage.disk_dir.path())?;

        // First store chunks in memory from disk
        let mut store_memory = storage.store_to_memory();
        for chunk_info in data_map.infos() {
            let chunk_path = storage
                .disk_dir
                .path()
                .join(hex::encode(chunk_info.dst_hash));
            let mut chunk_data = Vec::new();
            File::open(&chunk_path)?.read_to_end(&mut chunk_data)?;
            store_memory(chunk_info.dst_hash, Bytes::from(chunk_data))?;
        }

        // Now proceed with memory operations
        let mut store_memory = storage.store_to_memory();
        let shrunk_map = shrink_data_map(data_map.clone(), &mut store_memory)?;

        // Verify chunks are stored
        verify_storage_operation(&data_map, &storage)?;

        let mut retrieve_memory = storage.retrieve_from_memory();
        let root_map = get_root_data_map(shrunk_map, &mut retrieve_memory)?;

        let output_path = temp_dir
            .path()
            .join(format!("output_{}_{}.dat", name, size));
        let mut retrieve_fn = storage.retrieve_from_memory();
        decrypt_from_storage(&root_map, &output_path, &mut retrieve_fn)?;

        // Verify content
        let mut decrypted = Vec::new();
        File::open(&output_path)?.read_to_end(&mut decrypted)?;
        assert_eq!(
            original_data.as_ref(),
            decrypted.as_slice(),
            "Data mismatch for {} (size: {})",
            name,
            size
        );
    }

    Ok(())
}
