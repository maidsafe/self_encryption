# self_encryption

Self encrypting files (convergent encryption plus obfuscation)

|Crate|Documentation|
|:---:|:-----------:|
|[![](https://img.shields.io/crates/v/self_encryption.svg)](https://crates.io/crates/self_encryption)|[![Documentation](https://docs.rs/self_encryption/badge.svg)](https://docs.rs/self_encryption)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that takes a set of bytes and returns a secret key derived from those bytes, and a set of encrypted chunks.

The library can be used through either [Rust](#rust-usage) or [Python](#python-usage) interfaces.

**Important Security Note**: While this library provides very secure encryption of the data, the returned secret key **requires the same secure handling as would be necessary for any secret key**.

![image of self encryption](https://github.com/maidsafe/self_encryption/blob/master/img/self_encryption.png?raw=true)

## Documentation
- [Self Encrypting Data Whitepaper](https://docs.maidsafe.net/Whitepapers/pdf/SelfEncryptingData.pdf)
- [Process Overview Video](https://www.youtube.com/watch?v=Jnvwv4z17b4)

## Features

- Content-based chunking
- Convergent encryption
- Self-validating chunks
- Hierarchical data maps for handling large files
- Streaming encryption/decryption
- Python bindings
- Flexible storage backend support
- Custom storage backends via functors

## Usage

The library can be used through either Rust or Python interfaces.

### Rust Usage

#### Installation

Add this to your `Cargo.toml`:
```toml
[dependencies]
self_encryption = "0.30"
bytes = "1.0"
```

#### Basic Encryption/Decryption

```rust
use self_encryption::{encrypt, decrypt_full_set};
use bytes::Bytes;

fn main() -> Result<()> {
    // Create test data
    let data = Bytes::from("Hello, World!".as_bytes());
    
    // Encrypt data
    let (data_map, encrypted_chunks) = encrypt(data)?;
    
    // Decrypt data
    let decrypted = decrypt_full_set(&data_map, &encrypted_chunks)?;
    assert_eq!(decrypted, "Hello, World!".as_bytes());
    
    // Serialize data map for storage
    let serialized = bincode::serialize(&data_map)?;
    
    // Later, deserialize the data map
    let restored_map: DataMap = bincode::deserialize(&serialized)?;
    
    Ok(())
}
```

#### File Operations

```rust
use self_encryption::{encrypt_from_file, decrypt_from_storage};
use std::path::Path;
use std::fs::{self, File};
use std::io::Write;

fn process_file() -> Result<()> {
    // Encrypt a file
    let (data_map, chunk_names) = encrypt_from_file(
        Path::new("input.txt"),
        Path::new("chunks/")
    )?;
    
    // Print information about chunks
    println!("File was split into {} chunks", chunk_names.len());
    for name in &chunk_names {
        let path = Path::new("chunks/").join(hex::encode(name));
        let metadata = fs::metadata(&path)?;
        println!("Chunk {}: {} bytes", hex::encode(name), metadata.len());
    }
    
    // Create disk-based chunk retrieval
    let get_chunk = |hash| -> Result<Bytes> {
        let path = Path::new("chunks/").join(hex::encode(hash));
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(Bytes::from(data))
    };
    
    // Decrypt the file using the retrieval function
    decrypt_from_storage(
        &data_map,
        Path::new("output.txt"),
        get_chunk
    )?;
    
    Ok(())
}
```

#### Custom Storage Backend

```rust
use self_encryption::{decrypt_from_storage, shrink_data_map};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Example with thread-safe in-memory storage
fn memory_storage_example() -> Result<()> {
    // Create thread-safe storage
    let storage = Arc::new(Mutex::new(HashMap::new()));
    let storage_clone = storage.clone();
    
    // Create storage function
    let store_chunk = move |hash, data| {
        storage_clone.lock()
            .map_err(|_| Error::Generic("Lock poisoned".into()))?
            .insert(hash, data);
        Ok(())
    };
    
    // Create retrieval function
    let storage_clone = storage.clone();
    let get_chunk = move |hash| {
        storage_clone.lock()
            .map_err(|_| Error::Generic("Lock poisoned".into()))?
            .get(&hash)
            .cloned()
            .ok_or_else(|| Error::Generic("Chunk not found".into()))
    };
    
    // Use with storage functions
    let shrunk_map = shrink_data_map(large_data_map, store_chunk)?;
    decrypt_from_storage(&data_map, Path::new("output.txt"), get_chunk)?;
    
    Ok(())
}
```

#### Streaming Operations

```rust
use self_encryption::{StreamSelfEncryptor, StreamSelfDecryptor};
use std::path::PathBuf;

fn streaming_example() -> Result<()> {
    // Streaming encryption
    let mut encryptor = StreamSelfEncryptor::encrypt_from_file(
        PathBuf::from("large_input.txt"),
        Some(PathBuf::from("chunks/"))
    )?;
    
    // Process chunks as they're generated
    let mut chunk_count = 0;
    let final_map = loop {
        match encryptor.next_encryption()? {
            (Some(chunk), None) => {
                chunk_count += 1;
                println!(
                    "Processing chunk {}: {} bytes",
                    chunk_count,
                    chunk.content.len()
                );
                // Process chunk here
            }
            (None, Some(map)) => break map,  // Encryption complete
            _ => unreachable!(),
        }
    };
    
    // Streaming decryption
    let mut decryptor = StreamSelfDecryptor::decrypt_to_file(
        PathBuf::from("output.txt"),
        &final_map
    )?;
    
    // Process chunks one by one
    for chunk in chunks {
        if decryptor.next_encrypted(chunk)? {
            break;  // Decryption complete
        }
    }
    
    Ok(())
}
```

#### Hierarchical Data Maps

```rust
use self_encryption::{shrink_data_map, get_root_data_map};
use std::fs::{self, File};
use std::io::{Write, Read};

fn hierarchical_example() -> Result<()> {
    // Create storage functions
    let store_chunk = |hash, data| -> Result<()> {
        let path = Path::new("chunks/").join(hex::encode(hash));
        File::create(path)?.write_all(&data)?;
        Ok(())
    };
    
    let get_chunk = |hash| -> Result<Bytes> {
        let path = Path::new("chunks/").join(hex::encode(hash));
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        Ok(Bytes::from(data))
    };
    
    // Shrink a large data map
    let shrunk_map = shrink_data_map(large_data_map, store_chunk)?;
    
    // Save the shrunk map
    let serialized = bincode::serialize(&shrunk_map)?;
    fs::write("shrunk_map.dat", &serialized)?;
    
    // Later, load and expand the map
    let serialized = fs::read("shrunk_map.dat")?;
    let loaded_map: DataMap = bincode::deserialize(&serialized)?;
    
    // Get back the root map
    let root_map = get_root_data_map(loaded_map, get_chunk)?;
    
    Ok(())
}
```

#### Error Handling

```rust
use self_encryption::{encrypt, decrypt_from_storage, Error};

fn error_handling_example() -> Result<()> {
    // Handle data too small for encryption
    let small_data = Bytes::from("tiny");
    match encrypt(small_data) {
        Err(Error::Generic(msg)) if msg.contains("Too small") => {
            println!("Data too small for encryption");
        }
        Ok(_) => unreachable!(),
        Err(e) => return Err(e),
    }
    
    // Handle missing chunks
    let get_chunk = |_hash| -> Result<Bytes> {
        Err(Error::Generic("Chunk not found".into()))
    };
    
    match decrypt_from_storage(&data_map, Path::new("output.txt"), get_chunk) {
        Err(Error::Generic(msg)) if msg.contains("not found") => {
            println!("Failed to retrieve chunks");
        }
        Ok(_) => unreachable!(),
        Err(e) => return Err(e),
    }
    
    Ok(())
}
```

#### Complete File Processing Example

```rust
use self_encryption::*;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{Read, Write};

fn process_large_file(
    input_path: &Path,
    chunk_dir: &Path,
    output_path: &Path
) -> Result<()> {
    // Ensure chunk directory exists
    fs::create_dir_all(chunk_dir)?;
    
    // 1. Encrypt the file
    println!("Encrypting file...");
    let (data_map, chunk_names) = encrypt_from_file(input_path, chunk_dir)?;
    println!("File split into {} chunks", chunk_names.len());
    
    // 2. Create storage functions
    let store_chunk = |hash, data| -> Result<()> {
        let path = chunk_dir.join(hex::encode(hash));
        File::create(path)?.write_all(&data)?;
        Ok(())
    };
    
    let get_chunk = |hash| -> Result<Bytes> {
        let path = chunk_dir.join(hex::encode(hash));
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        Ok(Bytes::from(data))
    };
    
    // 3. Shrink the data map
    println!("Shrinking data map...");
    let shrunk_map = shrink_data_map(data_map, store_chunk)?;
    
    // 4. Save shrunk map
    let map_path = chunk_dir.join("map.dat");
    let serialized = bincode::serialize(&shrunk_map)?;
    fs::write(&map_path, &serialized)?;
    println!("Shrunk map saved to {:?}", map_path);
    
    // 5. Load and expand map
    println!("Loading shrunk map...");
    let serialized = fs::read(map_path)?;
    let loaded_map: DataMap = bincode::deserialize(&serialized)?;
    
    // 6. Get root map
    println!("Expanding to root map...");
    let root_map = get_root_data_map(loaded_map, get_chunk)?;
    
    // 7. Decrypt file
    println!("Decrypting file...");
    decrypt_from_storage(&root_map, output_path, get_chunk)?;
    println!("File decrypted to {:?}", output_path);
    
    // 8. Clean up
    fs::remove_dir_all(chunk_dir)?;
    
    Ok(())
}

fn main() -> Result<()> {
    process_large_file(
        Path::new("input.dat"),
        Path::new("temp_chunks"),
        Path::new("decrypted_output.dat")
    )
}
```

These examples demonstrate:
- Basic encryption/decryption
- File operations with detailed error handling
- Thread-safe in-memory storage
- Streaming operations for large files
- Hierarchical data map management
- Complete file processing workflow
- Proper resource cleanup
- Error handling patterns

Each example includes detailed comments and shows idiomatic Rust patterns for using the library.

## Implementation Details

- Files are split into chunks of up to 1MB
- Each chunk is encrypted using AES-256-GCM
- Chunk names are SHA3-256 hashes of their content
- Large data maps are automatically shrunk into a hierarchy
- All operations support custom storage backends
- Streaming operations for memory-efficient processing

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking Exception

self_encryption is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify self_encryption, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
