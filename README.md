# self_encryption

Self encrypting files (convergent encryption plus obfuscation)

|Crate|Documentation|
|:---:|:-----------:|
|[![](https://img.shields.io/crates/v/self_encryption.svg)](https://crates.io/crates/self_encryption)|[![Documentation](https://docs.rs/self_encryption/badge.svg)](https://docs.rs/self_encryption)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Table of Contents
- [Overview](#overview)
- [Documentation](#documentation)
- [Features](#features)
- [Usage](#usage)
  - [Rust Usage](#rust-usage)
    - [Basic Operations](#basic-operations)
    - [Storage Backends](#storage-backends)
    - [Streaming Operations](#streaming-operations)
    - [Advanced Usage](#advanced-usage)
  - [Python Usage](#python-usage)
    - [Basic Operations](#python-basic-operations)
    - [File Operations](#python-file-operations)
    - [Advanced Features](#python-advanced-features)
- [Implementation Details](#implementation-details)
- [License](#license)
- [Contributing](#contributing)

## Overview

A version of [convergent encryption](http://en.wikipedia.org/wiki/convergent_encryption) with an additional obfuscation step. This pattern allows secured data that can also be [de-duplicated](http://en.wikipedia.org/wiki/Data_deduplication). This library presents an API that takes a set of bytes and returns a secret key derived from those bytes, and a set of encrypted chunks.

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

### Rust Usage

#### Installation

Add this to your `Cargo.toml`:
```toml
[dependencies]
self_encryption = "0.30"
bytes = "1.0"
```

#### Basic Operations

```rust
use self_encryption::{encrypt, decrypt_full_set};
use bytes::Bytes;

// Basic encryption/decryption
fn basic_example() -> Result<()> {
    let data = Bytes::from("Hello, World!".repeat(1000));  // Must be at least 3072 bytes
    
    // Encrypt data
    let (data_map, encrypted_chunks) = encrypt(data.clone())?;
    
    // Decrypt data
    let decrypted = decrypt_full_set(&data_map, &encrypted_chunks)?;
    assert_eq!(data, decrypted);
    
    Ok(())
}
```

#### Storage Backends

```rust
use self_encryption::{shrink_data_map, get_root_data_map, decrypt_from_storage};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Memory Storage Example
fn memory_storage_example() -> Result<()> {
    let storage = Arc::new(Mutex::new(HashMap::new()));
    
    // Store function
    let store = |hash, data| {
        storage.lock().unwrap().insert(hash, data);
        Ok(())
    };
    
    // Retrieve function
    let retrieve = |hash| {
        storage.lock().unwrap()
            .get(&hash)
            .cloned()
            .ok_or_else(|| Error::Generic("Chunk not found".into()))
    };
    
    // Use with data map operations
    let shrunk_map = shrink_data_map(data_map, store)?;
    let root_map = get_root_data_map(shrunk_map, retrieve)?;
    
    Ok(())
}

// Disk Storage Example
fn disk_storage_example() -> Result<()> {
    let chunk_dir = PathBuf::from("chunks");
    
    // Store function
    let store = |hash, data| {
        let path = chunk_dir.join(hex::encode(hash));
        std::fs::write(path, data)?;
        Ok(())
    };
    
    // Retrieve function
    let retrieve = |hash| {
        let path = chunk_dir.join(hex::encode(hash));
        Ok(Bytes::from(std::fs::read(path)?))
    };
    
    // Use with data map operations
    let shrunk_map = shrink_data_map(data_map, store)?;
    let root_map = get_root_data_map(shrunk_map, retrieve)?;
    
    Ok(())
}
```

#### Streaming Operations

```rust
use self_encryption::{StreamSelfEncryptor, StreamSelfDecryptor};

fn streaming_example() -> Result<()> {
    // Streaming encryption
    let mut encryptor = StreamSelfEncryptor::encrypt_from_file(
        PathBuf::from("input.txt"),
        Some(PathBuf::from("chunks"))
    )?;
    
    let mut all_chunks = Vec::new();
    let mut final_map = None;
    
    while let (chunk, map) = encryptor.next_encryption()? {
        if let Some(chunk) = chunk {
            all_chunks.push(chunk);
        }
        if let Some(map) = map {
            final_map = Some(map);
            break;
        }
    }
    
    // Streaming decryption
    let mut decryptor = StreamSelfDecryptor::decrypt_to_file(
        PathBuf::from("output.txt"),
        &final_map.unwrap()
    )?;
    
    for chunk in all_chunks {
        if decryptor.next_encrypted(chunk)? {
            break;  // Decryption complete
        }
    }
    
    Ok(())
}
```

#### Advanced Usage

```rust
use self_encryption::{decrypt_range, seek_info};

fn advanced_example() -> Result<()> {
    // Partial decryption (seeking)
    let start_pos = 1024;
    let length = 4096;
    
    let seek = seek_info(file_size, start_pos, length);
    let data = decrypt_range(&data_map, &chunks, seek.relative_pos, length)?;
    
    // Hierarchical data maps
    let store = |hash, data| -> Result<()> {
        // Store chunk
        Ok(())
    };
    
    let shrunk_map = shrink_data_map(large_data_map, store)?;
    
    // Custom error handling
    match encrypt(small_data) {
        Err(Error::Generic(msg)) if msg.contains("Too small") => {
            println!("Data too small for encryption");
        }
        Ok(_) => println!("Encryption successful"),
        Err(e) => return Err(e),
    }
    
    Ok(())
}
```

### Python Usage

#### Installation

```bash
pip install self-encryption
```

#### Python Basic Operations

```python
from self_encryption import encrypt_bytes, decrypt_chunks

def basic_example():
    # Create test data (must be at least 3072 bytes)
    data = b"Hello, World!" * 1000
    
    # Encrypt data
    data_map, chunks = encrypt_bytes(data)
    
    # Decrypt data
    decrypted = decrypt_chunks(data_map, chunks)
    assert data == decrypted

```

#### Python File Operations

```python
from self_encryption import encrypt_file, decrypt_from_files
import os

def file_example():
    # Encrypt file
    data_map, chunk_names = encrypt_file("input.txt", "chunks")
    
    # Decrypt file
    decrypt_from_files("chunks", data_map, "output.txt")
    
    # Verify content
    with open("input.txt", "rb") as f:
        original = f.read()
    with open("output.txt", "rb") as f:
        decrypted = f.read()
    assert original == decrypted
```

#### Python Advanced Features

```python
from self_encryption import (
    shrink_data_map, 
    get_root_data_map,
    StreamSelfEncryptor,
    StreamSelfDecryptor
)

def advanced_example():
    # Hierarchical data maps
    shrunk_map = shrink_data_map(data_map, "chunks")
    root_map = get_root_data_map(shrunk_map, "chunks")
    
    # Streaming encryption
    encryptor = StreamSelfEncryptor("input.txt", "chunks")
    while True:
        chunk, map = encryptor.next_encryption()
        if chunk:
            process_chunk(chunk)
        if map:
            break
    
    # Streaming decryption
    decryptor = StreamSelfDecryptor("output.txt", map)
    for chunk in chunks:
        if decryptor.next_encrypted(chunk):
            break  # Decryption complete
```

## Implementation Details

### Core Process

- Files are split into chunks of up to 1MB
- Each chunk is processed in three steps:
  1. Compression (using Brotli)
  2. Encryption (using AES-256-CBC)
  3. XOR obfuscation

### Key Generation and Security

- Each chunk's encryption uses keys derived from the content hashes of three chunks:

  ```
  For chunk N:
  - Uses hashes from chunks [N, N+1, N+2]
  - Combined hash = hash(N) || hash(N+1) || hash(N+2)
  - Split into:
    - Pad (first X bytes)
    - Key (next 16 bytes for AES-256)
    - IV  (final 16 bytes)
  ```

- This creates a chain of dependencies where each chunk's encryption depends on its neighbors
- Provides both convergent encryption and additional security through the interdependencies

### Encryption Flow

1. Content Chunking:
   - File is split into chunks of optimal size
   - Each chunk's raw content is hashed (SHA3-256)
   - These hashes become part of the DataMap

2. Per-Chunk Processing:

   ```rust
   // For each chunk:
   1. Compress data using Brotli
   2. Generate key materials:
      - Combine three consecutive chunk hashes
      - Extract pad, key, and IV
   3. Encrypt compressed data using AES-256-CBC
   4. XOR encrypted data with pad for obfuscation
   ```

3. DataMap Creation:
   - Stores both pre-encryption (src) and post-encryption (dst) hashes
   - Maintains chunk ordering and size information
   - Required for both encryption and decryption processes

### Decryption Flow

1. Chunk Retrieval:
   - Use DataMap to identify required chunks
   - Retrieve chunks using dst_hash as identifier

2. Per-Chunk Processing:

   ```rust
   // For each chunk:
   1. Regenerate key materials using src_hashes from DataMap
   2. Remove XOR obfuscation using pad
   3. Decrypt using AES-256-CBC with key and IV
   4. Decompress using Brotli
   ```

3. Chunk Reassembly:
   - Chunks are processed in order specified by DataMap
   - Reassembled into original file

### Storage Features

- Flexible backend support through trait-based design
- Supports both memory and disk-based storage
- Streaming operations for memory efficiency
- Hierarchical data maps for large files:

  ```rust
  // DataMap shrinking for large files
  1. Serialize large DataMap
  2. Encrypt serialized map using same process
  3. Create new DataMap with fewer chunks
  4. Repeat until manageable size reached
  ```

### Security Properties

- Content-based convergent encryption
- Additional security through chunk interdependencies
- Self-validating chunks through hash verification
- No single point of failure in chunk storage
- Tamper-evident through hash chains

### Performance Optimizations

- Parallel chunk processing where possible
- Streaming support for large files
- Efficient memory usage through chunking
- Optimized compression settings
- Configurable chunk sizes

This implementation provides a balance of:

- Security (through multiple encryption layers)
- Deduplication (through convergent encryption)
- Performance (through parallelization and streaming)
- Flexibility (through modular storage backends)

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking Exception

self_encryption is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify self_encryption, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
