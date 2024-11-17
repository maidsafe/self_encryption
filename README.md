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

# Python Bindings 

### Basic Usage

```python
from self_encryption import encrypt, decrypt

# Basic in-memory encryption/decryption
def basic_example():
    # Create test data (must be at least 3072 bytes)
    data = b"Hello, World!" * 1000
    
    # Encrypt data - returns data map and encrypted chunks
    data_map, chunks = encrypt(data)
    print(f"Data encrypted into {len(chunks)} chunks")
    print(f"Data map has child level: {data_map.child()}")
    
    # Decrypt data
    decrypted = decrypt(data_map, chunks)
    assert data == decrypted
```

### File Operations

```python
from pathlib import Path
from self_encryption import encrypt_from_file, decrypt_from_storage

def file_example():
    # Setup paths
    input_path = Path("large_file.dat")
    chunk_dir = Path("chunks")
    output_path = Path("decrypted_file.dat")
    
    # Ensure chunk directory exists
    chunk_dir.mkdir(exist_ok=True)
    
    # Encrypt file - stores chunks to disk
    data_map, chunk_names = encrypt_from_file(str(input_path), str(chunk_dir))
    print(f"File encrypted into {len(chunk_names)} chunks")
    
    # Create chunk retrieval function
    def get_chunk(hash_hex: str) -> bytes:
        chunk_path = chunk_dir / hash_hex
        return chunk_path.read_bytes()
    
    # Decrypt file
    decrypt_from_storage(data_map, str(output_path), get_chunk)
```

### Advanced Features

```python
from self_encryption import shrink_data_map

def advanced_example():
    # Create large data to ensure multiple chunks
    data = b"x" * 10_000_000  # 10MB
    
    # Encrypt data
    data_map, chunks = encrypt(data)
    print(f"Initial encryption: {len(chunks)} chunks")
    
    # Track stored chunks during shrinking
    stored_chunks = {}
    def store_chunk(hash_hex: str, content: bytes):
        stored_chunks[hash_hex] = content
        print(f"Storing chunk: {hash_hex[:8]}...")
    
    # Shrink data map - useful for large files
    shrunk_map, shrink_chunks = shrink_data_map(data_map, store_chunk)
    print(f"Generated {len(shrink_chunks)} additional chunks during shrinking")
    
    # Verify child level is set
    assert shrunk_map.child() is not None
    assert shrunk_map.is_child()
    
    # Collect all chunks for decryption
    all_chunks = chunks + shrink_chunks
    
    # Decrypt using all chunks
    decrypted = decrypt(shrunk_map, all_chunks)
    assert data == decrypted
```

### Streaming Operations

```python
from self_encryption import streaming_decrypt_from_storage
from typing import List

def streaming_example():
    # ... setup code ...
    
    # Create parallel chunk retrieval function
    def get_chunks(hash_hexes: List[str]) -> List[bytes]:
        return [
            chunk_dir.joinpath(hash_hex).read_bytes()
            for hash_hex in hash_hexes
        ]
    
    # Decrypt using streaming - efficient for large files
    streaming_decrypt_from_storage(data_map, str(output_path), get_chunks)
```

### API Reference

#### Classes

- `DataMap`
  - `child() -> Optional[int]`: Get child level if set
  - `is_child() -> bool`: Check if this is a child data map
  - `len() -> int`: Get number of chunks
  - `infos() -> List[Tuple[int, bytes, bytes, int]]`: Get chunk information

- `EncryptedChunk`
  - `content() -> bytes`: Get chunk content
  - `from_bytes(content: bytes) -> EncryptedChunk`: Create from bytes

#### Functions

- `encrypt(data: bytes) -> Tuple[DataMap, List[EncryptedChunk]]`
  - Encrypts bytes data in memory
  - Returns data map and encrypted chunks

- `encrypt_from_file(input_path: str, output_dir: str) -> Tuple[DataMap, List[str]]`
  - Encrypts a file and stores chunks to disk
  - Returns data map and list of chunk hex names

- `decrypt(data_map: DataMap, chunks: List[EncryptedChunk]) -> bytes`
  - Decrypts data using provided chunks
  - Returns original data

- `decrypt_from_storage(data_map: DataMap, output_path: str, get_chunk: Callable[[str], bytes]) -> None`
  - Decrypts data using chunks from storage
  - Writes result to output path

- `shrink_data_map(data_map: DataMap, store_chunk: Callable[[str, bytes], None]) -> Tuple[DataMap, List[EncryptedChunk]]`
  - Shrinks a data map by recursively encrypting it
  - Returns shrunk map and additional chunks

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

## Python Bindings

This crate provides comprehensive Python bindings for self-encryption functionality, supporting both in-memory and file-based operations.

### Installation

```bash
pip install self-encryption
```

### Basic Usage

```python
from self_encryption import py_encrypt, py_decrypt

# Basic in-memory encryption/decryption
def basic_example():
    # Create test data (must be at least 3072 bytes)
    data = b"Hello, World!" * 1000
    
    # Encrypt data - returns data map and encrypted chunks
    data_map, chunks = py_encrypt(data)
    print(f"Data encrypted into {len(chunks)} chunks")
    print(f"Data map has child level: {data_map.child()}")
    
    # Decrypt data
    decrypted = py_decrypt(data_map, chunks)
    assert data == decrypted

```

### File Operations

```python
from pathlib import Path
from self_encryption import py_encrypt_from_file, py_decrypt_from_storage

def file_example():
    # Setup paths
    input_path = Path("large_file.dat")
    chunk_dir = Path("chunks")
    output_path = Path("decrypted_file.dat")
    
    # Ensure chunk directory exists
    chunk_dir.mkdir(exist_ok=True)
    
    # Encrypt file - stores chunks to disk
    data_map, chunk_names = py_encrypt_from_file(str(input_path), str(chunk_dir))
    print(f"File encrypted into {len(chunk_names)} chunks")
    
    # Create chunk retrieval function
    def get_chunk(hash_hex: str) -> bytes:
        chunk_path = chunk_dir / hash_hex
        return chunk_path.read_bytes()
    
    # Decrypt file
    py_decrypt_from_storage(data_map, str(output_path), get_chunk)
```

### Advanced Features

```python
from self_encryption import py_shrink_data_map

def advanced_example():
    # Create large data to ensure multiple chunks
    data = b"x" * 10_000_000  # 10MB
    
    # Encrypt data
    data_map, chunks = py_encrypt(data)
    print(f"Initial encryption: {len(chunks)} chunks")
    
    # Track stored chunks during shrinking
    stored_chunks = {}
    def store_chunk(hash_hex: str, content: bytes):
        stored_chunks[hash_hex] = content
        print(f"Storing chunk: {hash_hex[:8]}...")
    
    # Shrink data map - useful for large files
    shrunk_map, shrink_chunks = py_shrink_data_map(data_map, store_chunk)
    print(f"Generated {len(shrink_chunks)} additional chunks during shrinking")
    
    # Verify child level is set
    assert shrunk_map.child() is not None
    assert shrunk_map.is_child()
    
    # Collect all chunks for decryption
    all_chunks = chunks + shrink_chunks
    
    # Decrypt using all chunks
    decrypted = py_decrypt(shrunk_map, all_chunks)
    assert data == decrypted
```

### API Reference

#### Classes

- `PyDataMap`
  - `child() -> Optional[int]`: Get child level if set
  - `is_child() -> bool`: Check if this is a child data map
  - `len() -> int`: Get number of chunks
  - `infos() -> List[Tuple[int, bytes, bytes, int]]`: Get chunk information

- `PyEncryptedChunk`
  - `content() -> bytes`: Get chunk content
  - `from_bytes(content: bytes) -> PyEncryptedChunk`: Create from bytes

#### Functions

- `py_encrypt(data: bytes) -> Tuple[PyDataMap, List[PyEncryptedChunk]]`
  - Encrypts bytes data in memory
  - Returns data map and encrypted chunks

- `py_encrypt_from_file(input_path: str, output_dir: str) -> Tuple[PyDataMap, List[str]]`
  - Encrypts a file and stores chunks to disk
  - Returns data map and list of chunk hex names

- `py_decrypt(data_map: PyDataMap, chunks: List[PyEncryptedChunk]) -> bytes`
  - Decrypts data using provided chunks
  - Returns original data

- `py_decrypt_from_storage(data_map: PyDataMap, output_path: str, get_chunk: Callable[[str], bytes]) -> None`
  - Decrypts data using chunks from storage
  - Writes result to output path

- `py_shrink_data_map(data_map: PyDataMap, store_chunk: Callable[[str, bytes], None]) -> Tuple[PyDataMap, List[PyEncryptedChunk]]`
  - Shrinks a data map by recursively encrypting it
  - Returns shrunk map and additional chunks

### Notes

- All encryption methods handle parent/child relationships automatically
- Chunk storage and retrieval can be customized through callbacks
- Error handling follows Python conventions with descriptive exceptions
- Supports both synchronous and parallel chunk processing
- Memory efficient through streaming operations

### Chunk Verification

#### Rust
```rust
use self_encryption::{verify_chunk, EncryptedChunk, XorName};

// Verify a chunk matches its expected hash
fn verify_example() -> Result<()> {
    let chunk_hash = XorName([0; 32]); // 32-byte hash
    let chunk_content = vec![1, 2, 3]; // Raw chunk content
    
    match verify_chunk(chunk_hash, &chunk_content) {
        Ok(chunk) => println!("Chunk verified successfully"),
        Err(e) => println!("Chunk verification failed: {}", e),
    }
    Ok(())
}
```

The `verify_chunk` function provides a way to verify chunk integrity:
- Takes a `XorName` hash and chunk content as bytes
- Verifies the content matches the hash
- Returns a valid `EncryptedChunk` if verification succeeds
- Returns an error if verification fails

#### Python
```python
from self_encryption import verify_chunk

def verify_example():
    # Get a chunk and its expected hash from somewhere
    chunk_hash = bytes.fromhex("0" * 64)  # 32-byte hash as hex
    chunk_content = b"..."  # Raw chunk content
    
    try:
        # Verify and get a usable chunk
        verified_chunk = verify_chunk(chunk_hash, chunk_content)
        print("Chunk verified successfully")
    except ValueError as e:
        print(f"Chunk verification failed: {e}")
```

The Python `verify_chunk` function provides similar functionality:
- Takes a 32-byte hash (as bytes) and the chunk content
- Verifies the content matches the hash
- Returns a valid EncryptedChunk if verification succeeds
- Raises ValueError if verification fails

This functionality is particularly useful for:
- Verifying chunk integrity after network transfer
- Validating chunks in storage systems
- Debugging chunk corruption issues
- Implementing chunk validation in client applications

### XorName Operations

The `XorName` class provides functionality for working with cryptographic names and hashes:

```python
from self_encryption import XorName

# Create a XorName from content
content = b"Hello, World!"
name = XorName.from_content(content)
print(f"Content hash: {''.join(format(b, '02x') for b in name.as_bytes())}")

# Create a XorName directly from bytes (must be 32 bytes)
hash_bytes = bytes([x % 256 for x in range(32)])  # Example 32-byte array
name = XorName(hash_bytes)

# Get the underlying bytes
raw_bytes = name.as_bytes()

# Common use cases:
# 1. Verify chunk content matches its hash
def verify_chunk_example():
    # Get a chunk and its expected hash
    chunk_content = b"..."  # Raw chunk content
    expected_hash = XorName.from_content(chunk_content)
    
    # Verify the chunk
    verified_chunk = verify_chunk(expected_hash, chunk_content)
    print("Chunk verified successfully")

# 2. Track chunks by their content hash
def track_chunks_example():
    chunks = {}  # Dict to store chunks by hash
    
    # Store a chunk
    content = b"Some chunk content"
    chunk_hash = XorName.from_content(content)
    chunks[chunk_hash.as_bytes().hex()] = content
    
    # Retrieve a chunk
    retrieved = chunks.get(chunk_hash.as_bytes().hex())
```

The `XorName` class provides:
- `from_content(bytes) -> XorName`: Creates a XorName by hashing the provided content
- `__init__(bytes) -> XorName`: Creates a XorName from an existing 32-byte hash
- `as_bytes() -> bytes`: Returns the underlying 32-byte array
- Used for chunk verification and tracking in the self-encryption process
