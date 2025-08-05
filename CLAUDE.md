# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing

```bash
# Format code (MANDATORY before commits)
cargo fmt --all

# Run clippy linter with strict settings
cargo clippy --all-features -- -D warnings

# Run all Rust tests
cargo test --release

# Run comprehensive test script (includes Python tests)
./scripts/test.sh

# Build Python package with maturin
maturin develop --features python

# Run Python tests
pytest tests/ -v

# Run benchmarks
cargo bench

# Check for unused dependencies
cargo udeps --all-targets

# Publish dry run
cargo publish --dry-run
```

### Single Test Execution

```bash
# Run a specific Rust test
cargo test test_name --release

# Run a specific Python test
pytest tests/test_file.py::test_name -v

# Run tests with output
cargo test -- --nocapture
```

## Architecture Overview

### Core Encryption Process

The self_encryption crate implements convergent encryption with obfuscation through a three-stage process:

1. **Content Chunking**: Files are split into chunks (up to 1MB each)
2. **Per-Chunk Processing**:
   - Compression (Brotli with configurable quality)
   - Encryption (AES-256-CBC)
   - XOR obfuscation
3. **Key Derivation**: Each chunk's encryption keys are derived from a circular dependency pattern:
   - Chunks 0 and 1 have special handling due to circular dependencies
   - For chunk N (where N ≥ 2): uses hashes from chunks N, (N+1) % total, (N+2) % total
   - Creates interdependency where modifying any chunk affects multiple others

### Key Components

- **`src/lib.rs`**: Main library interface, exports public API including `encrypt`, `decrypt_full_set`
- **`src/encrypt.rs`**: Core encryption logic, handles chunk processing and key generation
- **`src/decrypt.rs`**: Decryption logic, reverses the encryption process
- **`src/data_map.rs`**: DataMap structure that stores chunk metadata (src/dst hashes, sizes, indices)
- **`src/stream.rs`**: Streaming encryption/decryption for memory-efficient large file handling
- **`src/chunk.rs`**: Chunk data structures (`EncryptedChunk`, `ChunkInfo`) and validation
- **`src/aes.rs`**: AES encryption implementation using CBC mode
- **`src/utils.rs`**: Utility functions for key derivation, hash extraction, chunk size calculation
- **`src/python.rs`**: PyO3 bindings for Python interface
- **`src/error.rs`**: Error types and handling

### Storage Backend Design

The library uses a trait-based design for flexible storage backends:
- Store functions: `Fn(XorName, Bytes) -> Result<()>`
- Retrieve functions: `Fn(XorName) -> Result<Bytes>`
- Supports memory, disk, or custom storage implementations

### DataMap Hierarchy

For large files, DataMaps can be shrunk hierarchically:
- Serialize large DataMap → Encrypt as data → Create new smaller DataMap
- Process repeats until manageable size reached
- `child` field tracks hierarchy level

## Critical Constraints

- **Minimum file size**: 3072 bytes (3 * MIN_CHUNK_SIZE) for self-encryption
- **Chunk size**: Maximum 1MB per chunk
- **Key security**: The returned secret key from encryption requires secure handling
- **Hash verification**: All chunks are self-validating through SHA3-256 hashes

## Python Bindings

The Python interface is built with PyO3 and maturin:
- CLI tool: `self-encryption` command
- Module: `self_encryption` Python package
- Supports both in-memory and streaming operations

## CI/CD Workflow

- **PR checks**: Format, clippy, tests, coverage, unused deps
- **Warnings as errors**: `RUSTFLAGS="-D warnings"` enforced in CI
- **Code coverage**: Uses cargo-llvm-cov and reports to coveralls.io
- **32-bit testing**: Includes i686 target testing
- **Python package**: Automated publishing via GitHub Actions

## Performance Considerations

- Parallel chunk processing via rayon in standard implementation
- Streaming APIs for memory efficiency with large files
- Benchmarks in `benches/lib.rs` for tracking performance
- Optimized compression settings in Brotli
- Chunk size optimization based on file size

## StreamSelfEncryptor Implementation Notes

The streaming implementation differs from the standard implementation in several important ways:

### Design Differences

1. **Memory Usage**: 
   - Standard: Loads entire file into memory, processes all chunks at once
   - Streaming: Processes one chunk at a time, O(1) memory usage

2. **API Pattern**:
   - Standard: Functional approach with `encrypt(bytes) -> (DataMap, Vec<EncryptedChunk>)`
   - Streaming: Stateful object with `next_encryption()` returning chunks incrementally

3. **Chunk Processing**:
   - Standard: Special handling for chunks 0 and 1 (deferred processing due to circular dependencies)
   - Streaming: Processes all chunks uniformly (potential issue)

### Known Issues with StreamSelfEncryptor

1. **First Two Chunks**: Does not implement the special handling for chunks 0 and 1 that the standard implementation uses. This could lead to incorrect encryption in edge cases.

2. **Error Handling**: Less robust error handling compared to standard implementation, particularly around chunk validation.

3. **File System Dependency**: StreamSelfDecryptor uses temporary files extensively, which adds complexity and potential failure points.

### When to Use Each Implementation

- **Standard Implementation**: Use for files that fit comfortably in memory (< 1GB)
- **Streaming Implementation**: Use for large files where memory usage is a concern
- **Note**: Both implementations produce compatible output when working correctly

### Potential Improvements Needed

1. **Unify Chunk Processing**: Align StreamSelfEncryptor's chunk processing with standard implementation, especially for chunks 0 and 1
2. **Error Handling**: Improve error handling in streaming implementation to match standard implementation's robustness
3. **Reduce File System Operations**: Consider memory-mapping or buffering strategies for StreamSelfDecryptor
4. **Progress Callbacks**: Add progress reporting capabilities to streaming implementation
5. **Test Coverage**: Ensure streaming implementation has comprehensive tests for edge cases
6. **API Consistency**: Consider refactoring to provide more consistent APIs between implementations