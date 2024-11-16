// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A file **content** self_encryptor.
//!
//! This library provides convergent encryption on file-based data and produces a `DataMap` type and
//! several chunks of encrypted data. Each chunk is up to 1MB in size and has an index and a name. This name is the
//! SHA3-256 hash of the content, which allows the chunks to be self-validating.  If size and hash
//! checks are utilised, a high degree of certainty in the validity of the data can be expected.
//!
//! [Project GitHub page](https://github.com/maidsafe/self_encryption).
//!
//! # Examples
//!
//! A working implementation can be found
//! in the "examples" folder of this project.
//!
//! ```
//! use self_encryption::{encrypt, test_helpers::random_bytes};
//!
//! #[tokio::main]
//! async fn main() {
//!     let file_size = 10_000_000;
//!     let bytes = random_bytes(file_size);
//!
//!     if let Ok((_data_map, _encrypted_chunks)) = encrypt(bytes) {
//!         // .. then persist the `encrypted_chunks`.
//!         // Remember to keep `data_map` somewhere safe..!
//!     }
//! }
//! ```
//!
//! Storage of the `Vec<EncryptedChunk>` or `DataMap` is outwith the scope of this
//! library and must be implemented by the user.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true,
    warnings
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results
)]
#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    non_camel_case_types
)]
// Doesn't allow casts on constants yet, remove when issue is fixed:
// https://github.com/rust-lang-nursery/rust-clippy/issues/2267
#![allow(clippy::cast_lossless, clippy::decimal_literal_representation)]

mod chunk;
mod data_map;
mod decrypt;
mod encrypt;
mod encryption;
mod error;
#[cfg(feature = "python")]
mod python;
pub mod test_helpers;
#[cfg(test)]
mod tests;
mod utils;
mod stream;

use decrypt::decrypt_chunk;
use utils::*;

pub use self::{
    data_map::{ChunkInfo, DataMap},
    error::{Error, Result},
    stream::{StreamSelfDecryptor, StreamSelfEncryptor},
};
use bytes::Bytes;
use lazy_static::lazy_static;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use xor_name::XorName;

// export these because they are used in our public API.
pub use bytes;
pub use xor_name;

/// The minimum size (before compression) of data to be self-encrypted, defined as 3B.
pub const MIN_ENCRYPTABLE_BYTES: usize = 3 * MIN_CHUNK_SIZE;
/// The default maximum size (before compression) of an individual chunk of a file, defaulting as 1MiB.
const DEFAULT_MAX_CHUNK_SIZE: usize = 1024 * 1024;

lazy_static! {
    /// The maximum size (before compression) of an individual chunk of a file, defaulting as 1MiB.
    pub static ref MAX_CHUNK_SIZE: usize = std::option_env!("MAX_CHUNK_SIZE")
        .unwrap_or("1048576")
        .parse::<usize>()
        .unwrap_or(DEFAULT_MAX_CHUNK_SIZE);
}

/// The minimum size (before compression) of an individual chunk of a file, defined as 1B.
pub const MIN_CHUNK_SIZE: usize = 1;
/// Controls the compression-speed vs compression-density tradeoffs.  The higher the quality, the
/// slower the compression.  Range is 0 to 11.
pub const COMPRESSION_QUALITY: i32 = 6;


/// The actual encrypted content of the chunk
#[derive(Clone)]
pub struct EncryptedChunk {
    /// The encrypted contents of the chunk.
    pub content: Bytes,
}
/// Read a file from the disk to encrypt, and output the chunks to a given output directory if presents.
pub fn encrypt_from_file(file_path: &Path, output_dir: &Path) -> Result<(DataMap, Vec<XorName>)> {
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes)?;
    let bytes = Bytes::from(bytes);

    let (data_map, encrypted_chunks) = encrypt(bytes)?;

    let mut chunk_names = Vec::new();
    for chunk in encrypted_chunks {
        let chunk_name = XorName::from_content(&chunk.content);
        chunk_names.push(chunk_name);

        let file_path = output_dir.join(hex::encode(chunk_name));
        let mut output_file = File::create(file_path)?;
        output_file.write_all(&chunk.content)?;
    }

    Ok((data_map, chunk_names))
}

/// Encrypts a set of bytes and returns the encrypted data together with
/// the data map that is derived from the input data, and is used to later decrypt the encrypted data.
/// Returns an error if the size is too small for self-encryption.
/// Only files larger than 3072 bytes (3 * MIN_CHUNK_SIZE) can be self-encrypted.
/// Smaller files will have to be batched together for self-encryption to work.
pub fn encrypt(bytes: Bytes) -> Result<(DataMap, Vec<EncryptedChunk>)> {
    if (MIN_ENCRYPTABLE_BYTES) > bytes.len() {
        return Err(Error::Generic(format!(
            "Too small for self-encryption! Required size at least {}",
            MIN_ENCRYPTABLE_BYTES
        )));
    }
    let (num_chunks, batches) = chunk::batch_chunks(bytes);
    let (data_map, encrypted_chunks) = encrypt::encrypt(batches);
    if num_chunks > encrypted_chunks.len() {
        return Err(Error::Encryption);
    }
    Ok((data_map, encrypted_chunks))
}

/// Decrypts what is expected to be the full set of chunks covered by the data map.
///
/// # Arguments
/// * `data_map` - The data map containing chunk information
/// * `chunks` - The encrypted chunks to decrypt
///
/// # Returns
/// * `Result<Bytes>` - The decrypted data or an error if chunks are missing/corrupted
pub fn decrypt_full_set(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);
    let chunk_indices: BTreeMap<XorName, usize> = data_map
        .infos()
        .iter()
        .map(|info| (info.dst_hash, info.index))
        .collect();

    // Map chunks to their indices, validating hashes
    let mut sorted_chunks = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let hash = XorName::from_content(&chunk.content);
        let idx = chunk_indices.get(&hash).ok_or_else(|| {
            Error::Generic(format!("Chunk with hash {:?} not found in data map", hash))
        })?;
        sorted_chunks.push((*idx, chunk));
    }

    // Sort chunks by index
    sorted_chunks.sort_by_key(|(idx, _)| *idx);

    // Extract just the chunks in order
    let sorted_chunks: Vec<_> = sorted_chunks.into_iter().map(|(_, c)| c).collect();

    decrypt::decrypt_sorted_set(src_hashes, &sorted_chunks)
}

/// Decrypts a range of data from the encrypted chunks.
///
/// # Arguments
/// * `data_map` - The data map containing chunk information
/// * `chunks` - The encrypted chunks to decrypt
/// * `file_pos` - The position within the complete file to start reading from
/// * `len` - Number of bytes to read
///
/// # Returns
/// * `Result<Bytes>` - The decrypted range of data or an error if chunks are missing/corrupted
pub fn decrypt_range(
    data_map: &DataMap,
    chunks: &[EncryptedChunk],
    file_pos: usize,
    len: usize,
) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);

    // Create a mapping of chunk hashes to their indices
    let chunk_indices: BTreeMap<XorName, usize> = data_map
        .infos()
        .iter()
        .map(|info| (info.dst_hash, info.index))
        .collect();

    // Get chunk size info
    let file_size = data_map.original_file_size();

    // Calculate which chunks we need based on the range
    let start_chunk = get_chunk_index(file_size, file_pos);
    let end_pos = std::cmp::min(file_pos + len, file_size);
    let end_chunk = get_chunk_index(file_size, end_pos);

    // Sort and filter chunks to only include the ones we need
    let mut sorted_chunks = Vec::new();
    for chunk in chunks {
        let hash = XorName::from_content(&chunk.content);
        let idx = match chunk_indices.get(&hash) {
            Some(&idx) if idx >= start_chunk && idx <= end_chunk => idx,
            Some(_) => continue, // Skip chunks outside our range
            None => {
                return Err(Error::Generic(format!(
                    "Chunk with hash {:?} not found in data map",
                    hash
                )))
            }
        };
        sorted_chunks.push((idx, chunk));
    }

    // Sort by chunk index
    sorted_chunks.sort_by_key(|(idx, _)| *idx);

    // Verify we have all needed chunks
    let expected_chunks = end_chunk - start_chunk + 1;
    if sorted_chunks.len() != expected_chunks {
        return Err(Error::Generic(format!(
            "Missing chunks. Expected {} chunks (from {} to {}), got {}",
            expected_chunks,
            start_chunk,
            end_chunk,
            sorted_chunks.len()
        )));
    }

    // Decrypt all required chunks completely
    let mut all_bytes = Vec::new();
    for (idx, chunk) in sorted_chunks.iter().enumerate() {
        let chunk_idx = start_chunk + idx;
        let decrypted = decrypt_chunk(chunk_idx, &chunk.1.content, &src_hashes)?;
        all_bytes.extend_from_slice(&decrypted);
    }

    let bytes = Bytes::from(all_bytes);

    // Calculate the actual offset within our decrypted data
    let chunk_start_pos = get_start_position(file_size, start_chunk);
    let internal_offset = file_pos - chunk_start_pos;

    if internal_offset >= bytes.len() {
        return Ok(Bytes::new());
    }

    // Extract just the range we need from the decrypted data
    let available_len = bytes.len() - internal_offset;
    let range_len = std::cmp::min(len, available_len);
    let range_bytes = bytes.slice(internal_offset..internal_offset + range_len);

    Ok(range_bytes)
}

/// Shrinks a data map by recursively encrypting it until the number of chunks is small enough
/// Takes a chunk storage function that handles storing the encrypted chunks
pub fn shrink_data_map<F>(mut data_map: DataMap, mut store_chunk: F) -> Result<DataMap>
where
    F: FnMut(XorName, Bytes) -> Result<()>,
{
    // Keep shrinking until we have less than 4 chunks
    while data_map.len() > 4 {
        let child_level = data_map.child().unwrap_or(0);
        // Serialize the data map
        let bytes = match test_helpers::serialise(&data_map) {
            Ok(bytes) => Bytes::from(bytes),
            Err(_) => return Err(Error::Generic("Failed to serialize data map".to_string())),
        };

        // Encrypt the serialized data map
        let (mut new_data_map, encrypted_chunks) = encrypt(bytes)?;

        // Store all chunks using the provided storage function
        for chunk in encrypted_chunks {
            let chunk_hash = XorName::from_content(&chunk.content);
            store_chunk(chunk_hash, chunk.content)?;
        }

        // Set the child level one higher than the previous
        new_data_map = DataMap::with_child(new_data_map.infos(), child_level + 1);
        data_map = new_data_map;
    }
    Ok(data_map)
}

/// Recursively gets the root data map by decrypting child data maps
/// Takes a chunk retrieval function that handles fetching the encrypted chunks
pub fn get_root_data_map<F>(data_map: DataMap, get_chunk: &mut F) -> Result<DataMap>
where
    F: FnMut(XorName) -> Result<Bytes>,
{
    // If this is the root data map (no child level), return it
    if !data_map.is_child() {
        return Ok(data_map);
    }

    // Get all the chunks for this data map using the provided retrieval function
    let mut encrypted_chunks = Vec::new();
    for chunk_info in data_map.infos() {
        let chunk_data = get_chunk(chunk_info.dst_hash)?;
        encrypted_chunks.push(EncryptedChunk {
            content: chunk_data,
        });
    }

    // Decrypt the chunks to get the parent data map bytes
    let decrypted_bytes = decrypt_full_set(&data_map, &encrypted_chunks)?;

    // Deserialize into a DataMap
    let parent_data_map = test_helpers::deserialise(&decrypted_bytes)
        .map_err(|_| Error::Generic("Failed to deserialize data map".to_string()))?;

    // Recursively get the root data map
    get_root_data_map(parent_data_map, get_chunk)
}

/// Decrypts data using chunks retrieved from any storage backend via the provided retrieval function.
/// Writes the decrypted output to the specified file path.
pub fn decrypt_from_storage<F>(
    data_map: &DataMap,
    output_filepath: &Path,
    mut get_chunk: F,
) -> Result<()>
where
    F: FnMut(XorName) -> Result<Bytes>,
{
    let root_map = if data_map.is_child() {
        get_root_data_map(data_map.clone(), &mut get_chunk)?
    } else {
        data_map.clone()
    };
    let mut encrypted_chunks = Vec::new();
    for chunk_info in root_map.infos() {
        let chunk_data = get_chunk(chunk_info.dst_hash)?;
        encrypted_chunks.push(EncryptedChunk {
            content: chunk_data,
        });
    }

    let decrypted_content = decrypt_full_set(&root_map, &encrypted_chunks)?;
    File::create(output_filepath)
        .map_err(Error::from)?
        .write_all(&decrypted_content)
        .map_err(Error::from)?;

    Ok(())
}

#[cfg(test)]
mod data_map_tests {
    use super::*;
    use std::sync::Mutex;
    use std::{collections::HashMap, sync::Arc};
    use tempfile::TempDir;

    // Helper function to create a data map with specified number of chunks
    fn create_test_data_map(num_chunks: usize) -> Result<DataMap> {
        let chunk_size = *MAX_CHUNK_SIZE;
        let data_size = num_chunks * chunk_size;
        let data = test_helpers::random_bytes(data_size);
        let (data_map, _) = encrypt(data)?;
        Ok(data_map)
    }

    fn create_dummy_data_map(num_chunks: usize) -> DataMap {
        let chunk_size = *MAX_CHUNK_SIZE;

        // Create dummy hashes - each hash is just the chunk number repeated
        let chunk_identifiers = (0..num_chunks)
            .map(|i| {
                let dummy_hash = XorName::from_content(&[i as u8; 32]); // Convert to XorName
                ChunkInfo {
                    index: i,
                    dst_hash: dummy_hash,
                    src_hash: dummy_hash, // Using same hash for src/dst for test
                    src_size: chunk_size,
                }
            })
            .collect();

        DataMap {
            chunk_identifiers,
            child: None,
        }
    }

    #[test]
    fn test_shrink_data_map_with_disk_storage() -> Result<()> {
        // Create a temp directory for chunk storage
        let temp_dir = TempDir::new()?;

        // Create disk-based store function
        let store = |hash: XorName, data: Bytes| -> Result<()> {
            let path = temp_dir.path().join(hex::encode(hash));
            let mut file = File::create(path)?;
            file.write_all(&data)?;
            Ok(())
        };

        // Create a large data map (5 chunks)
        let large_data_map = create_test_data_map(5)?;
        assert!(large_data_map.len() >= 4);

        // Shrink the data map
        let shrunk_map = shrink_data_map(large_data_map, store)?;

        // Verify the shrunk map has less than 4 chunks
        assert!(shrunk_map.len() < 4);
        // Verify it has a child level set
        assert!(shrunk_map.is_child());

        Ok(())
    }

    #[test]
    fn test_shrink_data_map_with_memory_storage() -> Result<()> {
        // Create in-memory storage
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let storage_clone = storage.clone();

        let store = move |hash: XorName, data: Bytes| -> Result<()> {
            let _ = storage_clone.lock().unwrap().insert(hash, data);
            Ok(())
        };

        // Create and shrink a large data map
        let large_data_map = create_test_data_map(6)?;
        let original_len = large_data_map.len();
        let shrunk_map = shrink_data_map(large_data_map, store)?;

        // Verify results
        assert!(original_len >= 4);
        assert!(shrunk_map.len() < 4);
        assert!(shrunk_map.is_child());

        // Verify chunks were stored
        assert!(!storage.lock().unwrap().is_empty());

        Ok(())
    }

    #[test]
    fn test_get_root_data_map_with_disk_storage() -> Result<()> {
        // Create temp directory
        let temp_dir = TempDir::new()?;

        // Create store and retrieve functions
        let store = |hash: XorName, data: Bytes| -> Result<()> {
            let path = temp_dir.path().join(hex::encode(hash));
            let mut file = File::create(path)?;
            file.write_all(&data)?;
            Ok(())
        };

        let mut retrieve = |hash: XorName| -> Result<Bytes> {
            let path = temp_dir.path().join(hex::encode(hash));
            let mut file = File::open(path)?;
            let mut data = Vec::new();
            let _ = file.read_to_end(&mut data)?;
            Ok(Bytes::from(data))
        };

        // Create and shrink a large data map
        let original_map = create_test_data_map(5)?;
        let shrunk_map = shrink_data_map(original_map.clone(), store)?;

        // Get the root data map
        let root_map = get_root_data_map(shrunk_map, &mut retrieve)?;

        // Verify the root map matches the original
        assert_eq!(root_map.len(), original_map.len());
        assert!(!root_map.is_child());
        assert_eq!(root_map.infos(), original_map.infos());

        Ok(())
    }

    #[test]
    fn test_get_root_data_map_with_memory_storage() -> Result<()> {
        // Create in-memory storage
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let storage_clone = storage.clone();

        let store = move |hash: XorName, data: Bytes| -> Result<()> {
            let _ = storage_clone.lock().unwrap().insert(hash, data);
            Ok(())
        };

        let storage_clone = storage.clone();
        let mut retrieve = move |hash: XorName| -> Result<Bytes> {
            storage_clone
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic("Chunk not found".to_string()))
        };

        // Create and shrink a large data map
        let original_map = create_test_data_map(5)?;
        let shrunk_map = shrink_data_map(original_map.clone(), store)?;

        // Get the root data map
        let root_map = get_root_data_map(shrunk_map, &mut retrieve)?;

        // Verify results
        assert_eq!(root_map.len(), original_map.len());
        assert!(!root_map.is_child());
        assert_eq!(root_map.infos(), original_map.infos());

        Ok(())
    }

    #[test]
    fn test_multiple_levels_of_shrinking() -> Result<()> {
        // Create in-memory storage
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let storage_clone = storage.clone();

        let store = move |hash: XorName, data: Bytes| -> Result<()> {
            let _ = storage_clone.lock().unwrap().insert(hash, data);
            Ok(())
        };

        let storage_clone = storage.clone();
        let mut retrieve = move |hash: XorName| -> Result<Bytes> {
            storage_clone
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic("Chunk not found".to_string()))
        };

        // Create a very large data map (12 chunks)
        let original_map = create_dummy_data_map(100000);
        let shrunk_map = shrink_data_map(original_map.clone(), store)?;

        // Verify multiple levels of shrinking occurred
        assert!(shrunk_map.child().unwrap() > 1);

        // Get back the root map
        let root_map = get_root_data_map(shrunk_map, &mut retrieve)?;

        // Verify the root map matches the original
        assert_eq!(root_map.len(), original_map.len());
        assert!(!root_map.is_child());
        assert_eq!(root_map.infos(), original_map.infos());

        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<()> {
        // Test with failing storage
        let store = |_: XorName, _: Bytes| -> Result<()> {
            Err(Error::Generic("Storage failed".to_string()))
        };

        let large_map = create_test_data_map(5)?;
        assert!(shrink_data_map(large_map, store).is_err());

        // Test with failing retrieval
        let mut retrieve =
            |_: XorName| -> Result<Bytes> { Err(Error::Generic("Retrieval failed".to_string())) };

        let child_map = DataMap::with_child(vec![], 1);
        assert!(get_root_data_map(child_map, &mut retrieve).is_err());

        Ok(())
    }

    #[test]
    fn test_decrypt_from_storage_with_disk() -> Result<()> {
        // Create temp directories for chunks and output
        let chunk_dir = TempDir::new()?;
        let output_dir = TempDir::new()?;

        // Create test data and encrypt it
        let test_data = test_helpers::random_bytes(1024 * 1024); // 1MB of random data
        let (data_map, encrypted_chunks) = encrypt(test_data.clone())?;

        // Store chunks to disk
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let path = chunk_dir.path().join(hex::encode(hash));
            let mut file = File::create(path)?;
            file.write_all(&chunk.content)?;
        }

        // Create disk-based retrieval function
        let get_chunk = |hash: XorName| -> Result<Bytes> {
            let path = chunk_dir.path().join(hex::encode(hash));
            let mut file = File::open(path)?;
            let mut data = Vec::new();
            let _bytes_read = file.read_to_end(&mut data)?;
            Ok(Bytes::from(data))
        };

        // Decrypt using storage function
        let output_path = output_dir.path().join("decrypted_file");
        decrypt_from_storage(&data_map, &output_path, get_chunk)?;

        // Verify decrypted content matches original
        let mut decrypted_content = Vec::new();
        let _bytes_read = File::open(output_path)?.read_to_end(&mut decrypted_content)?;
        assert_eq!(test_data, decrypted_content);

        Ok(())
    }

    #[test]
    fn test_decrypt_from_storage_with_memory() -> Result<()> {
        // Create in-memory storage
        let storage = Arc::new(Mutex::new(HashMap::new()));

        // Create test data and encrypt it
        let test_data = test_helpers::random_bytes(1024 * 1024); // 1MB of random data
        let (data_map, encrypted_chunks) = encrypt(test_data.clone())?;

        // Store chunks in memory
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _previous = storage.lock().unwrap().insert(hash, chunk.content);
        }

        // Create memory-based retrieval function
        let storage_clone = storage.clone();
        let get_chunk = move |hash: XorName| -> Result<Bytes> {
            storage_clone
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic("Chunk not found".to_string()))
        };

        // Create temp directory for output file
        let output_dir = TempDir::new()?;
        let output_path = output_dir.path().join("decrypted_file");

        // Decrypt using storage function
        decrypt_from_storage(&data_map, &output_path, get_chunk)?;

        // Verify decrypted content matches original
        let mut decrypted_content = Vec::new();
        let _bytes_read = File::open(output_path)?.read_to_end(&mut decrypted_content)?;
        assert_eq!(test_data, decrypted_content);

        Ok(())
    }

    #[test]
    fn test_decrypt_from_storage_with_missing_chunks() -> Result<()> {
        // Create in-memory storage with missing chunks
        let storage = Arc::new(Mutex::new(HashMap::new()));

        // Create test data and encrypt it
        let test_data = test_helpers::random_bytes(1024 * 1024);
        let (data_map, encrypted_chunks) = encrypt(test_data)?;

        // Store only half of the chunks
        for (i, chunk) in encrypted_chunks.into_iter().enumerate() {
            if i % 2 == 0 {
                // Skip odd-numbered chunks
                let hash = XorName::from_content(&chunk.content);
                let _previous = storage.lock().unwrap().insert(hash, chunk.content);
            }
        }

        // Create retrieval function
        let storage_clone = storage.clone();
        let get_chunk = move |hash: XorName| -> Result<Bytes> {
            storage_clone
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic("Chunk not found".to_string()))
        };

        // Attempt to decrypt with missing chunks
        let output_dir = TempDir::new()?;
        let output_path = output_dir.path().join("decrypted_file");

        // Should fail due to missing chunks
        assert!(decrypt_from_storage(&data_map, &output_path, get_chunk).is_err());

        Ok(())
    }

    #[test]
    fn test_decrypt_from_storage_with_invalid_output_path() -> Result<()> {
        // Create valid storage
        let storage = Arc::new(Mutex::new(HashMap::new()));

        // Create test data and encrypt it
        let test_data = test_helpers::random_bytes(1024 * 1024);
        let (data_map, encrypted_chunks) = encrypt(test_data)?;

        // Store chunks
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _previous = storage.lock().unwrap().insert(hash, chunk.content);
        }

        // Create retrieval function
        let storage_clone = storage.clone();
        let get_chunk = move |hash: XorName| -> Result<Bytes> {
            storage_clone
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic("Chunk not found".to_string()))
        };

        // Try to decrypt to an invalid path
        let invalid_path = Path::new("/nonexistent/directory/file");
        assert!(decrypt_from_storage(&data_map, invalid_path, get_chunk).is_err());

        Ok(())
    }

    #[test]
    fn test_decrypt_from_storage_basic_retrieval() -> Result<()> {
        let storage = Arc::new(Mutex::new(HashMap::new()));

        // Create test data and encrypt it
        let test_data = test_helpers::random_bytes(1024 * 1024);
        let (data_map, encrypted_chunks) = encrypt(test_data.clone())?;

        // Store chunks with their original hashes
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _previous = storage.lock().unwrap().insert(hash, chunk.content);
        }

        // Create simple retrieval function
        let storage_clone = storage.clone();
        let get_chunk = move |hash: XorName| -> Result<Bytes> {
            storage_clone
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .ok_or_else(|| Error::Generic(format!("Chunk not found for hash: {:?}", hash)))
        };

        let output_dir = TempDir::new()?;
        let output_path = output_dir.path().join("decrypted_file");

        // Verify basic decryption works
        decrypt_from_storage(&data_map, &output_path, get_chunk)?;

        // Verify the content matches
        let mut decrypted_content = Vec::new();
        let _bytes_read = File::open(output_path)?.read_to_end(&mut decrypted_content)?;
        assert_eq!(test_data, decrypted_content);

        Ok(())
    }
}

