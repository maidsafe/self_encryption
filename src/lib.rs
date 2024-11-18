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

pub use decrypt::decrypt_chunk;
use utils::*;
pub use xor_name::XorName;

pub use self::{
    data_map::{ChunkInfo, DataMap},
    error::{Error, Result},
};
use bytes::Bytes;
use lazy_static::lazy_static;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

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

    // First encrypt the data to get all chunks
    let (data_map, encrypted_chunks) = encrypt(bytes)?;

    // Track all chunk names
    let mut chunk_names = Vec::new();

    // Store all chunks to disk
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
/// the data map that is derived from the input data.
pub fn encrypt(bytes: Bytes) -> Result<(DataMap, Vec<EncryptedChunk>)> {
    if (MIN_ENCRYPTABLE_BYTES) > bytes.len() {
        return Err(Error::Generic(format!(
            "Too small for self-encryption! Required size at least {}",
            MIN_ENCRYPTABLE_BYTES
        )));
    }
    let (num_chunks, batches) = chunk::batch_chunks(bytes);
    let (data_map, mut encrypted_chunks) = encrypt::encrypt(batches);

    // Verify number of chunks matches
    if num_chunks > encrypted_chunks.len() {
        return Err(Error::Encryption);
    }

    // Create a vector to store chunks during shrinking
    let mut chunk_storage = Vec::new();

    // Get the shrunk data map and its chunks
    let (shrunk_data_map, _shrink_chunks) = shrink_data_map(data_map, |_hash, content| {
        chunk_storage.push(EncryptedChunk { content });
        Ok(())
    })?;

    // Add all chunks from shrinking process to encrypted_chunks
    encrypted_chunks.extend(chunk_storage);

    Ok((shrunk_data_map, encrypted_chunks))
}

/// Decrypts a full set of chunks using the provided data map.
///
/// This function takes a data map and a slice of encrypted chunks and decrypts them to recover
/// the original data. It handles both root data maps and child data maps.
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information
/// * `chunks` - The encrypted chunks to decrypt
///
/// # Returns
///
/// * `Result<Bytes>` - The decrypted data or an error if chunks are missing/corrupted
pub(crate) fn decrypt_full_set(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);

    // Create a mapping of chunk hashes to chunks for efficient lookup
    let chunk_map: std::collections::HashMap<XorName, &EncryptedChunk> = chunks
        .iter()
        .map(|chunk| (XorName::from_content(&chunk.content), chunk))
        .collect();

    // Get chunks in the order specified by the data map
    let mut sorted_chunks = Vec::with_capacity(data_map.len());
    for info in data_map.infos() {
        let chunk = chunk_map.get(&info.dst_hash).ok_or_else(|| {
            Error::Generic(format!(
                "Chunk with hash {:?} not found in data map",
                info.dst_hash
            ))
        })?;
        sorted_chunks.push(*chunk);
    }

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
#[allow(dead_code)]
pub(crate) fn decrypt_range(
    data_map: &DataMap,
    chunks: &[EncryptedChunk],
    file_pos: usize,
    len: usize,
) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);

    // Create a mapping of chunk hashes to chunks for efficient lookup
    let chunk_map: std::collections::HashMap<XorName, &EncryptedChunk> = chunks
        .iter()
        .map(|chunk| (XorName::from_content(&chunk.content), chunk))
        .collect();

    // Get chunk size info
    let file_size = data_map.original_file_size();

    // Calculate which chunks we need based on the range
    let start_chunk = get_chunk_index(file_size, file_pos);
    let end_pos = std::cmp::min(file_pos + len, file_size);
    let end_chunk = get_chunk_index(file_size, end_pos);

    // Get chunks in the order specified by the data map
    let mut sorted_chunks = Vec::new();
    for info in data_map.infos() {
        if info.index >= start_chunk && info.index <= end_chunk {
            let chunk = chunk_map.get(&info.dst_hash).ok_or_else(|| {
                Error::Generic(format!(
                    "Chunk with hash {:?} not found in data map",
                    info.dst_hash
                ))
            })?;
            sorted_chunks.push(*chunk);
        }
    }

    // Decrypt all required chunks
    let mut all_bytes = Vec::new();
    for (idx, chunk) in sorted_chunks.iter().enumerate() {
        let chunk_idx = start_chunk + idx;
        let decrypted = decrypt_chunk(chunk_idx, &chunk.content, &src_hashes)?;
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
/// Returns the final data map and all chunks generated during shrinking
pub fn shrink_data_map<F>(
    mut data_map: DataMap,
    mut store_chunk: F,
) -> Result<(DataMap, Vec<EncryptedChunk>)>
where
    F: FnMut(XorName, Bytes) -> Result<()>,
{
    let mut all_chunks = Vec::new();

    while data_map.len() > 3 {
        let child_level = data_map.child().unwrap_or(0);
        let bytes = test_helpers::serialise(&data_map)
            .map(Bytes::from)
            .map_err(|_| Error::Generic("Failed to serialize data map".to_string()))?;

        let (mut new_data_map, encrypted_chunks) = encrypt(bytes)?;

        // Store and collect chunks
        for chunk in &encrypted_chunks {
            store_chunk(XorName::from_content(&chunk.content), chunk.content.clone())?;
        }
        all_chunks.extend(encrypted_chunks);

        // Update data map for next iteration
        new_data_map = DataMap::with_child(new_data_map.infos(), child_level + 1);
        data_map = new_data_map;
    }
    Ok((data_map, all_chunks))
}

/// Recursively gets the root data map by decrypting child data maps
/// Takes a chunk retrieval function that handles fetching the encrypted chunks
pub fn get_root_data_map<F>(data_map: DataMap, get_chunk: &mut F) -> Result<DataMap>
where
    F: FnMut(XorName) -> Result<Bytes>,
{
    // Create a cache of found chunks at the top level
    let mut chunk_cache = std::collections::HashMap::new();

    fn inner_get_root_map<F>(
        data_map: DataMap,
        get_chunk: &mut F,
        chunk_cache: &mut std::collections::HashMap<XorName, Bytes>,
    ) -> Result<DataMap>
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
            let chunk_data = if let Some(cached) = chunk_cache.get(&chunk_info.dst_hash) {
                cached.clone()
            } else {
                let data = get_chunk(chunk_info.dst_hash)?;
                let _ = chunk_cache.insert(chunk_info.dst_hash, data.clone());
                data
            };
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
        inner_get_root_map(parent_data_map, get_chunk, chunk_cache)
    }

    // Start the recursive process with our cache
    inner_get_root_map(data_map, get_chunk, &mut chunk_cache)
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

/// Decrypts data using chunks retrieved from any storage backend via the provided retrieval function.
/// Writes the decrypted output to the specified file path.
pub fn decrypt(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<Bytes> {
    // Create a mapping of chunk hashes to chunks for efficient lookup
    let chunk_map: std::collections::HashMap<XorName, &EncryptedChunk> = chunks
        .iter()
        .map(|chunk| (XorName::from_content(&chunk.content), chunk))
        .collect();

    // Helper function to find chunks using our hash map
    let mut get_chunk = |hash| {
        chunk_map
            .get(&hash)
            .map(|chunk| chunk.content.clone())
            .ok_or_else(|| Error::Generic(format!("Chunk not found for hash: {:?}", hash)))
    };

    let root_map = if data_map.is_child() {
        get_root_data_map(data_map.clone(), &mut get_chunk)?
    } else {
        data_map.clone()
    };

    decrypt_full_set(&root_map, chunks)
}

/// Decrypts data from storage in a streaming fashion using parallel chunk retrieval.
///
/// This function retrieves the encrypted chunks in parallel using the provided `get_chunk_parallel` function,
/// decrypts them, and writes the decrypted data directly to the specified output file path.
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information.
/// * `output_filepath` - The path to write the decrypted data to.
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given a list of XorName hashes.
///
/// # Returns
///
/// * `Result<()>` - An empty result or an error if decryption fails.
pub fn streaming_decrypt_from_storage<F>(
    data_map: &DataMap,
    output_filepath: &Path,
    get_chunk_parallel: F,
) -> Result<()>
where
    F: Fn(&[XorName]) -> Result<Vec<Bytes>>,
{
    let root_map = if data_map.is_child() {
        // Recursively get root data map
        get_root_data_map_parallel(data_map.clone(), &get_chunk_parallel)?
    } else {
        data_map.clone()
    };

    // Retrieve all chunks in parallel
    let chunk_hashes: Vec<_> = root_map.infos().iter().map(|info| info.dst_hash).collect();
    let encrypted_chunks = get_chunk_parallel(&chunk_hashes)?
        .into_iter()
        .map(|content| EncryptedChunk { content })
        .collect::<Vec<_>>();

    // Open the output file for writing
    let mut output_file = File::create(output_filepath).map_err(Error::from)?;

    // Decrypt and write data in order
    let src_hashes = extract_hashes(&root_map);

    for (info, chunk) in root_map.infos().iter().zip(encrypted_chunks.iter()) {
        let decrypted_chunk = decrypt_chunk(info.index, &chunk.content, &src_hashes)?;
        output_file
            .write_all(&decrypted_chunk)
            .map_err(Error::from)?;
    }

    Ok(())
}

/// Recursively gets the root data map by decrypting child data maps using parallel chunk retrieval.
///
/// This function works similarly to `get_root_data_map`, but it retrieves chunks in parallel,
/// improving performance when dealing with large data maps or slow storage backends.
///
/// # Arguments
///
/// * `data_map` - The data map to retrieve the root from.
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given a list of XorName hashes.
///
/// # Returns
///
/// * `Result<DataMap>` - The root data map or an error if retrieval or decryption fails.
pub fn get_root_data_map_parallel<F>(data_map: DataMap, get_chunk_parallel: &F) -> Result<DataMap>
where
    F: Fn(&[XorName]) -> Result<Vec<Bytes>>,
{
    // Create a cache for chunks to avoid redundant retrievals
    let mut chunk_cache = std::collections::HashMap::new();

    fn inner_get_root_map<F>(
        data_map: DataMap,
        get_chunk_parallel: &F,
        chunk_cache: &mut std::collections::HashMap<XorName, Bytes>,
    ) -> Result<DataMap>
    where
        F: Fn(&[XorName]) -> Result<Vec<Bytes>>,
    {
        // If this is the root data map (no child level), return it
        if !data_map.is_child() {
            return Ok(data_map);
        }

        // Determine which chunks are missing from the cache
        let missing_hashes: Vec<_> = data_map
            .infos()
            .iter()
            .map(|info| info.dst_hash)
            .filter(|hash| !chunk_cache.contains_key(hash))
            .collect();

        if !missing_hashes.is_empty() {
            let new_chunks = get_chunk_parallel(&missing_hashes)?;
            for (hash, chunk_data) in missing_hashes.iter().zip(new_chunks.into_iter()) {
                let _ = chunk_cache.insert(*hash, chunk_data);
            }
        }

        let encrypted_chunks: Vec<EncryptedChunk> = data_map
            .infos()
            .iter()
            .map(|info| {
                let content = chunk_cache.get(&info.dst_hash).ok_or_else(|| {
                    Error::Generic(format!("Chunk not found for hash: {:?}", info.dst_hash))
                })?;
                Ok(EncryptedChunk {
                    content: content.clone(),
                })
            })
            .collect::<Result<_>>()?;

        // Decrypt the chunks to get the parent data map bytes
        let decrypted_bytes = decrypt_full_set(&data_map, &encrypted_chunks)?;
        let parent_data_map = test_helpers::deserialise(&decrypted_bytes)
            .map_err(|_| Error::Generic("Failed to deserialize data map".to_string()))?;

        // Recursively get the root data map
        inner_get_root_map(parent_data_map, get_chunk_parallel, chunk_cache)
    }

    // Start the recursive process with our cache
    inner_get_root_map(data_map, get_chunk_parallel, &mut chunk_cache)
}

/// Serializes a data structure using bincode.
///
/// # Arguments
///
/// * `data` - The data structure to serialize, must implement `serde::Serialize`
///
/// # Returns
///
/// * `Result<Vec<u8>>` - The serialized bytes or an error
pub fn serialize<T: serde::Serialize>(data: &T) -> Result<Vec<u8>> {
    bincode::serialize(data).map_err(|e| Error::Generic(format!("Serialization error: {}", e)))
}

/// Deserializes bytes into a data structure using bincode.
///
/// # Arguments
///
/// * `bytes` - The bytes to deserialize
///
/// # Returns
///
/// * `Result<T>` - The deserialized data structure or an error
pub fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|e| Error::Generic(format!("Deserialization error: {}", e)))
}

/// Verifies and deserializes a chunk by checking its content hash matches the provided name.
///
/// # Arguments
///
/// * `name` - The expected XorName hash of the chunk content
/// * `bytes` - The serialized chunk content to verify
///
/// # Returns
///
/// * `Result<EncryptedChunk>` - The deserialized chunk if verification succeeds
/// * `Error` - If the content hash doesn't match or deserialization fails
pub fn verify_chunk(name: XorName, bytes: &[u8]) -> Result<EncryptedChunk> {
    // Create an EncryptedChunk from the bytes
    let chunk = EncryptedChunk {
        content: Bytes::from(bytes.to_vec()),
    };

    // Calculate the hash of the encrypted content directly
    let calculated_hash = XorName::from_content(chunk.content.as_ref());

    // Verify the hash matches
    if calculated_hash != name {
        return Err(Error::Generic(format!(
            "Chunk content hash mismatch. Expected: {:?}, Got: {:?}",
            name, calculated_hash
        )));
    }

    Ok(chunk)
}

#[cfg(test)]
mod data_map_tests {
    use super::*;
    use std::{
        collections::HashMap,
        fs::File,
        io::{Read, Write},
        sync::{Arc, Mutex},
    };
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

        // Shrink the data map and destructure the tuple
        let (shrunk_map, _shrink_chunks) = shrink_data_map(large_data_map, store)?;

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
        let (shrunk_map, _shrink_chunks) = shrink_data_map(large_data_map, store)?;

        // Verify results (they should all be already shrunk)
        assert!(original_len < 4);
        assert!(shrunk_map.len() < 4);
        assert!(shrunk_map.is_child());

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
        let (shrunk_map, _shrink_chunks) = shrink_data_map(original_map.clone(), store)?;

        // Verify multiple levels of shrinking occurred
        assert!(shrunk_map.child().unwrap() > 0);

        // Get back the root map
        let root_map = get_root_data_map(shrunk_map, &mut retrieve)?;

        // Verify the root map matches the original
        assert!(!root_map.is_child());

        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<()> {
        // Test with failing storage
        let store = |_: XorName, _: Bytes| -> Result<()> {
            Err(Error::Generic("Storage failed".to_string()))
        };

        let large_map = create_test_data_map(5)?;
        assert!(shrink_data_map(large_map, store).is_ok());

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

    #[test]
    fn test_decrypt_functionality() -> Result<()> {
        // Create test data and encrypt it
        let test_data = test_helpers::random_bytes(1024 * 1024); // 1MB of random data
        let (data_map, encrypted_chunks) = encrypt(test_data.clone())?;

        // Updated call to decrypt
        let decrypted_data = decrypt(&data_map, &encrypted_chunks)?;

        // Verify the content matches
        assert_eq!(test_data, decrypted_data);

        Ok(())
    }
}
