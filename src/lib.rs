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
    while_true
)]
#![cfg_attr(not(feature = "python"), deny(warnings))]
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

mod aes;
mod chunk;
mod data_map;
mod decrypt;
mod encrypt;
mod error;
#[cfg(feature = "python")]
mod python;
/// Stream encryption and decryption
mod stream;
pub mod test_helpers;
mod utils;

pub use chunk::EncryptedChunk;
pub use decrypt::decrypt_chunk;
use utils::*;
pub use xor_name::XorName;

pub use self::{
    data_map::{ChunkInfo, DataMap},
    error::{Error, Result},
    stream::{StreamSelfDecryptor, StreamSelfEncryptor},
};
use bytes::Bytes;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

// export these because they are used in our public API.
pub use bytes;
pub use xor_name;

/// The minimum size (before compression) of data to be self-encrypted, defined as 3B.
pub const MIN_ENCRYPTABLE_BYTES: usize = 3 * MIN_CHUNK_SIZE;

/// The maximum size (before compression) of an individual chunk of a file, defaulting as 1MiB.
pub const MAX_CHUNK_SIZE: usize = match std::option_env!("MAX_CHUNK_SIZE") {
    Some(v) => match usize::from_str_radix(v, 10) {
        Ok(v) => v,
        Err(_err) => panic!("`MAX_CHUNK_SIZE` failed to parse as usize"),
    },
    // Default to 1MiB
    None => 1024 * 1024,
};

/// The minimum size (before compression) of an individual chunk of a file, defined as 1B.
pub const MIN_CHUNK_SIZE: usize = 1;
/// Controls the compression-speed vs compression-density tradeoffs.  The higher the quality, the
/// slower the compression.  Range is 0 to 11.
pub const COMPRESSION_QUALITY: i32 = 6;

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
    let file_size = bytes.len();
    if file_size < MIN_ENCRYPTABLE_BYTES {
        return Err(Error::Generic(format!(
            "Too small for self-encryption! Required size at least {MIN_ENCRYPTABLE_BYTES}"
        )));
    }

    let num_chunks = get_num_chunks(file_size);
    if num_chunks < 3 {
        return Err(Error::Generic(
            "File must be large enough to generate at least 3 chunks".to_string(),
        ));
    }

    let mut chunk_infos = Vec::with_capacity(num_chunks);
    let mut first_chunks = Vec::with_capacity(2);
    let mut src_hashes = Vec::with_capacity(num_chunks);
    let mut encrypted_chunks = Vec::with_capacity(num_chunks);

    // Process all chunks
    for chunk_index in 0..num_chunks {
        let (start, end) = get_start_end_positions(file_size, chunk_index);
        let chunk_data = bytes.slice(start..end);
        let src_hash = XorName::from_content(&chunk_data);
        src_hashes.push(src_hash);

        // Store first two chunks for later processing
        if chunk_index < 2 {
            first_chunks.push((chunk_index, chunk_data, src_hash, end - start));
            continue;
        }

        // For chunks 2 onwards, we can encrypt immediately since we have the previous two hashes
        let pki = get_pad_key_and_iv(chunk_index, &src_hashes);
        let encrypted_content = encrypt::encrypt_chunk(chunk_data, pki)?;
        let dst_hash = XorName::from_content(&encrypted_content);

        encrypted_chunks.push(EncryptedChunk {
            content: encrypted_content,
        });

        chunk_infos.push(ChunkInfo {
            index: chunk_index,
            dst_hash,
            src_hash,
            src_size: end - start,
        });
    }

    // Now process the first two chunks using the complete set of source hashes
    for (chunk_index, chunk_data, src_hash, src_size) in first_chunks {
        let pki = get_pad_key_and_iv(chunk_index, &src_hashes);
        let encrypted_content = encrypt::encrypt_chunk(chunk_data, pki)?;
        let dst_hash = XorName::from_content(&encrypted_content);

        encrypted_chunks.insert(
            chunk_index,
            EncryptedChunk {
                content: encrypted_content,
            },
        );

        chunk_infos.insert(
            chunk_index,
            ChunkInfo {
                index: chunk_index,
                dst_hash,
                src_hash,
                src_size,
            },
        );
    }

    let data_map = DataMap::new(chunk_infos);

    // Shrink the data map and store additional chunks if needed
    let (shrunk_data_map, _) = shrink_data_map(data_map, |_hash, content| {
        encrypted_chunks.push(EncryptedChunk { content });
        Ok(())
    })?;

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
            .ok_or_else(|| Error::Generic(format!("Chunk not found for hash: {hash:?}")))
    };

    // Get the root map if we're dealing with a child map
    let root_map = if data_map.is_child() {
        get_root_data_map(data_map.clone(), &mut get_chunk)?
    } else {
        data_map.clone()
    };

    // Get only the chunks needed for the root map
    let root_chunks: Vec<EncryptedChunk> = root_map
        .infos()
        .iter()
        .map(|info| {
            chunk_map
                .get(&info.dst_hash)
                .map(|chunk| EncryptedChunk {
                    content: chunk.content.clone(),
                })
                .ok_or_else(|| {
                    Error::Generic(format!("Missing chunk: {}", hex::encode(info.dst_hash)))
                })
        })
        .collect::<Result<_>>()?;

    decrypt_full_set(&root_map, &root_chunks)
}

/// Decrypts data from storage using streaming approach, processing chunks in batches
/// to minimize memory usage.
///
/// This function implements true streaming by:
/// 1. Processing chunks in ordered batches
/// 2. Fetching one batch at a time
/// 3. Decrypting and writing each batch immediately to disk
/// 4. Continuing until all chunks are processed
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information
/// * `output_filepath` - The path to write the decrypted data to
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given a list of XorName hashes
///
/// # Returns
///
/// * `Result<()>` - An empty result or an error if decryption fails
pub fn streaming_decrypt_from_storage<F>(
    data_map: &DataMap,
    output_filepath: &Path,
    get_chunk_parallel: F,
) -> Result<()>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    let root_map = if data_map.is_child() {
        get_root_data_map_parallel(data_map.clone(), &get_chunk_parallel)?
    } else {
        data_map.clone()
    };

    // Get all chunk information and source hashes
    let mut chunk_infos = root_map.infos().to_vec();
    // Sort chunks by index to ensure proper order during processing
    chunk_infos.sort_by_key(|info| info.index);
    let src_hashes = extract_hashes(&root_map);

    // Process chunks in batches to minimize memory usage
    // Use a reasonable batch size - could be made configurable
    const BATCH_SIZE: usize = 10;

    for batch_start in (0..chunk_infos.len()).step_by(BATCH_SIZE) {
        let batch_end = (batch_start + BATCH_SIZE).min(chunk_infos.len());
        let batch_infos = &chunk_infos[batch_start..batch_end];

        // Extract chunk hashes for this batch
        let batch_hashes: Vec<_> = batch_infos.iter().map(|info| (info.index, info.dst_hash)).collect();

        // Fetch only the chunks for this batch
        let mut fetched_chunks = get_chunk_parallel(&batch_hashes)?;
        // Shall be ordered to allow sequential appended to file
        fetched_chunks.sort_by_key(|(index, _content)| *index);

        let batch_chunks = fetched_chunks
            .into_iter()
            .map(|(_index, content)| EncryptedChunk { content })
            .collect::<Vec<_>>();

        // Process and write this batch immediately to disk
        for (i, (info, chunk)) in batch_infos.iter().zip(batch_chunks.iter()).enumerate() {
            let decrypted_chunk = decrypt_chunk(info.index, &chunk.content, &src_hashes)?;

            // For the first chunk in the entire process, create/overwrite the file
            // For subsequent chunks, append to the file
            if batch_start == 0 && i == 0 {
                // First chunk: create/overwrite the file
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true) // Ensure we start with a clean file
                    .open(output_filepath)?;
                file.write_all(&decrypted_chunk)?;
                file.sync_all()?;
            } else {
                // Subsequent chunks: append to the file
                append_to_file(output_filepath, &decrypted_chunk)?;
            }
        }
    }

    Ok(())
}

/// Appends content to an existing file.
/// This function is memory-efficient as it doesn't keep the file handle open.
/// Note: This should only be used for chunks after the first one, as it appends to existing content.
fn append_to_file(file_path: &Path, content: &Bytes) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_path)?;

    file.write_all(content)?;
    file.sync_all()?; // Ensure data is written to disk

    Ok(())
}

/// Reads a file in chunks, encrypts them, and stores them using a provided functor.
/// Returns a DataMap.
pub fn streaming_encrypt_from_file<F>(file_path: &Path, mut chunk_store: F) -> Result<DataMap>
where
    F: FnMut(XorName, Bytes) -> Result<()>,
{
    use std::io::{BufReader, Read};

    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len() as usize;

    if file_size < MIN_ENCRYPTABLE_BYTES {
        return Err(Error::Generic(format!(
            "Too small for self-encryption! Required size at least {MIN_ENCRYPTABLE_BYTES}"
        )));
    }

    let num_chunks = get_num_chunks(file_size);
    if num_chunks < 3 {
        return Err(Error::Generic(
            "File must be large enough to generate at least 3 chunks".to_string(),
        ));
    }

    let mut reader = BufReader::with_capacity(MAX_CHUNK_SIZE, file);
    let mut chunk_infos = Vec::with_capacity(num_chunks);

    // Ring buffer to hold all source hashes
    let mut src_hash_buffer = Vec::with_capacity(num_chunks);
    let mut first_chunks = Vec::with_capacity(2);

    // First pass: collect all source hashes
    for chunk_index in 0..num_chunks {
        let (start, end) = get_start_end_positions(file_size, chunk_index);
        let chunk_size = end - start;
        let mut chunk_data = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk_data)?;

        let chunk_bytes = Bytes::from(chunk_data);
        let src_hash = XorName::from_content(&chunk_bytes);
        src_hash_buffer.push(src_hash);

        if chunk_index < 2 {
            first_chunks.push((chunk_index, chunk_bytes, chunk_size));
        } else {
            // Process chunks after the first two immediately
            let pki = get_pad_key_and_iv(chunk_index, &src_hash_buffer);
            let encrypted_content = encrypt::encrypt_chunk(chunk_bytes, pki)?;
            let dst_hash = XorName::from_content(&encrypted_content);

            chunk_store(dst_hash, encrypted_content)?;

            chunk_infos.push(ChunkInfo {
                index: chunk_index,
                dst_hash,
                src_hash,
                src_size: chunk_size,
            });
        }
    }

    // Process first two chunks now that we have all hashes
    for (chunk_index, chunk_data, chunk_size) in first_chunks {
        let pki = get_pad_key_and_iv(chunk_index, &src_hash_buffer);
        let encrypted_content = encrypt::encrypt_chunk(chunk_data, pki)?;
        let dst_hash = XorName::from_content(&encrypted_content);

        chunk_store(dst_hash, encrypted_content)?;

        chunk_infos.insert(
            chunk_index,
            ChunkInfo {
                index: chunk_index,
                dst_hash,
                src_hash: src_hash_buffer[chunk_index],
                src_size: chunk_size,
            },
        );
    }

    // Create initial data map and shrink it
    let data_map = DataMap::new(chunk_infos);
    let (shrunk_map, _) = shrink_data_map(data_map, |hash, content| {
        chunk_store(hash, content)?;
        Ok(())
    })?;

    // Return the shrunk map - decrypt will handle getting back to the root map
    Ok(shrunk_map)
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
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    // Create a cache for chunks to avoid redundant retrievals
    let mut chunk_cache = std::collections::HashMap::new();

    fn inner_get_root_map<F>(
        data_map: DataMap,
        get_chunk_parallel: &F,
        chunk_cache: &mut std::collections::HashMap<XorName, Bytes>,
    ) -> Result<DataMap>
    where
        F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
    {
        // If this is the root data map (no child level), return it
        if !data_map.is_child() {
            return Ok(data_map);
        }

        // Determine which chunks are missing from the cache
        let missing_hashes: Vec<_> = data_map
            .infos()
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .filter(|(_i, hash)| !chunk_cache.contains_key(hash))
            .collect();

        if !missing_hashes.is_empty() {
            let new_chunks = get_chunk_parallel(&missing_hashes)?;
            for ((_i, hash), (_j, chunk_data)) in missing_hashes.iter().zip(new_chunks.into_iter()) {
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
    bincode::serialize(data).map_err(|e| Error::Generic(format!("Serialization error: {e}")))
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
    bincode::deserialize(bytes).map_err(|e| Error::Generic(format!("Deserialization error: {e}")))
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
            "Chunk content hash mismatch. Expected: {name:?}, Got: {calculated_hash:?}"
        )));
    }

    Ok(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::random_bytes;
    use std::{
        collections::HashMap,
        io::Write,
        sync::{Arc, Mutex},
    };
    use tempfile::NamedTempFile;

    // Helper function to create a data map with specified number of chunks
    #[allow(dead_code)]
    fn create_test_data_map(num_chunks: usize) -> Result<DataMap> {
        let bytes = random_bytes(num_chunks * MIN_CHUNK_SIZE);
        let (data_map, _) = encrypt(bytes)?;
        Ok(data_map)
    }

    #[allow(dead_code)]
    fn create_dummy_data_map(num_chunks: usize) -> DataMap {
        let mut chunks = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            chunks.push(ChunkInfo {
                index: i,
                dst_hash: XorName::from_content(&[i as u8]),
                src_hash: XorName::from_content(&[i as u8]),
                src_size: MIN_CHUNK_SIZE,
            });
        }
        DataMap::new(chunks)
    }

    #[test]
    fn test_multiple_levels_of_shrinking() -> Result<()> {
        // Create a temp file with random data
        let bytes = random_bytes(10_000_000);
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(&bytes)?;

        let storage = HashMap::new();
        let storage_clone = Arc::new(Mutex::new(storage));

        let store = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.lock().unwrap().insert(hash, content.to_vec());
            Ok(())
        };

        let data_map = streaming_encrypt_from_file(temp_file.path(), store)?;
        assert!(data_map.chunk_identifiers.len() <= 3);

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_4mb_file() -> Result<()> {
        // Create test data - exactly 4MB
        let file_size = 4 * 1024 * 1024;
        let bytes = random_bytes(file_size);

        // Create storage for encrypted chunks
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let storage_clone = storage.clone();

        // Store function that also prints chunk info for debugging
        let store = move |hash: XorName, content: Bytes| -> Result<()> {
            println!(
                "Storing chunk: {} (size: {}) at index {}",
                hex::encode(hash),
                content.len(),
                storage_clone.lock().unwrap().len()
            );
            let _ = storage_clone.lock().unwrap().insert(hash, content.to_vec());
            Ok(())
        };

        // First encrypt the data directly to get ALL chunks
        let (data_map, initial_chunks) = encrypt(bytes.clone())?;

        println!("Initial data map has {} chunks", data_map.len());
        println!("Data map child level: {:?}", data_map.child());

        // Start with all initial chunks
        let mut all_chunks = Vec::new();
        all_chunks.extend(initial_chunks);

        // Store all chunks
        for chunk in &all_chunks {
            let hash = XorName::from_content(&chunk.content);
            store(hash, chunk.content.clone())?;
        }

        // Now do a shrink operation
        let mut store_memory = store.clone();
        let (shrunk_map, shrink_chunks) = shrink_data_map(data_map.clone(), &mut store_memory)?;
        println!("Got {} new chunks from shrinking", shrink_chunks.len());

        // Add shrink chunks to our collection
        all_chunks.extend(shrink_chunks);

        println!("\nFinal Data Map Info:");
        println!("Number of chunks: {}", shrunk_map.len());
        println!("Original file size: {file_size}");
        println!("Is child: {}", shrunk_map.is_child());

        for (i, info) in shrunk_map.infos().iter().enumerate() {
            println!(
                "Chunk {}: index={}, src_size={}, src_hash={}, dst_hash={}",
                i,
                info.index,
                info.src_size,
                hex::encode(info.src_hash),
                hex::encode(info.dst_hash)
            );
        }

        // Print all stored chunks
        println!("\nStored Chunks:");
        let stored = storage.lock().unwrap();
        for (hash, content) in stored.iter() {
            println!("Hash: {} (size: {})", hex::encode(hash), content.len());
        }

        // Create output file for decryption
        let output_file = tempfile::NamedTempFile::new()?;

        // Create chunk retrieval function
        let stored_clone = stored.clone();
        let get_chunk = |hash: XorName| -> Result<Bytes> {
            stored_clone
                .get(&hash)
                .map(|data| Bytes::from(data.clone()))
                .ok_or_else(|| Error::Generic(format!("Missing chunk: {}", hex::encode(hash))))
        };

        // Decrypt using decrypt_from_storage
        decrypt_from_storage(&shrunk_map, output_file.path(), get_chunk)?;

        // Read and verify the decrypted data
        let mut decrypted = Vec::new();
        let _ = output_file.as_file().read_to_end(&mut decrypted)?;

        assert_eq!(decrypted.len(), file_size);
        assert_eq!(&decrypted[..], &bytes[..]);

        Ok(())
    }
}
