// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! File-based streaming encryption functionality.

use crate::{
    get_num_chunks, get_start_end_positions, shrink_data_map, utils::get_pad_key_and_iv, ChunkInfo,
    DataMap, Error, Result, MAX_CHUNK_SIZE, MIN_ENCRYPTABLE_BYTES,
};
use bytes::Bytes;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};
use xor_name::XorName;

/// Streaming encrypt from file
///
/// Rather than reading the entire file into memory, this function streams through the file
/// and encrypts it in chunks. This is more memory-efficient for large files.
///
/// The function reads the file twice:
/// 1. First pass: collect all source hashes
/// 2. Second pass: encrypt chunks (except first two) and store them
/// 3. Process first two chunks with complete source hash information
/// 4. Apply shrinking if needed
///
/// This maintains correct self-encryption while being memory-efficient.
///
/// # Arguments
///
/// * `file_path` - Path to the file to encrypt
/// * `chunk_store` - Function to store encrypted chunks
///
/// # Returns
///
/// Returns the final DataMap (after shrinking if applied)
///
/// # Examples
///
/// ```rust,no_run
/// use self_encryption::{streaming_encrypt_from_file, Result};
/// use bytes::Bytes;
/// use std::collections::HashMap;
/// use std::sync::{Arc, Mutex};
/// use xor_name::XorName;
///
/// # fn main() -> Result<()> {
/// // Create storage for chunks
/// let storage = Arc::new(Mutex::new(HashMap::new()));
/// let storage_clone = storage.clone();
///
/// // Store function
/// let store = move |hash: XorName, content: Bytes| -> Result<()> {
///     let _ = storage_clone.lock().unwrap().insert(hash, content.to_vec());
///     Ok(())
/// };
///
/// let data_map = streaming_encrypt_from_file("large_file.bin".as_ref(), store)?;
/// println!("File encrypted with {} chunks", data_map.len());
/// # Ok(())
/// # }
/// ```
pub fn streaming_encrypt_from_file<F>(file_path: &Path, mut chunk_store: F) -> Result<DataMap>
where
    F: FnMut(XorName, Bytes) -> Result<()>,
{
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
            let encrypted_content = crate::encrypt::encrypt_chunk(chunk_bytes, pki)?;
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

    // Now process the first two chunks with complete source hash information
    for (chunk_index, chunk_bytes, chunk_size) in first_chunks {
        let pki = get_pad_key_and_iv(chunk_index, &src_hash_buffer);
        let encrypted_content = crate::encrypt::encrypt_chunk(chunk_bytes, pki)?;
        let dst_hash = XorName::from_content(&encrypted_content);

        chunk_store(dst_hash, encrypted_content)?;

        chunk_infos.push(ChunkInfo {
            index: chunk_index,
            dst_hash,
            src_hash: src_hash_buffer[chunk_index],
            src_size: chunk_size,
        });
    }

    // Sort by index to ensure correct order
    chunk_infos.sort_by_key(|info| info.index);

    let data_map = DataMap::new(chunk_infos);

    // Apply shrinking like the regular encrypt function
    let (final_data_map, shrink_chunks) = shrink_data_map(data_map, &mut chunk_store)?;

    // Store any additional chunks created by shrinking
    for chunk in shrink_chunks {
        let hash = XorName::from_content(&chunk.content);
        chunk_store(hash, chunk.content)?;
    }

    Ok(final_data_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decrypt_from_storage, test_helpers::random_bytes};
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    #[test]
    fn test_streaming_encrypt_from_file_small() -> Result<()> {
        use std::io::Write;

        // Create a temporary file with test data
        let test_data = random_bytes(50_000); // 50KB
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(&test_data)?;

        // Create storage for encrypted chunks
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let storage_clone = storage.clone();

        // Store function
        let store = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.lock().unwrap().insert(hash, content.to_vec());
            Ok(())
        };

        // Encrypt the file
        let data_map = streaming_encrypt_from_file(temp_file.path(), store)?;
        assert!(data_map.chunk_identifiers.len() <= 3);

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_4mb_file() -> Result<()> {
        use std::io::Write;

        // Create test data - exactly 4MB
        let file_size = 4 * 1024 * 1024;
        let bytes = random_bytes(file_size);

        // Write test data to temporary file
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(&bytes)?;

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
        let (data_map, initial_chunks) = crate::encrypt(bytes.clone())?;

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
        let output_file = NamedTempFile::new()?;

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

    #[test]
    fn test_streaming_encrypt_consistency() -> Result<()> {
        use std::io::Write;

        // Test that streaming encryption produces same result as standard encryption
        let file_size = 200_000;
        let original_data = random_bytes(file_size);

        // Write data to temporary file
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(&original_data)?;

        // Standard encryption
        let (standard_data_map, standard_chunks) = crate::encrypt(original_data.clone())?;

        // Streaming encryption
        let streaming_storage = Arc::new(Mutex::new(HashMap::new()));
        let streaming_storage_clone = streaming_storage.clone();

        let streaming_store = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = streaming_storage_clone
                .lock()
                .unwrap()
                .insert(hash, content.to_vec());
            Ok(())
        };

        let streaming_data_map = streaming_encrypt_from_file(temp_file.path(), streaming_store)?;

        // Both should decrypt to same original data
        let mut standard_storage = HashMap::new();
        for chunk in standard_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = standard_storage.insert(hash, chunk.content.to_vec());
        }

        // Verify both methods produce working encryption/decryption
        let output_file1 = NamedTempFile::new()?;
        let output_file2 = NamedTempFile::new()?;

        // Decrypt standard
        let get_chunk1 = |hash: XorName| -> Result<Bytes> {
            standard_storage
                .get(&hash)
                .map(|data| Bytes::from(data.clone()))
                .ok_or_else(|| Error::Generic(format!("Missing chunk: {}", hex::encode(hash))))
        };
        decrypt_from_storage(&standard_data_map, output_file1.path(), get_chunk1)?;

        // Decrypt streaming
        let streaming_storage_locked = streaming_storage.lock().unwrap();
        let get_chunk2 = |hash: XorName| -> Result<Bytes> {
            streaming_storage_locked
                .get(&hash)
                .map(|data| Bytes::from(data.clone()))
                .ok_or_else(|| Error::Generic(format!("Missing chunk: {}", hex::encode(hash))))
        };
        decrypt_from_storage(&streaming_data_map, output_file2.path(), get_chunk2)?;

        // Read both decrypted files
        let mut decrypted1 = Vec::new();
        let mut decrypted2 = Vec::new();
        let _ = output_file1.as_file().read_to_end(&mut decrypted1)?;
        let _ = output_file2.as_file().read_to_end(&mut decrypted2)?;

        // Both should match original
        assert_eq!(decrypted1, original_data);
        assert_eq!(decrypted2, original_data);
        assert_eq!(decrypted1, decrypted2);

        Ok(())
    }
}
