// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Streaming decryption functionality for memory-efficient processing of large encrypted files.

use crate::{
    decrypt::decrypt_chunk, get_root_data_map_parallel, utils::extract_hashes, ChunkInfo, DataMap,
    Result,
};
use bytes::Bytes;
use xor_name::XorName;

/// Iterator that yields decrypted chunks as `Bytes` in streaming fashion.
///
/// This provides memory-efficient decryption by processing chunks in batches
/// and yielding them one at a time without buffering the entire file.
pub struct StreamingDecrypt<F> {
    chunk_infos: Vec<ChunkInfo>,
    src_hashes: Vec<XorName>,
    get_chunk_parallel: F,
    current_batch_start: usize,
    current_batch_chunks: Vec<Bytes>,
    current_batch_index: usize,
    batch_size: usize,
}

impl<F> StreamingDecrypt<F>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    /// Creates a new streaming decrypt iterator.
    ///
    /// # Arguments
    ///
    /// * `data_map` - The data map containing chunk information
    /// * `get_chunk_parallel` - Function to retrieve chunks in parallel
    /// * `batch_size` - Number of chunks to process in each batch (defaults to 10)
    pub fn new(
        data_map: &DataMap,
        get_chunk_parallel: F,
        batch_size: Option<usize>,
    ) -> Result<Self> {
        let root_map = if data_map.is_child() {
            get_root_data_map_parallel(data_map.clone(), &get_chunk_parallel)?
        } else {
            data_map.clone()
        };

        let mut chunk_infos = root_map.infos().to_vec();
        chunk_infos.sort_by_key(|info| info.index);
        let src_hashes = extract_hashes(&root_map);

        Ok(Self {
            chunk_infos,
            src_hashes,
            get_chunk_parallel,
            current_batch_start: 0,
            current_batch_chunks: Vec::new(),
            current_batch_index: 0,
            batch_size: batch_size.unwrap_or(10),
        })
    }

    /// Fetches and decrypts the next batch of chunks.
    fn fetch_next_batch(&mut self) -> Result<bool> {
        if self.current_batch_start >= self.chunk_infos.len() {
            return Ok(false); // No more chunks
        }

        let batch_end = (self.current_batch_start + self.batch_size).min(self.chunk_infos.len());
        let batch_infos = &self.chunk_infos[self.current_batch_start..batch_end];

        // Extract chunk hashes for this batch
        let batch_hashes: Vec<_> = batch_infos
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .collect();

        // Fetch chunks in parallel
        let mut fetched_chunks = (self.get_chunk_parallel)(&batch_hashes)?;
        fetched_chunks.sort_by_key(|(index, _content)| *index);

        // Decrypt each chunk and store the results
        self.current_batch_chunks.clear();
        for (info, (_index, encrypted_content)) in
            batch_infos.iter().zip(fetched_chunks.into_iter())
        {
            let decrypted_chunk = decrypt_chunk(info.index, &encrypted_content, &self.src_hashes)?;
            self.current_batch_chunks.push(decrypted_chunk);
        }

        self.current_batch_start = batch_end;
        self.current_batch_index = 0;

        Ok(true)
    }
}

impl<F> Iterator for StreamingDecrypt<F>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    type Item = Result<Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        // If we've consumed all chunks in the current batch, fetch the next batch
        if self.current_batch_index >= self.current_batch_chunks.len() {
            match self.fetch_next_batch() {
                Ok(has_more) => {
                    if !has_more {
                        return None; // No more chunks available
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }

        // Return the next chunk from the current batch
        if self.current_batch_index < self.current_batch_chunks.len() {
            let chunk = self.current_batch_chunks[self.current_batch_index].clone();
            self.current_batch_index += 1;
            Some(Ok(chunk))
        } else {
            None
        }
    }
}

/// Creates a streaming decrypt iterator that yields decrypted chunks as `Bytes`.
///
/// This function provides memory-efficient decryption by processing chunks in batches
/// and yielding them one at a time. It's ideal for large files where loading the entire
/// decrypted content into memory at once would be impractical.
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given chunk hashes
/// * `batch_size` - Optional batch size for chunk processing (defaults to 10)
///
/// # Returns
///
/// * `Result<StreamingDecrypt<F>>` - An iterator that yields `Result<Bytes>` for each decrypted chunk
///
/// # Example
///
/// ```rust
/// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes};
/// use bytes::Bytes;
/// use xor_name::XorName;
/// use std::collections::HashMap;
///
/// # fn main() -> self_encryption::Result<()> {
/// // Create some test data and encrypt it
/// let original_data = random_bytes(10000);
/// let (data_map, encrypted_chunks) = encrypt(original_data)?;
///
/// // Create a simple storage backend
/// let mut storage = HashMap::new();
/// for chunk in encrypted_chunks {
///     let hash = XorName::from_content(&chunk.content);
///     storage.insert(hash, chunk.content.to_vec());
/// }
///
/// // Create chunk retrieval function
/// let get_chunks = |hashes: &[(usize, XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
///     let mut results = Vec::new();
///     for &(index, hash) in hashes {
///         if let Some(data) = storage.get(&hash) {
///             results.push((index, Bytes::from(data.clone())));
///         }
///     }
///     Ok(results)
/// };
///
/// // Create streaming decrypt iterator
/// let stream = streaming_decrypt(&data_map, get_chunks, Some(5))?;
///
/// // Process each decrypted chunk
/// for chunk_result in stream {
///     match chunk_result {
///         Ok(chunk_bytes) => {
///             println!("Decrypted chunk of {} bytes", chunk_bytes.len());
///         }
///         Err(e) => {
///             eprintln!("Error decrypting chunk: {}", e);
///             break;
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn streaming_decrypt<F>(
    data_map: &DataMap,
    get_chunk_parallel: F,
    batch_size: Option<usize>,
) -> Result<StreamingDecrypt<F>>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    StreamingDecrypt::new(data_map, get_chunk_parallel, batch_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt, test_helpers::random_bytes, Error};
    use std::collections::HashMap;

    #[test]
    fn test_streaming_decrypt_basic() -> Result<()> {
        // Create test data
        let original_data = random_bytes(50_000); // Small test file
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        // Create storage map
        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        // Create chunk retrieval function
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Test streaming decryption
        let stream = streaming_decrypt(&data_map, get_chunks, Some(2))?;
        let mut decrypted_data = Vec::new();

        for chunk_result in stream {
            let chunk = chunk_result?;
            decrypted_data.extend_from_slice(&chunk);
        }

        assert_eq!(decrypted_data, original_data.to_vec());
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_large_file() -> Result<()> {
        // Create larger test data
        let original_data = random_bytes(5_000_000); // 5MB test file
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        // Create storage map
        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        // Create chunk retrieval function
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Test streaming decryption with different batch sizes
        let stream = streaming_decrypt(&data_map, get_chunks, Some(3))?;
        let mut decrypted_data = Vec::new();
        let mut chunk_count = 0;

        for chunk_result in stream {
            let chunk = chunk_result?;
            decrypted_data.extend_from_slice(&chunk);
            chunk_count += 1;
        }

        assert_eq!(decrypted_data, original_data.to_vec());
        assert!(chunk_count > 1, "Should have processed multiple chunks");
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_error_handling() -> Result<()> {
        // Create test data
        let original_data = random_bytes(10_000);
        let (data_map, encrypted_chunks) = encrypt(original_data)?;

        // Create incomplete storage (missing some chunks)
        let mut storage = HashMap::new();
        for (i, chunk) in encrypted_chunks.iter().enumerate() {
            if i < encrypted_chunks.len() - 1 {
                // Skip the last chunk to simulate missing data
                let hash = XorName::from_content(&chunk.content);
                let _ = storage.insert(hash, chunk.content.to_vec());
            }
        }

        // Create chunk retrieval function that will fail on missing chunks
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Test that streaming properly handles errors
        let stream = streaming_decrypt(&data_map, get_chunks, Some(2))?;
        let mut found_error = false;

        for chunk_result in stream {
            match chunk_result {
                Ok(_chunk) => {
                    // Continue processing successful chunks
                }
                Err(_e) => {
                    found_error = true;
                    break;
                }
            }
        }

        assert!(
            found_error,
            "Should have encountered an error for missing chunk"
        );
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_matches_streaming_decrypt_from_storage() -> Result<()> {
        use crate::streaming_decrypt_from_storage;
        use std::fs;
        use tempfile::NamedTempFile;

        // Create test data
        let original_data = random_bytes(1_000_000); // 1MB test file
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        // Create storage map
        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        // Create chunk retrieval function for both methods
        let get_chunks_parallel = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(crate::Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Method 1: Use streaming_decrypt to collect all chunks
        let stream = streaming_decrypt(&data_map, &get_chunks_parallel, Some(3))?;
        let mut stream_result = Vec::new();
        for chunk_result in stream {
            let chunk = chunk_result?;
            stream_result.extend_from_slice(&chunk);
        }

        // Method 2: Use streaming_decrypt_from_storage to write to file
        let temp_file = NamedTempFile::new()?;
        streaming_decrypt_from_storage(&data_map, temp_file.path(), get_chunks_parallel)?;

        let file_result = fs::read(temp_file.path())?;

        // Compare the results
        assert_eq!(
            stream_result.len(),
            file_result.len(),
            "Output lengths should match"
        );
        assert_eq!(
            stream_result, file_result,
            "Output content should be identical"
        );
        assert_eq!(
            stream_result,
            original_data.to_vec(),
            "Both methods should match original data"
        );

        Ok(())
    }
}
