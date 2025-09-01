// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Streaming decryption functionality for memory-efficient processing of large encrypted files.

use crate::{
    decrypt::decrypt_chunk, get_root_data_map_parallel, utils::extract_hashes, utils::get_chunk_index, ChunkInfo, DataMap,
    Result,
};
use bytes::Bytes;
use std::ops::Range;
use xor_name::XorName;

/// Iterator that yields decrypted chunks as `Bytes` in streaming fashion.
///
/// This provides memory-efficient decryption by processing chunks in batches
/// and yielding them one at a time without buffering the entire file.
/// 
/// In addition to sequential streaming, this struct also supports random access
/// to any byte range within the encrypted file using methods like `get_range()`,
/// `range()`, and other convenience methods.
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

    /// Returns the original file size for random access operations.
    pub fn file_size(&self) -> usize {
        self.chunk_infos.iter().fold(0, |acc, chunk| acc + chunk.src_size)
    }

    /// Decrypts and returns a specific byte range from the encrypted data.
    ///
    /// This method provides random access to any portion of the encrypted file
    /// without requiring sequential iteration through all preceding chunks.
    ///
    /// # Arguments
    ///
    /// * `start` - The starting byte position (inclusive)
    /// * `len` - The number of bytes to read
    ///
    /// # Returns
    ///
    /// * `Result<Bytes>` - The decrypted range of data or an error if chunks are missing/corrupted
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
    /// // Create streaming decrypt instance
    /// let stream = streaming_decrypt(&data_map, get_chunks, Some(5))?;
    ///
    /// // Random access: get bytes 1000-2000
    /// let range_data = stream.get_range(1000, 1000)?;
    /// println!("Got {} bytes from range 1000-2000", range_data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_range(&self, start: usize, len: usize) -> Result<Bytes> {
        let file_size = self.file_size();
        
        // Validate range
        if start >= file_size {
            return Ok(Bytes::new());
        }
        
        let end_pos = std::cmp::min(start + len, file_size);
        let actual_len = end_pos - start;
        
        if actual_len == 0 {
            return Ok(Bytes::new());
        }

        // Calculate which chunks we need
        let start_chunk = get_chunk_index(file_size, start);
        let end_chunk = get_chunk_index(file_size, end_pos.saturating_sub(1));

        // Collect the chunk hashes we need
        let mut required_hashes = Vec::new();
        for chunk_info in &self.chunk_infos {
            if chunk_info.index >= start_chunk && chunk_info.index <= end_chunk {
                required_hashes.push((chunk_info.index, chunk_info.dst_hash));
            }
        }

        // Sort by index to ensure correct order
        required_hashes.sort_by_key(|(index, _)| *index);

        // Fetch the required chunks
        let fetched_chunks = (self.get_chunk_parallel)(&required_hashes)?;
        
        // Create a mapping for quick lookup
        let chunk_map: std::collections::HashMap<usize, Bytes> = fetched_chunks
            .into_iter()
            .collect();

        // Decrypt the chunks in order and collect the bytes
        let mut all_bytes = Vec::new();
        for chunk_index in start_chunk..=end_chunk {
            if let Some(encrypted_content) = chunk_map.get(&chunk_index) {
                let decrypted = decrypt_chunk(chunk_index, encrypted_content, &self.src_hashes)?;
                all_bytes.extend_from_slice(&decrypted);
            }
        }

        let bytes = Bytes::from(all_bytes);

        // Calculate the offset within our decrypted data
        let start_chunk_pos = self.get_chunk_start_position(start_chunk);
        let internal_offset = start - start_chunk_pos;

        if internal_offset >= bytes.len() {
            return Ok(Bytes::new());
        }

        // Extract just the range we need
        let available_len = bytes.len() - internal_offset;
        let range_len = std::cmp::min(actual_len, available_len);
        let result = bytes.slice(internal_offset..internal_offset + range_len);

        Ok(result)
    }

    /// Helper method to get the starting byte position of a chunk within the file
    fn get_chunk_start_position(&self, chunk_index: usize) -> usize {
        self.chunk_infos
            .iter()
            .filter(|info| info.index < chunk_index)
            .fold(0, |acc, chunk| acc + chunk.src_size)
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

impl<F> StreamingDecrypt<F>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    /// Convenience method to get a range using Range syntax.
    /// 
    /// # Example
    /// ```rust
    /// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes};
    /// use bytes::Bytes;
    /// use xor_name::XorName;
    /// use std::collections::HashMap;
    /// 
    /// # fn main() -> self_encryption::Result<()> {
    /// let original_data = random_bytes(10000);
    /// let (data_map, encrypted_chunks) = encrypt(original_data)?;
    /// let mut storage = HashMap::new();
    /// for chunk in encrypted_chunks {
    ///     let hash = XorName::from_content(&chunk.content);
    ///     storage.insert(hash, chunk.content.to_vec());
    /// }
    /// let get_chunks = |hashes: &[(usize, XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
    ///     let mut results = Vec::new();
    ///     for &(index, hash) in hashes {
    ///         if let Some(data) = storage.get(&hash) {
    ///             results.push((index, Bytes::from(data.clone())));
    ///         }
    ///     }
    ///     Ok(results)
    /// };
    /// let stream = streaming_decrypt(&data_map, get_chunks, Some(5))?;
    /// let _chunk_bytes = stream.range(1000..2000)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn range(&self, range: Range<usize>) -> Result<Bytes> {
        let len = range.end.saturating_sub(range.start);
        self.get_range(range.start, len)
    }

    /// Convenience method to get a range from a starting position to the end of the file.
    pub fn range_from(&self, start: usize) -> Result<Bytes> {
        let file_size = self.file_size();
        let len = file_size.saturating_sub(start);
        self.get_range(start, len)
    }

    /// Convenience method to get a range from the beginning of the file to an end position.
    pub fn range_to(&self, end: usize) -> Result<Bytes> {
        self.get_range(0, end)
    }

    /// Convenience method to get the entire file content.
    pub fn range_full(&self) -> Result<Bytes> {
        let file_size = self.file_size();
        self.get_range(0, file_size)
    }

    /// Convenience method to get an inclusive range.
    pub fn range_inclusive(&self, start: usize, end: usize) -> Result<Bytes> {
        let len = end.saturating_sub(start) + 1; // +1 because inclusive
        self.get_range(start, len)
    }
}

/// Creates a streaming decrypt iterator that yields decrypted chunks as `Bytes`.
///
/// This function provides memory-efficient decryption by processing chunks in batches
/// and yielding them one at a time. It's ideal for large files where loading the entire
/// decrypted content into memory at once would be impractical.
/// 
/// The returned `StreamingDecrypt` struct supports both sequential iteration and random
/// access to any byte range within the encrypted file.
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
/// # Examples
///
/// ## Sequential Processing
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
/// // Process each decrypted chunk sequentially
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
/// 
/// ## Random Access
/// 
/// ```rust
/// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes};
/// use bytes::Bytes;
/// use xor_name::XorName;
/// use std::collections::HashMap;
///
/// # fn main() -> self_encryption::Result<()> {
/// let original_data = random_bytes(10000);
/// let (data_map, encrypted_chunks) = encrypt(original_data)?;
///
/// let mut storage = HashMap::new();
/// for chunk in encrypted_chunks {
///     let hash = XorName::from_content(&chunk.content);
///     storage.insert(hash, chunk.content.to_vec());
/// }
///
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
/// let stream = streaming_decrypt(&data_map, get_chunks, Some(5))?;
///
/// // Random access examples
/// let chunk_bytes = stream.range(1000..2000)?;
/// println!("Decrypted range 1000-2000: {} bytes", chunk_bytes.len());
///
/// let from_middle = stream.range_from(5000)?;
/// println!("From byte 5000 to end: {} bytes", from_middle.len());
///
/// let first_kilobyte = stream.range_to(1024)?;
/// println!("First 1024 bytes: {} bytes", first_kilobyte.len());
///
/// // Direct range access with get_range
/// let specific_range = stream.get_range(2000, 500)?;
/// println!("500 bytes starting at position 2000: {} bytes", specific_range.len());
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

    #[test]
    fn test_random_access_basic() -> Result<()> {
        // Create test data
        let original_data = random_bytes(10_000); 
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

        let stream = streaming_decrypt(&data_map, get_chunks, Some(2))?;

        // Test basic range access
        let range_start = 1000;
        let range_len = 500;
        let range_data = stream.get_range(range_start, range_len)?;

        // Verify against original data
        assert_eq!(range_data.len(), range_len);
        assert_eq!(
            range_data.as_ref(),
            &original_data[range_start..range_start + range_len]
        );

        Ok(())
    }

    #[test]
    fn test_random_access_convenience_methods() -> Result<()> {
        let original_data = random_bytes(5_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks, Some(3))?;

        // Test range method
        let range_data = stream.range(1000..2000)?;
        assert_eq!(range_data.as_ref(), &original_data[1000..2000]);

        // Test range_from method  
        let from_data = stream.range_from(3000)?;
        assert_eq!(from_data.as_ref(), &original_data[3000..]);

        // Test range_to method
        let to_data = stream.range_to(1500)?;
        assert_eq!(to_data.as_ref(), &original_data[..1500]);

        // Test range_full method
        let full_data = stream.range_full()?;
        assert_eq!(full_data.as_ref(), &original_data[..]);

        // Test range_inclusive method
        let inclusive_data = stream.range_inclusive(500, 999)?;
        assert_eq!(inclusive_data.as_ref(), &original_data[500..1000]); // 500 to 999 inclusive = 500..1000

        Ok(())
    }

    #[test]
    fn test_random_access_edge_cases() -> Result<()> {
        let original_data = random_bytes(1_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks, Some(2))?;

        // Test range beyond file size
        let beyond_range = stream.get_range(2000, 500)?;
        assert_eq!(beyond_range.len(), 0);

        // Test range starting at file size
        let at_end = stream.get_range(1000, 100)?;
        assert_eq!(at_end.len(), 0);

        // Test range that partially exceeds file size
        let partial_exceed = stream.get_range(950, 100)?;
        assert_eq!(partial_exceed.len(), 50); // Only 50 bytes available from position 950
        assert_eq!(partial_exceed.as_ref(), &original_data[950..]);

        // Test zero-length range
        let zero_len = stream.get_range(500, 0)?;
        assert_eq!(zero_len.len(), 0);

        // Test range at start of file
        let at_start = stream.get_range(0, 100)?;
        assert_eq!(at_start.as_ref(), &original_data[0..100]);

        Ok(())
    }

    #[test]
    fn test_random_access_chunk_boundaries() -> Result<()> {
        // Create data large enough to span multiple chunks
        let original_data = random_bytes(5_000_000); // 5MB to ensure multiple chunks
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks, Some(3))?;

        // Test ranges that cross chunk boundaries
        let cross_boundary = stream.get_range(1_000_000, 2_000_000)?; // Should span multiple chunks
        assert_eq!(cross_boundary.len(), 2_000_000);
        assert_eq!(
            cross_boundary.as_ref(),
            &original_data[1_000_000..3_000_000]
        );

        // Test small ranges within single chunks
        let within_chunk = stream.get_range(500_000, 1000)?;
        assert_eq!(within_chunk.len(), 1000);
        assert_eq!(within_chunk.as_ref(), &original_data[500_000..501_000]);

        Ok(())
    }

    #[test]
    fn test_random_access_file_size() -> Result<()> {
        let original_data = random_bytes(1234); // Odd size
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks, Some(2))?;

        // Test file_size method
        assert_eq!(stream.file_size(), 1234);

        // Test getting exactly the full file
        let full_file = stream.get_range(0, 1234)?;
        assert_eq!(full_file.len(), 1234);
        assert_eq!(full_file.as_ref(), &original_data[..]);

        Ok(())
    }

    #[test]
    fn test_random_access_vs_sequential() -> Result<()> {
        // Test that random access produces the same results as sequential reading
        let original_data = random_bytes(100_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        // Get data via random access
        let stream = streaming_decrypt(&data_map, &get_chunks, Some(2))?;
        let random_access_data = stream.range_full()?;

        // Get data via sequential iteration
        let stream2 = streaming_decrypt(&data_map, get_chunks, Some(2))?;
        let mut sequential_data = Vec::new();
        for chunk_result in stream2 {
            sequential_data.extend_from_slice(&chunk_result?);
        }

        // Both should match the original
        assert_eq!(random_access_data.as_ref(), &original_data[..]);
        assert_eq!(sequential_data, original_data.to_vec());
        assert_eq!(random_access_data.as_ref(), &sequential_data[..]);

        Ok(())
    }
}
