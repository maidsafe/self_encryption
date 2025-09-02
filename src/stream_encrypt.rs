// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Streaming encryption functionality for memory-efficient processing of large files.

use crate::{
    encrypt::encrypt_chunk,
    utils::{get_num_chunks, get_pad_key_and_iv, get_start_end_positions},
    ChunkInfo, DataMap, Error, Result,
};
use bytes::Bytes;
use std::collections::BTreeMap;
use xor_name::XorName;

/// A sparse buffer that stores data ranges for random input
#[derive(Debug)]
struct SparseBuffer {
    /// Map from start_position -> data
    ranges: BTreeMap<usize, Vec<u8>>,
    /// Total size of all stored data
    total_size: usize,
}

impl SparseBuffer {
    fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
            total_size: 0,
        }
    }

    /// Add data at a specific position
    fn insert(&mut self, start_pos: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let end_pos = start_pos + data.len();

        // Find all overlapping/adjacent ranges
        let mut overlapping_ranges = Vec::new();
        let mut to_remove = Vec::new();

        for (&existing_start, existing_data) in &self.ranges {
            let existing_end = existing_start + existing_data.len();

            // Check for overlap or adjacency (adjacent means touching)
            if existing_end < start_pos || existing_start > end_pos {
                continue; // No overlap or adjacency
            }

            // This range overlaps or is adjacent
            overlapping_ranges.push((existing_start, existing_end, existing_data.clone()));
            to_remove.push(existing_start);
        }

        // Calculate the bounds of the merged range
        let mut merged_start = start_pos;
        let mut merged_end = end_pos;

        for (existing_start, existing_end, _) in &overlapping_ranges {
            merged_start = merged_start.min(*existing_start);
            merged_end = merged_end.max(*existing_end);
        }

        // Create the merged data buffer
        let mut merged_data = vec![0u8; merged_end - merged_start];

        // Copy all existing data first
        for (existing_start, _existing_end, existing_data) in &overlapping_ranges {
            let offset = existing_start - merged_start;
            merged_data[offset..offset + existing_data.len()].copy_from_slice(existing_data);
        }

        // Copy new data (may overwrite existing data where they overlap)
        let new_offset = start_pos - merged_start;
        merged_data[new_offset..new_offset + data.len()].copy_from_slice(data);

        // Remove old ranges and update total size
        for key in to_remove {
            if let Some(old_data) = self.ranges.remove(&key) {
                self.total_size -= old_data.len();
            }
        }

        // Insert the new merged range
        self.total_size += merged_data.len();
        let _ = self.ranges.insert(merged_start, merged_data);
    }

    /// Get data for a specific range if available
    fn get_range(&self, start: usize, end: usize) -> Option<Vec<u8>> {
        if start >= end {
            return Some(Vec::new());
        }

        // Find the range that contains this data
        for (&range_start, range_data) in &self.ranges {
            let range_end = range_start + range_data.len();

            if range_start <= start && end <= range_end {
                // Range is fully contained
                let offset_start = start - range_start;
                let offset_end = end - range_start;
                return Some(range_data[offset_start..offset_end].to_vec());
            }
        }

        None
    }

    /// Remove data ranges that are no longer needed
    fn remove_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }

        let mut to_update = Vec::new();
        let mut to_remove = Vec::new();

        for (&range_start, range_data) in &self.ranges {
            let range_end = range_start + range_data.len();

            // Check for overlap
            if range_end <= start || range_start >= end {
                continue; // No overlap
            }

            let overlap_start = start.max(range_start);
            let overlap_end = end.min(range_end);

            if overlap_start <= overlap_end {
                // There's an overlap to remove
                to_remove.push(range_start);

                // Keep parts before and after the removed range
                if range_start < overlap_start {
                    let before_data = range_data[0..(overlap_start - range_start)].to_vec();
                    to_update.push((range_start, before_data));
                }

                if overlap_end < range_end {
                    let after_data = range_data[(overlap_end - range_start)..].to_vec();
                    to_update.push((overlap_end, after_data));
                }
            }
        }

        // Apply updates
        for key in to_remove {
            if let Some(old_data) = self.ranges.remove(&key) {
                self.total_size -= old_data.len();
            }
        }

        for (new_start, new_data) in to_update {
            self.total_size += new_data.len();
            let _ = self.ranges.insert(new_start, new_data);
        }
    }

    /// Get total size of all buffered data
    fn total_size(&self) -> usize {
        self.total_size
    }

    /// Check if we have continuous coverage from start to end
    fn has_continuous_coverage(&self, start: usize, end: usize) -> bool {
        if self.ranges.is_empty() {
            return start >= end;
        }

        let mut sorted_ranges: Vec<_> = self.ranges.iter().collect();
        sorted_ranges.sort_by_key(|(&start, _)| start);

        let mut current_pos = start;

        for (&range_start, range_data) in sorted_ranges {
            let range_end = range_start + range_data.len();

            // If there's a gap before this range
            if range_start > current_pos {
                return false;
            }

            // If this range extends our coverage
            if range_end > current_pos {
                current_pos = range_end;
                if current_pos >= end {
                    return true;
                }
            }
        }

        current_pos >= end
    }
}

/// Streaming encrypt that processes data incrementally without disk dependency.
///
/// This struct allows for memory-efficient encryption by processing data in chunks
/// as they are provided, storing encrypted chunks via a user-provided function.
/// Only returns the final DataMap when the entire file has been encrypted.
pub struct StreamingEncrypt<F> {
    /// The total expected file size
    file_size: usize,
    /// The total number of chunks expected
    total_chunks: usize,
    /// Function to store encrypted chunks
    chunk_store: F,
    /// Sparse buffer for accumulated data (handles random input positions)
    buffer: SparseBuffer,
    /// Track which byte ranges have been received (separate from buffer)
    received_ranges: SparseBuffer,
    /// Source hashes of all chunks (filled as we process)
    src_hashes: Vec<Option<XorName>>,
    /// Chunk infos for building the final DataMap (dst_hash filled when encrypted)
    chunk_infos: Vec<Option<ChunkInfo>>,
    /// Track which chunks have been processed for source hash calculation
    chunks_src_processed: Vec<bool>,
    /// Track which chunks have been encrypted and stored
    chunks_encrypted: Vec<bool>,
    /// Raw chunk data for chunks 0 and 1 (needed for deferred encryption)
    deferred_chunks: Vec<Option<Bytes>>,
    /// Whether encryption is complete
    is_complete: bool,
}

impl<F> StreamingEncrypt<F>
where
    F: Fn(XorName, Bytes) -> Result<()>,
{
    /// Creates a new streaming encrypt instance.
    ///
    /// # Arguments
    ///
    /// * `file_size` - The total size of the file to be encrypted
    /// * `chunk_store` - Function that stores encrypted chunks given (hash, content)
    ///
    /// # Returns
    ///
    /// * `Result<StreamingEncrypt<F>>` - A new streaming encrypt instance
    ///
    /// # Examples
    ///
    /// ```rust
    /// use self_encryption::StreamingEncrypt;
    /// use bytes::Bytes;
    /// use xor_name::XorName;
    /// use std::{collections::HashMap, cell::RefCell, rc::Rc};
    ///
    /// # fn main() -> self_encryption::Result<()> {
    /// let storage = Rc::new(RefCell::new(HashMap::new()));
    /// let storage_clone = Rc::clone(&storage);
    /// let store_chunk = move |hash: XorName, content: Bytes| -> self_encryption::Result<()> {
    ///     let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
    ///     Ok(())
    /// };
    ///
    /// let file_size = 10_000;
    /// let _encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_from_memory(file_size: usize, chunk_store: F) -> Result<Self> {
        if file_size < crate::MIN_ENCRYPTABLE_BYTES {
            return Err(Error::Generic(format!(
                "Too small for self-encryption! Required size at least {}",
                crate::MIN_ENCRYPTABLE_BYTES
            )));
        }

        let total_chunks = get_num_chunks(file_size);
        if total_chunks < 3 {
            return Err(Error::Generic(
                "File must be large enough to generate at least 3 chunks".to_string(),
            ));
        }

        Ok(Self {
            file_size,
            total_chunks,
            chunk_store,
            buffer: SparseBuffer::new(),
            received_ranges: SparseBuffer::new(),
            src_hashes: vec![None; total_chunks],
            chunk_infos: vec![None; total_chunks],
            chunks_src_processed: vec![false; total_chunks],
            chunks_encrypted: vec![false; total_chunks],
            deferred_chunks: vec![None; 2.min(total_chunks)],
            is_complete: false,
        })
    }

    /// Encrypts part of the data stream.
    ///
    /// This method processes incoming data, splits it into appropriate chunks according to
    /// the pre-specified total file size, encrypts them, and stores them using the chunk_store
    /// function. Returns `Some(DataMap)` only when the entire file encryption is complete.
    ///
    /// # Arguments
    ///
    /// * `start_pos` - The starting byte position of this data in the overall file
    /// * `content` - The data content to encrypt (must align with expected position)
    ///
    /// # Returns
    ///
    /// * `Result<Option<DataMap>>` - None if more data is needed, Some(DataMap) when complete
    ///
    /// # Examples
    ///
    /// ```rust
    /// use self_encryption::StreamingEncrypt;
    /// use bytes::Bytes;
    /// use xor_name::XorName;
    /// use std::{collections::HashMap, cell::RefCell, rc::Rc};
    ///
    /// # fn main() -> self_encryption::Result<()> {
    /// let storage = Rc::new(RefCell::new(HashMap::new()));
    /// let storage_clone = Rc::clone(&storage);
    /// let store_chunk = move |hash: XorName, content: Bytes| -> self_encryption::Result<()> {
    ///     let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
    ///     Ok(())
    /// };
    ///
    /// let file_size = 10_000;
    /// let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;
    ///
    /// // Process first chunk of data
    /// let data1 = Bytes::from(vec![1u8; 5000]);
    /// let result1 = encryptor.encrypt_part(0, data1)?;
    /// assert!(result1.is_none()); // Not complete yet
    ///
    /// // Process second chunk of data
    /// let data2 = Bytes::from(vec![2u8; 5000]);
    /// let result2 = encryptor.encrypt_part(5000, data2)?;
    /// assert!(result2.is_some()); // Complete! Returns DataMap
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_part(&mut self, start_pos: usize, content: Bytes) -> Result<Option<DataMap>> {
        if self.is_complete {
            return Err(Error::Generic("Encryption already complete".to_string()));
        }

        // Validate position bounds
        if start_pos + content.len() > self.file_size {
            return Err(Error::Generic(format!(
                "Data extends beyond file size: {}+{} > {}",
                start_pos,
                content.len(),
                self.file_size
            )));
        }

        // Track that we've received this range
        self.received_ranges.insert(start_pos, &content);

        // Add content to sparse buffer (handles random positions)
        self.buffer.insert(start_pos, &content);

        // Process complete chunks from buffer
        self.process_available_chunks()?;

        // Check if we have all data and can complete encryption
        if self
            .received_ranges
            .has_continuous_coverage(0, self.file_size)
        {
            return self.finalize_encryption();
        }

        Ok(None)
    }

    /// Process any complete chunks available in the buffer
    /// Encrypts and stores chunks immediately when possible, drains buffer to free memory
    fn process_available_chunks(&mut self) -> Result<()> {
        // Process chunks in order to find complete ones
        for chunk_index in 0..self.total_chunks {
            if self.chunks_src_processed[chunk_index] {
                continue;
            }

            let (chunk_start, chunk_end) = get_start_end_positions(self.file_size, chunk_index);

            // Check if this chunk is completely available in our sparse buffer
            if let Some(chunk_data_vec) = self.buffer.get_range(chunk_start, chunk_end) {
                let chunk_data = Bytes::from(chunk_data_vec);

                // Calculate and store source hash
                let src_hash = XorName::from_content(&chunk_data);
                self.src_hashes[chunk_index] = Some(src_hash);
                self.chunks_src_processed[chunk_index] = true;

                // Create chunk info
                self.chunk_infos[chunk_index] = Some(ChunkInfo {
                    index: chunk_index,
                    dst_hash: XorName::from_content(&[]), // placeholder
                    src_hash,
                    src_size: chunk_end - chunk_start,
                });

                // Handle chunk encryption based on type
                if chunk_index < 2 {
                    // Defer encryption of first two chunks until we have all source hashes
                    if chunk_index < self.deferred_chunks.len() {
                        self.deferred_chunks[chunk_index] = Some(chunk_data);
                    }
                } else {
                    // Can encrypt chunks 2+ immediately if we have enough source hashes
                    if self.can_encrypt_chunk(chunk_index) {
                        self.encrypt_and_store_chunk(chunk_index, chunk_data)?;
                        // Remove this chunk's data from buffer since it's encrypted and stored
                        self.buffer.remove_range(chunk_start, chunk_end);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a chunk can be encrypted (has required source hashes)
    fn can_encrypt_chunk(&self, chunk_index: usize) -> bool {
        if chunk_index < 2 {
            // First two chunks need ALL source hashes
            self.src_hashes.iter().all(|h| h.is_some())
        } else {
            // Chunks 2+ need their own hash and the two preceding chunks' hashes
            let (n1, n2) = crate::utils::get_n_1_n_2(chunk_index, self.total_chunks);
            self.src_hashes[chunk_index].is_some()
                && self.src_hashes[n1].is_some()
                && self.src_hashes[n2].is_some()
        }
    }

    /// Encrypt a chunk and store it immediately
    fn encrypt_and_store_chunk(&mut self, chunk_index: usize, chunk_data: Bytes) -> Result<()> {
        if self.chunks_encrypted[chunk_index] {
            return Ok(()); // Already encrypted
        }

        // Collect only the source hashes that are available (for chunks 2+ this should be sufficient)
        let available_src_hashes: Vec<Option<XorName>> = self.src_hashes.clone();

        // Check if we have the required hashes for this chunk
        let (n1, n2) = crate::utils::get_n_1_n_2(chunk_index, self.total_chunks);

        let _src_hash = available_src_hashes[chunk_index].ok_or_else(|| {
            Error::Generic(format!("Missing source hash for chunk {}", chunk_index))
        })?;
        let _n1_hash = available_src_hashes[n1].ok_or_else(|| {
            Error::Generic(format!(
                "Missing source hash for chunk {} (n1={})",
                chunk_index, n1
            ))
        })?;
        let _n2_hash = available_src_hashes[n2].ok_or_else(|| {
            Error::Generic(format!(
                "Missing source hash for chunk {} (n2={})",
                chunk_index, n2
            ))
        })?;

        // Create the full src_hashes array with placeholders for missing hashes
        let mut src_hashes = vec![XorName::from_content(&[]); self.total_chunks];
        for (i, hash_opt) in available_src_hashes.iter().enumerate() {
            if let Some(hash) = hash_opt {
                src_hashes[i] = *hash;
            }
        }

        // Encrypt the chunk
        let pki = get_pad_key_and_iv(chunk_index, &src_hashes);
        let encrypted_content = encrypt_chunk(chunk_data, pki)?;
        let dst_hash = XorName::from_content(&encrypted_content);

        // Store the encrypted chunk
        (self.chunk_store)(dst_hash, encrypted_content)?;

        // Update chunk info with destination hash
        if let Some(chunk_info) = &mut self.chunk_infos[chunk_index] {
            chunk_info.dst_hash = dst_hash;
        }

        self.chunks_encrypted[chunk_index] = true;
        Ok(())
    }

    /// Finalize encryption when all data has been received
    fn finalize_encryption(&mut self) -> Result<Option<DataMap>> {
        if self.is_complete {
            return Err(Error::Generic("Encryption already complete".to_string()));
        }

        // Process any remaining chunks
        self.process_remaining_chunks()?;

        // Collect all source hashes (should all be available now)
        let src_hashes: Result<Vec<XorName>> = self
            .src_hashes
            .iter()
            .map(|h| h.ok_or_else(|| Error::Generic("Missing source hash".to_string())))
            .collect();
        let src_hashes = src_hashes?;

        // Encrypt any remaining chunks that haven't been encrypted yet
        for chunk_index in 0..self.total_chunks {
            if !self.chunks_encrypted[chunk_index] {
                if chunk_index < 2 && chunk_index < self.deferred_chunks.len() {
                    // Handle deferred chunks (first two chunks)
                    if let Some(chunk_data) = self.deferred_chunks[chunk_index].take() {
                        self.encrypt_and_store_chunk_with_hashes(
                            chunk_index,
                            chunk_data,
                            &src_hashes,
                        )?;
                    }
                } else {
                    // This shouldn't happen if process_available_chunks worked correctly
                    return Err(Error::Generic(format!(
                        "Chunk {} was not encrypted but should have been",
                        chunk_index
                    )));
                }
            }
        }

        // Collect final chunk infos
        let mut final_chunk_infos = Vec::new();
        for chunk_info_opt in &self.chunk_infos {
            if let Some(chunk_info) = chunk_info_opt {
                final_chunk_infos.push(chunk_info.clone());
            } else {
                return Err(Error::Generic(
                    "Missing chunk info for finalization".to_string(),
                ));
            }
        }

        // Sort chunk infos by index
        final_chunk_infos.sort_by_key(|info| info.index);

        let data_map = DataMap::new(final_chunk_infos);

        // Create storage wrapper to bridge mutable/immutable function types
        let storage_wrapper = std::cell::RefCell::new(&mut self.chunk_store);
        let store_fn = |hash: XorName, content: Bytes| -> Result<()> {
            storage_wrapper.borrow_mut()(hash, content)
        };

        let (shrunk_map, _) = crate::shrink_data_map(data_map, store_fn)?;

        self.is_complete = true;

        Ok(Some(shrunk_map))
    }

    /// Encrypt a chunk with provided source hashes and store it
    fn encrypt_and_store_chunk_with_hashes(
        &mut self,
        chunk_index: usize,
        chunk_data: Bytes,
        src_hashes: &[XorName],
    ) -> Result<()> {
        if self.chunks_encrypted[chunk_index] {
            return Ok(()); // Already encrypted
        }

        // Encrypt the chunk
        let pki = get_pad_key_and_iv(chunk_index, src_hashes);
        let encrypted_content = encrypt_chunk(chunk_data, pki)?;
        let dst_hash = XorName::from_content(&encrypted_content);

        // Store the encrypted chunk
        (self.chunk_store)(dst_hash, encrypted_content)?;

        // Update chunk info with destination hash
        if let Some(chunk_info) = &mut self.chunk_infos[chunk_index] {
            chunk_info.dst_hash = dst_hash;
        }

        self.chunks_encrypted[chunk_index] = true;
        Ok(())
    }

    /// Process any remaining chunks from the buffer
    fn process_remaining_chunks(&mut self) -> Result<()> {
        // Process all remaining unprocessed chunks
        for chunk_index in 0..self.total_chunks {
            if !self.chunks_src_processed[chunk_index] {
                let (chunk_start, chunk_end) = get_start_end_positions(self.file_size, chunk_index);

                // Check if this chunk is available in our sparse buffer
                if let Some(chunk_data_vec) = self.buffer.get_range(chunk_start, chunk_end) {
                    let chunk_data = Bytes::from(chunk_data_vec);
                    let src_hash = XorName::from_content(&chunk_data);

                    self.src_hashes[chunk_index] = Some(src_hash);
                    self.chunk_infos[chunk_index] = Some(ChunkInfo {
                        index: chunk_index,
                        dst_hash: XorName::from_content(&[]), // placeholder
                        src_hash,
                        src_size: chunk_end - chunk_start,
                    });
                    self.chunks_src_processed[chunk_index] = true;

                    // Store deferred chunks for later encryption
                    if chunk_index < 2 && chunk_index < self.deferred_chunks.len() {
                        self.deferred_chunks[chunk_index] = Some(chunk_data);
                    }
                }
            }
        }

        // Now that we should have all source hashes, encrypt any remaining chunks
        for chunk_index in 2..self.total_chunks {
            if !self.chunks_encrypted[chunk_index] && self.can_encrypt_chunk(chunk_index) {
                // For chunks 2+, get the data from buffer and encrypt
                if self.chunk_infos[chunk_index].is_some() {
                    let (chunk_start, chunk_end) =
                        get_start_end_positions(self.file_size, chunk_index);
                    if let Some(chunk_data_vec) = self.buffer.get_range(chunk_start, chunk_end) {
                        let chunk_data = Bytes::from(chunk_data_vec);
                        self.encrypt_and_store_chunk(chunk_index, chunk_data)?;
                        // Remove this chunk's data from buffer since it's encrypted and stored
                        self.buffer.remove_range(chunk_start, chunk_end);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the total size of buffered data (for testing/monitoring)
    pub fn buffer_total_size(&self) -> usize {
        self.buffer.total_size()
    }
}

/// Reads a file in chunks, encrypts them, and stores them using a provided functor.
///
/// This function uses `StreamingEncrypt` internally for memory-efficient processing,
/// reading the file sequentially and processing chunks as they become available.
///
/// # Arguments
///
/// * `file_path` - Path to the file to encrypt
/// * `chunk_store` - Function to store encrypted chunks given (hash, content)
///
/// # Returns
///
/// * `Result<DataMap>` - The resulting data map for decryption
///
/// # Examples
///
/// ```rust
/// use self_encryption::{streaming_encrypt_from_file, test_helpers::random_bytes};
/// use tempfile::NamedTempFile;
/// use std::io::Write;
/// use bytes::Bytes;
/// use xor_name::XorName;
/// use std::collections::HashMap;
///
/// # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
/// // Create a temporary file with test data
/// let mut temp_file = NamedTempFile::new()?;
/// let test_data = random_bytes(50_000);
/// temp_file.write_all(&test_data)?;
///
/// let mut storage = HashMap::new();
/// let store = |hash: XorName, content: Bytes| -> self_encryption::Result<()> {
///     storage.insert(hash, content.to_vec());
///     Ok(())
/// };
///
/// let data_map = streaming_encrypt_from_file(temp_file.path(), store)?;
/// assert!(data_map.len() > 0);
/// # Ok(())
/// # }
/// ```
pub fn streaming_encrypt_from_file<F>(
    file_path: &std::path::Path,
    mut chunk_store: F,
) -> Result<crate::DataMap>
where
    F: FnMut(XorName, Bytes) -> Result<()>,
{
    use std::fs::File;
    use std::io::{BufReader, Read};

    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len() as usize;

    // Create storage wrapper to bridge mutable/immutable function types
    let storage_wrapper = std::cell::RefCell::new(&mut chunk_store);
    let store_fn = |hash: XorName, content: Bytes| -> Result<()> {
        storage_wrapper.borrow_mut()(hash, content)
    };

    // Create streaming encryptor
    let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_fn)?;

    // Read and process the file in chunks
    let mut reader = BufReader::with_capacity(crate::MAX_CHUNK_SIZE, file);
    let mut position = 0;
    let mut buffer = vec![0u8; crate::MAX_CHUNK_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let chunk_data = Bytes::from(buffer[..bytes_read].to_vec());
        if let Some(data_map) = encryptor.encrypt_part(position, chunk_data)? {
            return Ok(data_map);
        }

        position += bytes_read;
    }

    // If we reach here, something went wrong - the file should have been fully processed
    Err(Error::Generic(
        "File encryption did not complete".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{streaming_decrypt, test_helpers::random_bytes, Error};
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    #[test]
    fn test_streaming_encrypt_basic() -> Result<()> {
        let file_size = 50_000; // 50KB test file
        let original_data = random_bytes(file_size);

        // Storage for encrypted chunks
        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        // Create streaming encrypt instance
        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Encrypt all data at once
        let data_map = encryptor.encrypt_part(0, original_data.clone())?;
        assert!(data_map.is_some(), "Should have completed encryption");

        let data_map = data_map.unwrap();
        assert!(data_map.len() > 0);

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_incremental() -> Result<()> {
        let file_size = 100_000; // 100KB test file
        let original_data = random_bytes(file_size);

        // Storage for encrypted chunks
        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        // Create streaming encrypt instance
        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Encrypt data in chunks
        let chunk_size = 25_000;
        let mut data_map = None;

        for i in (0..file_size).step_by(chunk_size) {
            let end = std::cmp::min(i + chunk_size, file_size);
            let chunk_data = original_data.slice(i..end);

            let result = encryptor.encrypt_part(i, chunk_data)?;
            if result.is_some() {
                data_map = result;
                break;
            }
        }

        assert!(data_map.is_some(), "Should have completed encryption");
        let data_map = data_map.unwrap();
        assert!(data_map.len() > 0);

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_too_small() -> Result<()> {
        let file_size = 2; // Too small for self-encryption (MIN_ENCRYPTABLE_BYTES = 3)
        let store_chunk = |_hash: XorName, _content: Bytes| -> Result<()> { Ok(()) };

        let result = StreamingEncrypt::new_from_memory(file_size, store_chunk);
        assert!(result.is_err(), "Should reject files that are too small");

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_position_validation() -> Result<()> {
        let file_size = 1000;
        let original_data = random_bytes(file_size);

        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Try to encrypt data at wrong position
        let chunk_data = original_data.slice(0..file_size / 2);
        let result = encryptor.encrypt_part(file_size / 2, chunk_data); // Wrong position!

        if let Ok(None) = result {
        } else {
            panic!("encryption shall be continued");
        }

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_multiple_completion_calls() -> Result<()> {
        let file_size = 50_000;
        let original_data = random_bytes(file_size);

        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Complete encryption
        let _data_map = encryptor.encrypt_part(0, original_data.clone())?;

        // Try to encrypt more data after completion
        let result = encryptor.encrypt_part(0, Bytes::from(vec![1u8; 100]));
        assert!(result.is_err(), "Should reject data after completion");

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_decrypt_roundtrip() -> Result<()> {
        let file_size = 500_000; // 500KB test file to ensure multiple chunks
        let original_data = random_bytes(file_size);

        // Storage for encrypted chunks
        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        // Create streaming encrypt instance
        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Encrypt data incrementally
        let chunk_size = 50_000;
        let mut data_map = None;

        for i in (0..file_size).step_by(chunk_size) {
            let end = std::cmp::min(i + chunk_size, file_size);
            let chunk_data = original_data.slice(i..end);

            let result = encryptor.encrypt_part(i, chunk_data)?;
            if result.is_some() {
                data_map = result;
                break;
            }
        }

        let data_map = data_map.expect("Encryption should complete");

        // Now decrypt using StreamingDecrypt
        let storage_for_get = Rc::clone(&storage);
        let get_chunks = move |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage_for_get.borrow().get(&hash) {
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

        // Test decryption using range_full
        let stream = streaming_decrypt(&data_map, get_chunks.clone())?;
        let decrypted_data = stream.range_full()?;

        // Verify roundtrip
        assert_eq!(
            decrypted_data.len(),
            original_data.len(),
            "Decrypted data should have same length"
        );
        assert_eq!(
            decrypted_data.as_ref(),
            original_data.as_ref(),
            "Decrypted data should match original"
        );

        // Also test random access decryption
        let storage_for_get2 = Rc::clone(&storage);
        let get_chunks2 = move |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage_for_get2.borrow().get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };
        let stream2 = streaming_decrypt(&data_map, get_chunks2)?;

        // Test various ranges
        let range_data = stream2.get_range(10000, 5000)?;
        assert_eq!(range_data.len(), 5000);
        assert_eq!(range_data.as_ref(), &original_data[10000..15000]);

        let full_data = stream2.range_full()?;
        assert_eq!(full_data.as_ref(), &original_data[..]);

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_consistency_with_standard_encrypt() -> Result<()> {
        let file_size = 200_000; // 200KB test file
        let original_data = random_bytes(file_size);

        // Standard encryption
        let (standard_data_map, standard_chunks) = crate::encrypt(original_data.clone())?;

        // Streaming encryption
        let streaming_storage = Rc::new(RefCell::new(HashMap::new()));
        let streaming_storage_clone = Rc::clone(&streaming_storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = streaming_storage_clone
                .borrow_mut()
                .insert(hash, content.to_vec());
            Ok(())
        };

        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;
        let streaming_data_map = encryptor
            .encrypt_part(0, original_data.clone())?
            .expect("Should complete");

        // Both should produce the same number of chunks
        assert_eq!(
            standard_data_map.len(),
            streaming_data_map.len(),
            "Should produce same number of chunks"
        );

        // Create storage for standard chunks
        let mut standard_storage = HashMap::new();
        for chunk in standard_chunks {
            let hash = XorName::from_content(&chunk.content);
            let _ = standard_storage.insert(hash, chunk.content.to_vec());
        }

        // Create retrieval functions
        let get_standard_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = standard_storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let streaming_storage_for_get = Rc::clone(&streaming_storage);
        let get_streaming_chunks =
            move |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
                let mut results = Vec::new();
                for &(index, hash) in hashes {
                    if let Some(data) = streaming_storage_for_get.borrow().get(&hash) {
                        results.push((index, Bytes::from(data.clone())));
                    }
                }
                Ok(results)
            };

        // Decrypt both and verify they produce the same result
        let standard_stream = streaming_decrypt(&standard_data_map, get_standard_chunks)?;
        let standard_decrypted = standard_stream.range_full()?;

        let streaming_stream = streaming_decrypt(&streaming_data_map, get_streaming_chunks)?;
        let streaming_decrypted = streaming_stream.range_full()?;

        assert_eq!(standard_decrypted.as_ref(), original_data.as_ref());
        assert_eq!(streaming_decrypted.as_ref(), original_data.as_ref());
        assert_eq!(standard_decrypted.as_ref(), streaming_decrypted.as_ref());

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_memory_efficiency() -> Result<()> {
        // Test that buffer doesn't grow unbounded with large file processing
        let file_size = 10_000_000; // 10MB file
        let original_data = random_bytes(file_size);

        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Process data in small chunks to test buffer management
        let chunk_size = 100_000; // 100KB chunks
        let mut max_buffer_size = 0;
        let mut data_map = None;

        for i in (0..file_size).step_by(chunk_size) {
            let end = std::cmp::min(i + chunk_size, file_size);
            let chunk_data = original_data.slice(i..end);

            let result = encryptor.encrypt_part(i, chunk_data)?;

            // Track maximum buffer size (should remain bounded)
            max_buffer_size = max_buffer_size.max(encryptor.buffer_total_size());

            if result.is_some() {
                data_map = result;
                break;
            }
        }

        let data_map = data_map.expect("Encryption should complete");

        // Buffer should not grow to the full file size - it should be much smaller
        // due to draining processed chunks
        assert!(
            max_buffer_size < file_size / 2,
            "Buffer grew too large: {} bytes (should be much less than file size {})",
            max_buffer_size,
            file_size
        );

        // Verify the encryption worked correctly by testing decryption
        let storage_for_get = Rc::clone(&storage);
        let get_chunks = move |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage_for_get.borrow().get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;
        let decrypted_full = stream.range_full()?;

        assert_eq!(decrypted_full.len(), original_data.len());
        assert_eq!(decrypted_full.as_ref(), original_data.as_ref());

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_random_input_order() -> Result<()> {
        // Test that data can be provided in any order and buffer management works correctly
        let file_size = 5_000_000; // 5MB file
        let original_data = random_bytes(file_size);

        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);
        let store_chunk = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        let mut encryptor = StreamingEncrypt::new_from_memory(file_size, store_chunk)?;

        // Define random input chunks (out of order)
        let input_chunks = vec![
            (2_000_000, 1_000_000), // Middle chunk first
            (0, 500_000),           // Beginning chunk
            (4_000_000, 1_000_000), // Near end chunk
            (500_000, 1_500_000),   // Fill gap from beginning
            (3_000_000, 1_000_000), // Fill another gap
        ];

        let mut max_buffer_size = 0;
        let mut data_map = None;

        // Process chunks in random order
        for (start, len) in input_chunks {
            let end = std::cmp::min(start + len, file_size);
            let chunk_data = original_data.slice(start..end);

            let result = encryptor.encrypt_part(start, chunk_data)?;

            // Track buffer size - should stay bounded even with random input
            max_buffer_size = max_buffer_size.max(encryptor.buffer_total_size());

            if result.is_some() {
                data_map = result;
                break;
            }
        }

        let data_map = data_map.expect("Encryption should complete");

        // Buffer should contain only unencrypted portions, not the entire file
        // With random input, buffer may temporarily hold more data until chunks can be processed
        // The key is that it eventually drains down as chunks are encrypted
        assert!(
            max_buffer_size < file_size,
            "Buffer grew too large: {} bytes (should be less than file size {})",
            max_buffer_size,
            file_size
        );

        // Verify final buffer is much smaller (encrypted chunks were drained)
        let final_buffer_size = encryptor.buffer_total_size();
        assert!(
            final_buffer_size < file_size / 2,
            "Final buffer too large: {} bytes (should be less than {})",
            final_buffer_size,
            file_size / 2
        );

        // Verify the encryption worked correctly
        let storage_for_get = Rc::clone(&storage);
        let get_chunks = move |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage_for_get.borrow().get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;
        let decrypted_full = stream.range_full()?;

        assert_eq!(decrypted_full.len(), original_data.len());
        assert_eq!(decrypted_full.as_ref(), original_data.as_ref());

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_from_file() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create test data - 4MB file
        let file_size = 4 * 1024 * 1024;
        let test_data = random_bytes(file_size);

        // Write test data to temporary file
        let mut temp_file = NamedTempFile::new().map_err(|e| Error::Generic(e.to_string()))?;
        temp_file
            .write_all(&test_data)
            .map_err(|e| Error::Generic(e.to_string()))?;
        temp_file
            .flush()
            .map_err(|e| Error::Generic(e.to_string()))?;

        // Create storage for encrypted chunks
        let storage = Rc::new(RefCell::new(HashMap::new()));
        let storage_clone = Rc::clone(&storage);

        // Store function
        let store = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.borrow_mut().insert(hash, content.to_vec());
            Ok(())
        };

        // Encrypt file using streaming_encrypt_from_file
        let data_map = streaming_encrypt_from_file(temp_file.path(), store)?;

        // Verify the data map
        assert!(data_map.len() > 0);
        assert!(data_map.len() <= 3); // Should be shrunk

        // Test decryption to verify correctness
        let storage_for_get = Rc::clone(&storage);
        let get_chunks = move |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage_for_get.borrow().get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = crate::streaming_decrypt(&data_map, get_chunks)?;
        let decrypted_data = stream.range_full()?;

        assert_eq!(decrypted_data.len(), test_data.len());
        assert_eq!(decrypted_data.as_ref(), test_data.as_ref());

        Ok(())
    }
}
