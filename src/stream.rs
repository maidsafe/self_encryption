use crate::{
    decrypt::decrypt_chunk,
    encrypt::encrypt_chunk,
    error::{Error, Result},
    utils::{extract_hashes, get_pki},
    DataMap, EncryptedChunk,
};
use bytes::Bytes;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Error as IoError, ErrorKind},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
use tempfile::{tempdir, TempDir};
use xor_name::XorName;

/// The streaming encryptor to carry out the encryption on fly, chunk by chunk.
#[derive(Clone)]
pub struct StreamSelfEncryptor {
    // File path for the encryption target.
    file_path: PathBuf,
    // List of `(start_position, end_position)` for each chunk for the target file.
    batch_positions: Vec<(usize, usize)>,
    // Current step (i.e. chunk_index) for encryption
    chunk_index: usize,
    // Progressing DataMap
    data_map: Vec<crate::ChunkInfo>,
    // Progressing collection of source chunks' names
    src_hashes: BTreeMap<usize, XorName>,
    // File path to flush encrypted_chunks into.
    chunk_dir: Option<PathBuf>,
}

impl StreamSelfEncryptor {
    /// For encryption, return with an initialized streaming encryptor.
    /// If a `chunk_dir` is provided, the encrypted_chunks will be written into the specified dir as well.
    pub fn encrypt_from_file(file_path: PathBuf, chunk_dir: Option<PathBuf>) -> Result<Self> {
        // First check if file exists
        if !file_path.exists() {
            return Err(Error::Generic("Input file does not exist".to_string()));
        }

        let file = File::open(&file_path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;

        // Strict size validation
        if file_size < crate::MIN_ENCRYPTABLE_BYTES {
            return Err(Error::Generic(format!(
                "File too small for self-encryption! Size: {}, Required minimum: {}",
                file_size,
                crate::MIN_ENCRYPTABLE_BYTES
            )));
        }

        // Create chunk directory if specified
        if let Some(ref dir) = chunk_dir {
            std::fs::create_dir_all(dir)?;
        }

        let batch_positions = crate::chunk::batch_positions(file_size);

        Ok(StreamSelfEncryptor {
            file_path,
            batch_positions,
            chunk_index: 0,
            data_map: Vec::new(),
            src_hashes: BTreeMap::new(),
            chunk_dir,
        })
    }

    /// Return the next encrypted chunk, if already reached the end, return with the data_map.
    /// Note: only of the two returned options will be `Some`.
    pub fn next_encryption(&mut self) -> Result<(Option<EncryptedChunk>, Option<DataMap>)> {
        if self.chunk_index >= self.batch_positions.len() {
            return Ok((None, Some(DataMap::new(self.data_map.clone()))));
        }

        let (src_hash, content) = self.read_chunk(self.chunk_index)?;

        let pki = self.get_pad_key_and_iv(src_hash)?;
        let encrypted_content = encrypt_chunk(content, pki)?;
        let dst_hash = XorName::from_content(encrypted_content.as_ref());

        let index = self.chunk_index;
        self.chunk_index += 1;

        let (start_pos, end_pos) = self.batch_positions[index];
        self.data_map.push(crate::ChunkInfo {
            index,
            dst_hash,
            src_hash,
            src_size: end_pos - start_pos,
        });

        let encrypted_chunk = EncryptedChunk {
            content: encrypted_content,
        };

        if let Some(chunk_dir) = self.chunk_dir.clone() {
            let file_path = chunk_dir.join(hex::encode(dst_hash));
            let result = File::create(file_path);
            let mut output_file = result?;
            output_file.write_all(&encrypted_chunk.content)?;
        }

        Ok((Some(encrypted_chunk), None))
    }

    fn read_chunk(&mut self, chunk_index: usize) -> Result<(XorName, Bytes)> {
        let (start_pos, end_pos) = self.batch_positions[chunk_index];
        let mut buffer = vec![0; end_pos - start_pos];

        // Open file for each chunk read to avoid keeping file handle open
        let mut file = File::open(&self.file_path)?;
        let _ = file.seek(SeekFrom::Start(start_pos as u64))?;
        file.read_exact(&mut buffer)?;

        let content = Bytes::from(buffer);
        let src_hash = XorName::from_content(content.as_ref());

        let _ = self.src_hashes.insert(chunk_index, src_hash);

        Ok((src_hash, content))
    }

    fn get_pad_key_and_iv(
        &mut self,
        src_hash: XorName,
    ) -> Result<(crate::aes::Pad, crate::aes::Key, crate::aes::Iv)> {
        let (n_1, n_2) = crate::utils::get_n_1_n_2(self.chunk_index, self.batch_positions.len());

        let n_1_src_hash = self.get_src_chunk_name(n_1)?;
        let n_2_src_hash = self.get_src_chunk_name(n_2)?;

        Ok(get_pki(&src_hash, &n_1_src_hash, &n_2_src_hash))
    }

    fn get_src_chunk_name(&mut self, index: usize) -> Result<XorName> {
        if let Some(name) = self.src_hashes.get(&index) {
            Ok(*name)
        } else {
            let (src_hash, _content) = self.read_chunk(index)?;
            Ok(src_hash)
        }
    }
}

/// The streaming decryptor to carry out the decryption on fly, chunk by chunk.
pub struct StreamSelfDecryptor {
    // File path for the decryption output.
    file_path: PathBuf,
    // Current step (i.e. chunk_index) for decryption
    chunk_index: usize,
    // Source hashes of the chunks that collected from the data_map, they shall already be sorted by index.
    src_hashes: Vec<XorName>,
    // Progressing collection of received encrypted chunks, maps chunk hash to content
    encrypted_chunks: BTreeMap<XorName, Bytes>,
    // Map of chunk indices to their expected hashes from the data map
    chunk_hash_map: BTreeMap<usize, XorName>,
    // Temp directory to hold the un-processed encrypted_chunks
    temp_dir: TempDir,
    // Add a flag to track if all chunks are processed
    all_chunks_processed: bool,
}

impl StreamSelfDecryptor {
    /// For decryption, return with an initialized streaming decryptor
    pub fn decrypt_to_file(file_path: PathBuf, data_map: &DataMap) -> Result<Self> {
        // Create a new temporary directory for processing
        let temp_dir = tempdir()?;

        // Create parent directory for output file
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create temp processing directory
        let temp_processing_dir = temp_dir.path().join("processing");
        std::fs::create_dir_all(&temp_processing_dir)?;

        let src_hashes = extract_hashes(data_map);
        let chunk_hash_map = data_map
            .infos()
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .collect();

        // Remove output file if it exists
        let _ = std::fs::remove_file(&file_path);

        Ok(StreamSelfDecryptor {
            file_path,
            chunk_index: 0,
            src_hashes,
            encrypted_chunks: BTreeMap::new(),
            chunk_hash_map,
            temp_dir,
            all_chunks_processed: false,
        })
    }

    /// Return true if all encrypted chunks have been received and the file is decrypted.
    pub fn next_encrypted(&mut self, encrypted_chunk: EncryptedChunk) -> Result<bool> {
        let chunk_hash = XorName::from_content(&encrypted_chunk.content);

        // Find the index for this chunk based on its hash
        let chunk_index = self
            .chunk_hash_map
            .iter()
            .find(|(_, &hash)| hash == chunk_hash)
            .map(|(&idx, _)| idx);

        if let Some(idx) = chunk_index {
            if idx == self.chunk_index {
                // Process this chunk immediately
                let decrypted_content =
                    decrypt_chunk(idx, &encrypted_chunk.content, &self.src_hashes)?;
                self.append_to_file(&decrypted_content)?;
                self.chunk_index += 1;
                self.drain_unprocessed()?;

                if self.chunk_index == self.src_hashes.len() {
                    self.all_chunks_processed = true;
                    self.finalize_decryption()?;
                    return Ok(true);
                }
            } else {
                // Store for later processing
                let file_path = self.temp_dir.path().join(hex::encode(chunk_hash));
                let mut output_file = File::create(&file_path).map_err(|e| {
                    Error::Io(IoError::new(
                        ErrorKind::Other,
                        format!("Failed to create file {:?}: {}", file_path.display(), e),
                    ))
                })?;
                output_file.write_all(&encrypted_chunk.content)?;
                let _ = self
                    .encrypted_chunks
                    .insert(chunk_hash, encrypted_chunk.content);
            }
        }

        Ok(false)
    }

    // If the file does not exist, it will be created. The function then writes the content to the file.
    // If the file already exists, the content will be appended to the end of the file.
    fn append_to_file(&self, content: &Bytes) -> std::io::Result<()> {
        let partial_output_path = self.temp_dir.path().join("partial_output");

        // Ensure parent directory exists
        if let Some(parent) = partial_output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&partial_output_path)?;

        file.write_all(content)?;
        file.sync_all()?; // Ensure data is written to disk

        Ok(())
    }

    // The encrypted chunks may come in out-of-order.
    // Drain any in-order chunks due to the recently filled-in piece.
    fn drain_unprocessed(&mut self) -> Result<()> {
        while let Some(&next_hash) = self.chunk_hash_map.get(&self.chunk_index) {
            if let Some(content) = self.encrypted_chunks.remove(&next_hash) {
                let decrypted_content =
                    decrypt_chunk(self.chunk_index, &content, &self.src_hashes)?;
                self.append_to_file(&decrypted_content)?;
                self.chunk_index += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Finalizes the decryption process by moving the partial output to the final output file.
    fn finalize_decryption(&self) -> Result<()> {
        let partial_output_path = self.temp_dir.path().join("partial_output");
        if partial_output_path.exists() {
            // Ensure the parent directory of the final output path exists
            if let Some(parent) = self.file_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Io(IoError::new(
                        ErrorKind::Other,
                        format!("Failed to create output directory: {}", e),
                    ))
                })?;
            }

            // Move the partial output to the final output path
            std::fs::rename(&partial_output_path, &self.file_path).map_err(|e| {
                Error::Io(IoError::new(
                    ErrorKind::Other,
                    format!("Failed to move decrypted file: {}", e),
                ))
            })?;
        } else {
            return Err(Error::Io(IoError::new(
                ErrorKind::NotFound,
                "Partial output file does not exist",
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::random_bytes;
    use std::fs;

    struct TestEnvironment {
        _temp_dir: TempDir, // Keep TempDir alive by storing it in the struct
        input_path: PathBuf,
        output_path: PathBuf,
        chunk_dir: PathBuf,
    }

    impl TestEnvironment {
        fn new() -> Result<Self> {
            let _temp_dir = TempDir::new()?;
            let base_path = _temp_dir.path().to_path_buf();

            // Create all necessary directories
            let input_dir = base_path.join("input");
            let output_dir = base_path.join("output");
            let chunk_dir = base_path.join("chunks");

            // Create all directories
            std::fs::create_dir_all(&input_dir)?;
            std::fs::create_dir_all(&output_dir)?;
            std::fs::create_dir_all(&chunk_dir)?;

            let input_path = input_dir.join("input_file");
            let output_path = output_dir.join("output_file");

            Ok(TestEnvironment {
                _temp_dir,
                input_path,
                output_path,
                chunk_dir,
            })
        }

        // Add helper method to ensure directories exist
        fn ensure_dirs(&self) -> Result<()> {
            if let Some(parent) = self.input_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if let Some(parent) = self.output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir_all(&self.chunk_dir)?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_stream_self_encryptor() -> Result<()> {
        let env = TestEnvironment::new()?;
        env.ensure_dirs()?;

        let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
        fs::write(&env.input_path, &test_data)?;

        let mut encryptor =
            StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir.clone()))?;

        let mut encrypted_chunks = Vec::new();
        let data_map = loop {
            let (chunk_opt, map_opt) = encryptor.next_encryption()?;
            if let Some(chunk) = chunk_opt {
                encrypted_chunks.push(chunk);
            }
            if let Some(map) = map_opt {
                break map;
            }
        };

        // Now decrypt the data
        let mut decryptor =
            StreamSelfDecryptor::decrypt_to_file(env.output_path.clone(), &data_map)?;

        // Feed chunks in order
        for chunk in encrypted_chunks {
            let done = decryptor.next_encrypted(chunk)?;
            if done {
                break;
            }
        }

        // Verify the decrypted content matches original
        let decrypted_content = fs::read(env.output_path)?;
        assert_eq!(test_data.to_vec(), decrypted_content);

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_self_decryptor_basic() -> Result<()> {
        let env = TestEnvironment::new()?;
        env.ensure_dirs()?;

        let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
        fs::write(&env.input_path, &test_data)?;

        let mut encryptor =
            StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir.clone()))?;

        let mut encrypted_chunks = Vec::new();
        let data_map = loop {
            let (chunk_opt, map_opt) = encryptor.next_encryption()?;
            if let Some(chunk) = chunk_opt {
                encrypted_chunks.push(chunk);
            }
            if let Some(map) = map_opt {
                break map;
            }
        };

        // Now decrypt the data
        let mut decryptor =
            StreamSelfDecryptor::decrypt_to_file(env.output_path.clone(), &data_map)?;

        // Feed chunks in order
        for chunk in encrypted_chunks {
            let done = decryptor.next_encrypted(chunk)?;
            if done {
                break;
            }
        }

        // Verify the decrypted content matches original
        let decrypted_content = fs::read(env.output_path)?;
        assert_eq!(test_data.to_vec(), decrypted_content);

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_self_decryptor_out_of_order() -> Result<()> {
        let env = TestEnvironment::new()?;
        env.ensure_dirs()?;

        let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
        fs::write(&env.input_path, &test_data)?;

        let mut encryptor =
            StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir.clone()))?;

        let mut encrypted_chunks = Vec::new();
        let data_map = loop {
            let (chunk_opt, map_opt) = encryptor.next_encryption()?;
            if let Some(chunk) = chunk_opt {
                encrypted_chunks.push(chunk);
            }
            if let Some(map) = map_opt {
                break map;
            }
        };

        // Now decrypt the data, but feed chunks in reverse order
        let mut decryptor =
            StreamSelfDecryptor::decrypt_to_file(env.output_path.clone(), &data_map)?;

        for chunk in encrypted_chunks.into_iter().rev() {
            let done = decryptor.next_encrypted(chunk)?;
            if done {
                break;
            }
        }

        // Verify the decrypted content matches original
        let decrypted_content = fs::read(env.output_path)?;
        assert_eq!(test_data.to_vec(), decrypted_content);

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_self_encryptor_empty_file() -> Result<()> {
        let env = TestEnvironment::new()?;

        // Create empty file
        fs::write(&env.input_path, b"")?;

        // Attempt to encrypt empty file
        let result = StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir));

        // Should fail because file is too small
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_self_encryptor_small_file() -> Result<()> {
        let env = TestEnvironment::new()?;

        // Create file smaller than minimum size
        let small_data = random_bytes(crate::MIN_ENCRYPTABLE_BYTES - 1);
        fs::write(&env.input_path, &small_data)?;

        let result = StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir));

        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_self_decryptor_invalid_chunk() -> Result<()> {
        let env = TestEnvironment::new()?;

        // Create test data
        let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
        fs::write(&env.input_path, &test_data)?;

        // First encrypt the data
        let mut encryptor =
            StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir.clone()))?;

        let mut encrypted_chunks = Vec::new();
        let data_map = loop {
            let (chunk_opt, map_opt) = encryptor.next_encryption()?;
            if let Some(chunk) = chunk_opt {
                encrypted_chunks.push(chunk);
            }
            if let Some(map) = map_opt {
                break map;
            }
        };

        // Create decryptor
        let mut decryptor =
            StreamSelfDecryptor::decrypt_to_file(env.output_path.clone(), &data_map)?;

        // Create an invalid chunk with random content
        let invalid_chunk = EncryptedChunk {
            content: Bytes::from(random_bytes(1024)),
        };

        // Try to decrypt with invalid chunk
        let result = decryptor.next_encrypted(invalid_chunk);

        // Should handle invalid chunk gracefully
        assert!(result.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_stream_self_decryptor_missing_chunks() -> Result<()> {
        let env = TestEnvironment::new()?;

        // Create test data
        let test_data = random_bytes(5 * crate::MIN_ENCRYPTABLE_BYTES);
        fs::write(&env.input_path, &test_data)?;

        // First encrypt the data
        let mut encryptor =
            StreamSelfEncryptor::encrypt_from_file(env.input_path, Some(env.chunk_dir.clone()))?;

        let mut encrypted_chunks = Vec::new();
        let data_map = loop {
            let (chunk_opt, map_opt) = encryptor.next_encryption()?;
            if let Some(chunk) = chunk_opt {
                encrypted_chunks.push(chunk);
            }
            if let Some(map) = map_opt {
                break map;
            }
        };

        // Create decryptor
        let mut decryptor =
            StreamSelfDecryptor::decrypt_to_file(env.output_path.clone(), &data_map)?;

        // Only feed half of the chunks
        let chunk_count = encrypted_chunks.len();
        for chunk in encrypted_chunks.into_iter().take(chunk_count / 2) {
            let _ = decryptor.next_encrypted(chunk)?;
        }

        // Verify the file is not complete
        assert!(fs::read(&env.output_path).is_err());

        Ok(())
    }
}
