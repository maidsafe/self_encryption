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
    unused_qualifications,
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
pub mod test_helpers;
#[cfg(test)]
mod tests;

use self::encryption::{Iv, Key, Pad, IV_SIZE, KEY_SIZE, PAD_SIZE};
pub use self::{
    data_map::{ChunkInfo, DataMap},
    error::{Error, Result},
};
use bytes::Bytes;
use chunk::batch_positions;
use decrypt::decrypt_chunk;
use encrypt::encrypt_chunk;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
};
use tempfile::{tempdir, TempDir};
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

/// The actual encrypted content
/// of the chunk, and its key index.
#[derive(Clone)]
pub struct EncryptedChunk {
    /// Index number (zero-based)
    pub index: usize,
    /// The encrypted contents of the chunk.
    pub content: Bytes,
}

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
    data_map: Vec<ChunkInfo>,
    // Progressing collection of source chunks' names
    src_hashes: BTreeMap<usize, XorName>,
    // File path to flush encrypted_chunks into.
    chunk_dir: Option<PathBuf>,
}

impl StreamSelfEncryptor {
    /// For encryption, return with an intialized streaming encryptor.
    /// If a `chunk_dir` is provided, the encrypted_chunks will be written into the specified dir as well.
    pub fn encrypt_from_file(file_path: PathBuf, chunk_dir: Option<PathBuf>) -> Result<Self> {
        let file = File::open(&*file_path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        let batch_positions = batch_positions(file_size as usize);

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
        self.data_map.push(ChunkInfo {
            index,
            dst_hash,
            src_hash,
            src_size: end_pos - start_pos,
        });

        let encrypted_chunk = EncryptedChunk {
            index,
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

        let mut file = File::open(&*self.file_path)?;

        let _ = file.seek(SeekFrom::Start(start_pos as u64))?;
        file.read_exact(&mut buffer)?;
        let content = Bytes::from(buffer);
        let src_hash = XorName::from_content(content.as_ref());

        let _ = self.src_hashes.insert(chunk_index, src_hash);

        Ok((src_hash, content))
    }

    fn get_pad_key_and_iv(&mut self, src_hash: XorName) -> Result<(Pad, Key, Iv)> {
        let (n_1, n_2) = get_n_1_n_2(self.chunk_index, self.batch_positions.len());

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
    // Progressing collection of received encrypted chunks
    encrypted_chunks: BTreeMap<usize, XorName>,
    // Temp directory to hold the un-processed encrypted_chunks
    temp_dir: TempDir,
}

impl StreamSelfDecryptor {
    /// For decryption, return with an intialized streaming decryptor
    pub fn decrypt_to_file(file_path: PathBuf, data_map: &DataMap) -> Result<Self> {
        let temp_dir = tempdir()?;
        let src_hashes = extract_hashes(data_map);

        // The targeted file shall not be pre-exist.
        // Hence we carry out a forced removal before carry out any further action.
        let _ = fs::remove_file(&*file_path);

        Ok(StreamSelfDecryptor {
            file_path,
            chunk_index: 0,
            src_hashes,
            encrypted_chunks: BTreeMap::new(),
            temp_dir,
        })
    }

    /// Return true if all encrypted chunk got received and file decrypted.
    pub fn next_encrypted(&mut self, encrypted_chunk: EncryptedChunk) -> Result<bool> {
        if encrypted_chunk.index == self.chunk_index {
            let decrypted_content =
                decrypt_chunk(self.chunk_index, &encrypted_chunk.content, &self.src_hashes)?;
            self.append_to_file(&decrypted_content)?;

            self.chunk_index += 1;

            self.drain_unprocessed()?;

            if self.chunk_index == self.src_hashes.len() {
                return Ok(true);
            }
        } else {
            let chunk_name = XorName::from_content(&encrypted_chunk.content);

            let file_path = self.temp_dir.path().join(hex::encode(chunk_name));
            let mut output_file = File::create(file_path)?;
            output_file.write_all(&encrypted_chunk.content)?;

            let _ = self
                .encrypted_chunks
                .insert(encrypted_chunk.index, chunk_name);
        }

        Ok(false)
    }

    // If the file does not exist, it will be created. The function then writes the content to the file.
    // If the file already exists, the content will be appended to the end of the file.
    fn append_to_file(&self, content: &Bytes) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&*self.file_path)?;

        file.write_all(content)?;

        Ok(())
    }

    // The encrypted chunks may come in out-of-order.
    // Drain any in-order chunks due to the recent filled in piece.
    fn drain_unprocessed(&mut self) -> Result<()> {
        while let Some(chunk_name) = self.encrypted_chunks.get(&self.chunk_index) {
            let file_path = self.temp_dir.path().join(hex::encode(chunk_name));
            let mut chunk_file = File::open(file_path)?;
            let mut chunk_data = Vec::new();
            let _ = chunk_file.read_to_end(&mut chunk_data)?;

            let decrypted_content =
                decrypt_chunk(self.chunk_index, &chunk_data.into(), &self.src_hashes)?;
            self.append_to_file(&decrypted_content)?;

            self.chunk_index += 1;
        }

        Ok(())
    }
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

/// Decrypts from an expected full set of chunks which presents in the disk.
/// Output the resulted file to the specific directory.
pub fn decrypt_from_chunk_files(
    chunk_dir: &Path,
    data_map: &DataMap,
    output_filepath: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encrypted_chunks = Vec::new();
    for chunk_info in data_map.infos() {
        let chunk_name = chunk_info.dst_hash;
        let file_path = chunk_dir.join(hex::encode(chunk_name));
        let mut chunk_file = File::open(file_path)?;
        let mut chunk_data = Vec::new();
        let _ = chunk_file.read_to_end(&mut chunk_data)?;
        encrypted_chunks.push(EncryptedChunk {
            index: chunk_info.index,
            content: Bytes::from(chunk_data),
        });
    }

    let decrypted_content = decrypt_full_set(data_map, &encrypted_chunks)?;
    let mut output_file = File::create(output_filepath)?;
    output_file.write_all(&decrypted_content)?;

    Ok(())
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
pub fn decrypt_full_set(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);
    let mut sorted_chunks = Vec::with_capacity(chunks.len());
    sorted_chunks.extend(chunks.iter().sorted_by_key(|c| c.index));
    decrypt::decrypt(src_hashes, &sorted_chunks)
}

/// Decrypts a range, used when seeking.
///
/// `relative_pos` is the position within the first read chunk, that we start reading from.
pub fn decrypt_range(
    data_map: &DataMap,
    chunks: &[EncryptedChunk],
    relative_pos: usize,
    len: usize,
) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);
    let mut sorted_chunks = Vec::with_capacity(chunks.len());
    sorted_chunks.extend(chunks.iter().sorted_by_key(|c| c.index));

    let mut bytes = decrypt::decrypt(src_hashes, &sorted_chunks)?;

    if relative_pos >= bytes.len() {
        return Ok(Bytes::new());
    }

    // truncate taking care of overflows
    let _ = bytes.split_to(relative_pos);
    bytes.truncate(len);

    Ok(bytes)
}

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub(crate) fn xor(data: &Bytes, &Pad(pad): &Pad) -> Bytes {
    let vec: Vec<_> = data
        .iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect();
    Bytes::from(vec)
}

/// Helper struct for seeking
/// original file bytes from chunks.
pub struct SeekInfo {
    /// Start and end index for the chunks
    /// covered by a pos and len.
    pub index_range: Range<usize>,
    /// The start pos of first chunk.
    /// The position is relative to the
    /// byte content of that chunk, not the whole file.
    pub relative_pos: usize,
}

/// Helper function for getting info needed
/// to seek original file bytes from chunks.
///
/// It is used to first fetch chunks using the `index_range`.
/// Then the chunks are passed into `self_encryption::decrypt_range` together
/// with `relative_pos` from the `SeekInfo` instance, and the `len` to be read.
pub fn seek_info(file_size: usize, pos: usize, len: usize) -> SeekInfo {
    let (start_index, end_index) = overlapped_chunks(file_size, pos, len);

    let relative_pos = if start_index == 2 && file_size < 3 * *MAX_CHUNK_SIZE {
        pos - (2 * get_chunk_size(file_size, 0))
    } else {
        pos % get_chunk_size(file_size, start_index)
    };

    SeekInfo {
        index_range: start_index..end_index,
        relative_pos,
    }
}

// ------------------------------------------------------------------------------
//   ---------------------- Private methods -----------------------------------
// ------------------------------------------------------------------------------

/// Returns the chunk index range [start, end) that is overlapped by the byte range defined by `pos`
/// and `len`. Returns empty range if `file_size` is so small that there are no chunks.
fn overlapped_chunks(file_size: usize, pos: usize, len: usize) -> (usize, usize) {
    // FIX THIS SHOULD NOT BE ALLOWED
    if file_size < (3 * MIN_CHUNK_SIZE) || pos >= file_size || len == 0 {
        return (0, 0);
    }

    // calculate end position taking care of overflows
    let end = match pos.checked_add(len) {
        Some(end) => end,
        None => file_size,
    };

    let start_index = get_chunk_index(file_size, pos);
    let end_index = get_chunk_index(file_size, end);

    (start_index, end_index)
}

fn extract_hashes(data_map: &DataMap) -> Vec<XorName> {
    data_map.infos().iter().map(|c| c.src_hash).collect()
}

fn get_pad_key_and_iv(chunk_index: usize, chunk_hashes: &[XorName]) -> (Pad, Key, Iv) {
    let (n_1, n_2) = get_n_1_n_2(chunk_index, chunk_hashes.len());

    let src_hash = &chunk_hashes[chunk_index];
    let n_1_src_hash = &chunk_hashes[n_1];
    let n_2_src_hash = &chunk_hashes[n_2];

    get_pki(src_hash, n_1_src_hash, n_2_src_hash)
}

fn get_n_1_n_2(chunk_index: usize, total_num_chunks: usize) -> (usize, usize) {
    match chunk_index {
        0 => (total_num_chunks - 1, total_num_chunks - 2),
        1 => (0, total_num_chunks - 1),
        n => (n - 1, n - 2),
    }
}

fn get_pki(src_hash: &XorName, n_1_src_hash: &XorName, n_2_src_hash: &XorName) -> (Pad, Key, Iv) {
    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in pad
        .iter_mut()
        .zip(src_hash.iter().chain(n_2_src_hash.iter()))
    {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().chain(iv.iter_mut()).zip(n_1_src_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

// Returns the number of chunks according to file size.
fn get_num_chunks(file_size: usize) -> usize {
    if file_size < (3 * MIN_CHUNK_SIZE) {
        return 0;
    }
    if file_size < (3 * *MAX_CHUNK_SIZE) {
        return 3;
    }
    if file_size % *MAX_CHUNK_SIZE == 0 {
        file_size / *MAX_CHUNK_SIZE
    } else {
        (file_size / *MAX_CHUNK_SIZE) + 1
    }
}

// Returns the size of a chunk according to file size.
fn get_chunk_size(file_size: usize, chunk_index: usize) -> usize {
    if file_size < 3 * MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * *MAX_CHUNK_SIZE {
        if chunk_index < 2 {
            return file_size / 3;
        } else {
            // When the file_size % 3 > 0, the third (last) chunk includes the remainder
            return file_size - (2 * (file_size / 3));
        }
    }
    let total_chunks = get_num_chunks(file_size);
    if chunk_index < total_chunks - 2 {
        return *MAX_CHUNK_SIZE;
    }
    let remainder = file_size % *MAX_CHUNK_SIZE;
    let penultimate = (total_chunks - 2) == chunk_index;
    if remainder == 0 {
        return *MAX_CHUNK_SIZE;
    }
    if remainder < MIN_CHUNK_SIZE {
        if penultimate {
            *MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        } else {
            MIN_CHUNK_SIZE + remainder
        }
    } else if penultimate {
        *MAX_CHUNK_SIZE
    } else {
        remainder
    }
}

// Returns the [start, end) half-open byte range of a chunk.
fn get_start_end_positions(file_size: usize, chunk_index: usize) -> (usize, usize) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start = get_start_position(file_size, chunk_index);
    (start, start + get_chunk_size(file_size, chunk_index))
}

fn get_start_position(file_size: usize, chunk_index: usize) -> usize {
    let total_chunks = get_num_chunks(file_size);
    if total_chunks == 0 {
        return 0;
    }
    let last = (total_chunks - 1) == chunk_index;
    let first_chunk_size = get_chunk_size(file_size, 0);
    if last {
        first_chunk_size * (chunk_index - 1) + get_chunk_size(file_size, chunk_index - 1)
    } else {
        first_chunk_size * chunk_index
    }
}

fn get_chunk_index(file_size: usize, position: usize) -> usize {
    let num_chunks = get_num_chunks(file_size);
    if num_chunks == 0 {
        return 0; // FIX THIS SHOULD NOT BE ALLOWED
    }

    let chunk_size = get_chunk_size(file_size, 0);
    let remainder = file_size % chunk_size;

    if remainder == 0
        || remainder >= MIN_CHUNK_SIZE
        || position < file_size - remainder - MIN_CHUNK_SIZE
    {
        usize::min(position / chunk_size, num_chunks - 1)
    } else {
        num_chunks - 1
    }
}
