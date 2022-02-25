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
    box_pointers,
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
use itertools::Itertools;
use std::ops::Range;
use xor_name::XorName;

/// The minimum size (before compression) of data to be self-encrypted, defined as 3kB.
pub const MIN_ENCRYPTABLE_BYTES: usize = 3 * MIN_CHUNK_SIZE;
/// The maximum size (before compression) of an individual chunk of the file, defined as 1MB.
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;
/// The minimum size (before compression) of an individual chunk of the file, defined as 1kB.
pub const MIN_CHUNK_SIZE: usize = 1024;
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
    let sorted_chunks = chunks
        .iter()
        .sorted_by_key(|c| c.index)
        .cloned() // should not be needed, something is wrong here, the docs for sorted_by_key says it will return owned items...!
        .collect_vec();
    decrypt::decrypt(src_hashes, sorted_chunks)
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
    let encrypted_chunks = chunks
        .iter()
        .sorted_by_key(|c| c.index)
        .cloned()
        .collect_vec();
    let mut bytes = decrypt::decrypt(src_hashes, encrypted_chunks)?;

    if relative_pos >= bytes.len() {
        return Ok(Bytes::new());
    }

    // truncate taking care of overflows
    let _ = bytes.split_to(relative_pos);
    bytes.truncate(len);

    Ok(bytes)
}

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub(crate) fn xor(data: Bytes, &Pad(pad): &Pad) -> Bytes {
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
    SeekInfo {
        index_range: start_index..end_index,
        relative_pos: pos % get_chunk_size(file_size, start_index),
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
    let (n_1, n_2) = match chunk_index {
        0 => (chunk_hashes.len() - 1, chunk_hashes.len() - 2),
        1 => (0, chunk_hashes.len() - 1),
        n => (n - 1, n - 2),
    };
    let src_hash = &chunk_hashes[chunk_index];
    let n_1_src_hash = &chunk_hashes[n_1];
    let n_2_src_hash = &chunk_hashes[n_2];

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
    if file_size < (3 * MAX_CHUNK_SIZE) {
        return 3;
    }
    if file_size % MAX_CHUNK_SIZE == 0 {
        file_size / MAX_CHUNK_SIZE
    } else {
        (file_size / MAX_CHUNK_SIZE) + 1
    }
}

// Returns the size of a chunk according to file size.
fn get_chunk_size(file_size: usize, chunk_index: usize) -> usize {
    if file_size < 3 * MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE {
        if chunk_index < 2 {
            return file_size / 3;
        } else {
            return file_size - (2 * (file_size / 3));
        }
    }
    let total_chunks = get_num_chunks(file_size);
    if chunk_index < total_chunks - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = file_size % MAX_CHUNK_SIZE;
    let penultimate = (total_chunks - 2) == chunk_index;
    if remainder == 0 {
        return MAX_CHUNK_SIZE;
    }
    if remainder < MIN_CHUNK_SIZE {
        if penultimate {
            MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        } else {
            MIN_CHUNK_SIZE + remainder
        }
    } else if penultimate {
        MAX_CHUNK_SIZE
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
