// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS"  BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{encryption, get_pad_key_and_iv, xor, EncryptedChunk, Error, Result};
use bytes::Bytes;
use std::io::Cursor;
use xor_name::XorName;

// encrypted_Chunks are sorted !!
pub fn decrypt_sorted_set(
    src_hashes: Vec<XorName>,
    encrypted_chunks: &[&EncryptedChunk],
) -> Result<Bytes> {
    let mut all_bytes = Vec::new();

    // Process chunks sequentially to maintain proper boundaries
    for (chunk_index, chunk) in encrypted_chunks.iter().enumerate() {
        let decrypted = decrypt_chunk(chunk_index, &chunk.content, &src_hashes)?;
        all_bytes.extend_from_slice(&decrypted);
    }

    Ok(Bytes::from(all_bytes))
}

/// Decrypt a chunk, given the index of that chunk in the sequence of chunks,
/// and the raw encrypted content.
pub fn decrypt_chunk(chunk_index: usize, content: &Bytes, src_hashes: &[XorName]) -> Result<Bytes> {
    let pki = get_pad_key_and_iv(chunk_index, src_hashes);
    let (pad, key, iv) = pki;

    // First remove the XOR obfuscation
    let xored = xor(content, &pad);

    // Then decrypt the content
    let decrypted = encryption::decrypt(xored, &key, &iv)?;

    // Finally decompress
    let mut decompressed = Vec::new();
    let mut cursor = Cursor::new(&decrypted);

    brotli::BrotliDecompress(&mut cursor, &mut decompressed).map_err(|_| Error::Compression)?;

    Ok(Bytes::from(decompressed))
}
