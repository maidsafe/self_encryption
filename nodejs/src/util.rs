use napi::Result;
use napi_derive::napi;

use crate::{XorName, map_error};

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
#[napi]
pub fn verify_chunk(name: &XorName, bytes: &[u8]) -> Result<crate::EncryptedChunk> {
    let name = name.0;
    self_encryption::verify_chunk(name, bytes)
        .map_err(map_error)
        .map(crate::EncryptedChunk)
}
