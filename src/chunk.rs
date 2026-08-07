// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use bytes::Bytes;

/// The actual encrypted content of the chunk
#[derive(Clone, Debug)]
pub struct EncryptedChunk {
    /// The encrypted content of the chunk
    pub content: Bytes,
}
