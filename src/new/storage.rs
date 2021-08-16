// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::error::Error;
use async_trait::async_trait;
use bytes::Bytes;

/// Trait which must be implemented by storage objects to be used in self_encryption.  Data is
/// passed to the storage object encrypted with `name` being the SHA3-256 hash of `data`.  `Storage`
/// could be implemented as an in-memory `HashMap` or a disk-based container for example.
#[async_trait]
pub trait Storage {
    /// Retrieve data previously `put` under `name`.  If the data does not exist, an error should be
    /// returned.
    async fn get(&self, name: Bytes) -> Result<Bytes, Error>;
    /// Store `data` under `name`.
    async fn put(&self, name: Bytes, data: Bytes) -> Result<(), Error>;
    /// Delete `data` under `name`.
    async fn delete(&self, name: Bytes) -> Result<(), Error>;

    /// Generate the address at which the data will be stored. This address will be stored as a part of the data map.
    async fn generate_address(&self, data: Bytes) -> Result<Bytes, Error>;
}
