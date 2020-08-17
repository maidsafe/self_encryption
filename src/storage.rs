// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use async_trait::async_trait;
use std::error::Error;
/// Trait inherited from `std::error::Error` representing errors which can be returned by the
/// `Storage` object.
pub trait StorageError: Error {}

/// Trait which must be implemented by storage objects to be used in self-encryption.  Data is
/// passed to the storage object encrypted with `name` being the SHA3-256 hash of `data`.  `Storage`
/// could be implemented as an in-memory `HashMap` or a disk-based container for example.
#[async_trait]
pub trait Storage {
    /// Error type returned by `get` or `put`.
    type Error: StorageError;

    /// Retrieve data previously `put` under `name`.  If the data does not exist, an error should be
    /// returned.
    async fn get(&mut self, name: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// Store `data` under `name`.
    async fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Result<(), Self::Error>;

    /// Generate the address at which the data will be stored. This address will be stored as a part of the data map.
    async fn generate_address(&self, data: &[u8]) -> Vec<u8>;
}
