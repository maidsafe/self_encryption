// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use futures::Future;
use std::error::Error;

/// Trait inherited from `std::error::Error` representing errors which can be returned by the
/// `Storage` object.
pub trait StorageError: Error {}

/// Trait which must be implemented by storage objects to be used in self-encryption.  Data is
/// passed to the storage object encrypted with `name` being the SHA3-256 hash of `data`.  `Storage`
/// could be implemented as an in-memory `HashMap` or a disk-based container for example.
pub trait Storage {
    /// Error type returned by `get` or `put`.
    type Error: StorageError;

    /// Retrieve data previously `put` under `name`.  If the data does not exist, an error should be
    /// returned.
    fn get(&self, name: &[u8]) -> Box<Future<Item = Vec<u8>, Error = Self::Error>>;
    /// Store `data` under `name`.
    fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Box<Future<Item = (), Error = Self::Error>>;
}
