// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::error::Error;

/// Trait inherited from `std::error::Error` representing errors which can be returned by the
/// `Storage` object.
pub trait StorageError: Error {}

/// Trait which must be implemented by storage objects to be used in self-encryption.  Data is
/// passed to the storage object encrypted with `name` being the SHA512 hash of `data`.  `Storage`
/// could be implemented as an in-memory `HashMap` or a disk-based container for example.
pub trait Storage<E: StorageError> {
    /// Retrieve data previously `put` under `name`.  If the data does not exist, an error should be
    /// returned.
    fn get(&self, name: &[u8]) -> Result<Vec<u8>, E>;
    /// Store `data` under `name`.
    fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Result<(), E>;
}
