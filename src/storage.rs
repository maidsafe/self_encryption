// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// Storage traits of SelfEncryptor. Data stored in Storage is encrypted, name is the SHA512 hash
/// of content. Storage can be in-memory HashMap or disk based
pub trait Storage {
    /// Fetch the data bearing the name
    fn get(&self, name: &[u8]) -> Vec<u8>;
    /// Insert the data bearing the name.
    fn put(&mut self, name: Vec<u8>, data: Vec<u8>);
}
