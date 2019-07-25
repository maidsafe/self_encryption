// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO(dirvine) Look at aessafe 256X8 cbc it should be very much faster  :01/03/2015

use rust_sodium::crypto::secretbox::{self, KEYBYTES, NONCEBYTES};

pub use rust_sodium::crypto::secretbox::{Key, Nonce as Iv};
pub type DecryptionError = ();

pub const KEY_SIZE: usize = KEYBYTES;
pub const IV_SIZE: usize = NONCEBYTES;

pub fn encrypt(data: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    secretbox::seal(data, iv, key)
}

pub fn decrypt(encrypted_data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, DecryptionError> {
    secretbox::open(encrypted_data, iv, key)
}
