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

// TODO(dirvine) Look at aessafe 256X8 cbc it should be very much faster  :01/03/2015

use sodiumoxide::crypto::secretbox::{KEYBYTES, NONCEBYTES, self};

pub use sodiumoxide::crypto::secretbox::Key;
pub use sodiumoxide::crypto::secretbox::Nonce as Iv;

pub const KEY_SIZE: usize = KEYBYTES;
pub const IV_SIZE: usize = NONCEBYTES;

pub fn encrypt(data: &[u8], key: &Key, iv: &Iv) -> Vec<u8> {
    secretbox::seal(data, iv, key)
}

pub fn decrypt(encrypted_data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, ()> {
    secretbox::open(encrypted_data, iv, key)
}

#[cfg(test)]
mod tests {
    use rustc_serialize::hex::ToHex;
    use sodiumoxide::crypto::hash::sha512;
    use sodiumoxide::randombytes::randombytes_into;
    use super::*;

    #[test]
    fn test_hash_sha_512() {
        let input = ['a' as u8, 'b' as u8, 'c' as u8];
        let sha512::Digest(name) = sha512::hash(&input);
        let hex = &name.to_vec()[..].to_hex();
        assert_eq!(hex,
                   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc\
                    1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    #[test]
    fn test_salsa20poly1305() {
        let message = "Hello World!";

        let mut key = [0u8; KEY_SIZE];
        let mut iv = [0u8; IV_SIZE];

        randombytes_into(&mut key);
        randombytes_into(&mut iv);

        let encrypted_data = encrypt(message.as_bytes(), &Key(key), &Iv(iv));
        let decrypted_data = unwrap_result!(decrypt(&encrypted_data[..], &Key(key), &Iv(iv)));

        assert!(message.as_bytes() == &decrypted_data[..]);
    }
}
