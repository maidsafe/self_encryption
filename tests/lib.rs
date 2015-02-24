/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */

extern crate rand;
extern crate crypto;
extern crate test;
use crypto::digest::Digest;
use crypto::sha2::Sha512  as Sha512;

use self::rand::{ Rng, OsRng };
extern crate self_encryption;
pub use self_encryption::*;

#[test]
  fn test_hash_sha_512() {
    let mut hasher = Sha512::new();
    hasher.input_str("abc");
    let hex = hasher.result_str();
    assert_eq!(hex.as_slice(),
        concat!("ddaf35a193617abacc417349ae2041311",
          "2e6fa4e89a97ea20a9eeee64b55d39a",
          "2192992a274fc1a836ba3c23a3feebbd45",
          "4d4423643ce80e2a9ac94fa54ca49f"));
  }

#[test]
  fn test_aes_cbc() {
    let message = "Hello World!";

    let mut key: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];

    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let encrypted_data = self_encryption::encryption::encrypt(message.as_bytes(), &key, &iv).ok().unwrap();
    let decrypted_data = self_encryption::encryption::decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();

    assert!(message.as_bytes() == &decrypted_data[..]);
  } 
