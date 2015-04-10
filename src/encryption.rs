// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

use crypto::{symmetriccipher, aes, blockmodes};
use crypto::buffer::{self, ReadBuffer, WriteBuffer, BufferResult};

/* use self::rand::{ Rng, OsRng }; */
// TODO(dirvine) Look at aessafe 256X8 cbc it should be very much faster  :01/03/2015

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) ->
Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256,
                                           key,
                                           iv,
                                           blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&x| x));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) ->
Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize256,
                                           key,
                                           iv,
                                           blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&x| x));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::digest::Digest;
    use crypto::sha2::Sha512  as Sha512;
    use rand::Rng;

#[test]
    fn test_hash_sha_512() {
        let mut hasher = Sha512::new();
        hasher.input_str("abc");
        let hex = hasher.result_str();
        assert_eq!(hex, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                        2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

#[test]
    fn test_aes_cbc() {
        let message = "Hello World!";

        let mut key: [u8; 32] = [0; 32];
        let mut iv: [u8; 16] = [0; 16];

        let mut rng = super::rand::OsRng::new().unwrap();
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);

        let encrypted_data = encrypt(message.as_bytes(), &key, &iv).unwrap();
        let decrypted_data = decrypt(&encrypted_data[..], &key, &iv).unwrap();

        assert!(message.as_bytes() == &decrypted_data[..]);
    }
}
