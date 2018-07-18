// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::small_encryptor::SmallEncryptor;
use super::{utils, SelfEncryptionError, Storage, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use data_map::{ChunkDetails, DataMap};
use futures::{future, Future};
use safe_crypto::hash;
use std::convert::From;
use util::{BoxFuture, FutureExt};

pub const MIN: u64 = 3 * MIN_CHUNK_SIZE as u64;
pub const MAX: u64 = 3 * MAX_CHUNK_SIZE as u64;

// An encryptor for data which will be split into exactly three chunks (i.e. size is between
// `3 * MIN_CHUNK_SIZE` and `3 * MAX_CHUNK_SIZE` inclusive).  Only `close()` will actually cause
// chunks to be stored.  Until then, data is held internally in `buffer`.
pub struct MediumEncryptor<S> {
    pub storage: S,
    pub buffer: Vec<u8>,
    original_chunks: Option<Vec<ChunkDetails>>,
}

impl<S> MediumEncryptor<S>
where
    S: Storage + 'static,
{
    // Constructor for use with pre-existing `DataMap::Chunks` where there are exactly three chunks.
    // Retrieves the chunks from storage and decrypts them to its internal `buffer`.
    pub fn new(
        storage: S,
        chunks: Vec<ChunkDetails>,
    ) -> BoxFuture<MediumEncryptor<S>, SelfEncryptionError<S::Error>> {
        debug_assert_eq!(chunks.len(), 3);
        debug_assert!(MIN <= chunks.iter().fold(0, |acc, chunk| acc + chunk.source_size));
        debug_assert!(chunks.iter().fold(0, |acc, chunk| acc + chunk.source_size) <= MAX);

        let mut futures = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let pad_key_iv = utils::get_pad_key_and_iv(index, &chunks);
            futures.push(
                storage
                    .get(&chunk.hash)
                    .map_err(From::from)
                    .and_then(move |data| utils::decrypt_chunk(&data, pad_key_iv)),
            );
        }

        future::join_all(futures)
            .map(move |data| {
                let init = Vec::with_capacity(MAX as usize);
                let buffer = data.into_iter().fold(init, |mut buffer, data| {
                    buffer.extend(data);
                    buffer
                });

                MediumEncryptor {
                    storage,
                    buffer,
                    original_chunks: Some(chunks),
                }
            }).into_box()
    }

    // Simply appends to internal buffer assuming the size limit is not exceeded.  No chunks are
    // generated by this call.
    pub fn write(mut self, data: &[u8]) -> BoxFuture<Self, SelfEncryptionError<S::Error>> {
        debug_assert!(data.len() as u64 + self.len() <= MAX);
        self.original_chunks = None;
        self.buffer.extend_from_slice(data);
        future::ok(self).into_box()
    }

    // This finalises the encryptor - it should not be used again after this call.  Exactly three
    // chunks will be generated and stored by calling this unless the encryptor didn't receive any
    // `write()` calls.
    pub fn close(mut self) -> BoxFuture<(DataMap, S), SelfEncryptionError<S::Error>> {
        if let Some(chunks) = self.original_chunks {
            return future::ok((DataMap::Chunks(chunks), self.storage)).into_box();
        }

        let mut futures;
        let mut chunk_details;

        {
            // Third the contents, with the extra single or two bytes in the last chunk.
            let chunk_contents = vec![
                &self.buffer[..(self.buffer.len() / 3)],
                &self.buffer[(self.buffer.len() / 3)..(2 * (self.buffer.len() / 3))],
                &self.buffer[(2 * (self.buffer.len() / 3))..],
            ];
            // Note the pre-encryption hashes and sizes.
            chunk_details = vec![];
            for (index, contents) in chunk_contents.iter().enumerate() {
                chunk_details.push(ChunkDetails {
                    chunk_num: index as u32,
                    hash: vec![],
                    pre_hash: hash(contents).to_vec(),
                    source_size: contents.len() as u64,
                });
            }
            // Encrypt the chunks and note the post-encryption hashes
            let partial_details = chunk_details.clone();
            futures = Vec::with_capacity(chunk_contents.len());
            // FIXME: rust-nightly requires this to be mutable while rust-stable does not
            #[allow(unused)]
            for (index, (contents, mut details)) in chunk_contents
                .iter()
                .zip(chunk_details.iter_mut())
                .enumerate()
            {
                let pad_key_iv = utils::get_pad_key_and_iv(index, &partial_details);
                let future = match utils::encrypt_chunk(contents, pad_key_iv) {
                    Ok(encrypted_contents) => {
                        let hash = hash(&encrypted_contents);
                        details.hash = hash.to_vec();
                        self.storage
                            .put(hash.to_vec(), encrypted_contents)
                            .map_err(From::from)
                            .into_box()
                    }
                    Err(error) => future::err(error).into_box(),
                };

                futures.push(future);
            }
        }

        future::join_all(futures)
            .map(move |_| (DataMap::Chunks(chunk_details), self.storage))
            .into_box()
    }

    pub fn len(&self) -> u64 {
        self.buffer.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl<S: Storage> From<SmallEncryptor<S>> for MediumEncryptor<S> {
    fn from(small_encryptor: SmallEncryptor<S>) -> MediumEncryptor<S> {
        MediumEncryptor {
            storage: small_encryptor.storage,
            buffer: small_encryptor.buffer,
            original_chunks: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::small_encryptor::{self, SmallEncryptor};
    use super::super::{utils, MAX_CHUNK_SIZE};
    use super::*;
    use data_map::DataMap;
    use futures::Future;
    use itertools::Itertools;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    use self_encryptor::SelfEncryptor;
    use test_helpers::{Blob, SimpleStorage};

    #[test]
    fn consts() {
        assert_eq!(MIN, small_encryptor::MAX + 1);
    }

    // Writes all of `data` to a new encryptor in a single call, then closes and reads back via
    // a `SelfEncryptor`.
    fn basic_write_and_close(data: &[u8]) {
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let mut encryptor = unwrap!(
                SmallEncryptor::new(storage, vec![])
                    .map(MediumEncryptor::from)
                    .wait()
            );
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            encryptor = unwrap!(encryptor.write(data).wait());
            assert_eq!(encryptor.len(), data.len() as u64);
            assert!(!encryptor.is_empty());
            unwrap!(encryptor.close().wait())
        };

        match data_map {
            DataMap::Chunks(ref chunks) => assert_eq!(chunks.len(), 3),
            _ => panic!("Wrong DataMap type returned."),
        }

        let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map));
        let fetched = unwrap!(self_encryptor.read(0, data.len() as u64).wait());
        assert_eq!(Blob(&fetched), Blob(data));
    }

    // Splits `data` into several pieces, then for each piece:
    //  * constructs a new encryptor from existing chunk details (except for the first piece)
    //  * writes the piece
    //  * closes and reads back the full data via a `SelfEncryptor`.
    fn multiple_writes_then_close<T: Rng>(rng: &mut T, data: &[u8]) {
        let mut storage = SimpleStorage::new();
        let mut existing_data = vec![];
        let data_pieces = utils::make_random_pieces(rng, data, MIN as usize);
        let mut current_chunks = vec![];
        for data in data_pieces {
            let data_map = {
                let mut encryptor = if current_chunks.is_empty() {
                    unwrap!(
                        SmallEncryptor::new(storage, vec![])
                            .map(MediumEncryptor::from)
                            .wait()
                    )
                } else {
                    unwrap!(MediumEncryptor::new(storage, current_chunks).wait())
                };
                encryptor = unwrap!(encryptor.write(data).wait());
                existing_data.extend_from_slice(data);
                assert_eq!(encryptor.len(), existing_data.len() as u64);

                let (data_map, storage2) = unwrap!(encryptor.close().wait());
                storage = storage2;
                data_map
            };

            match data_map {
                DataMap::Chunks(ref chunks) => {
                    assert_eq!(chunks.len(), 3);
                    current_chunks = chunks.clone()
                }
                _ => panic!("Wrong DataMap type returned."),
            }

            let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map));
            assert_eq!(self_encryptor.len(), existing_data.len() as u64);
            let fetched = unwrap!(self_encryptor.read(0, existing_data.len() as u64).wait());
            assert_eq!(fetched, existing_data);
            storage = self_encryptor.into_storage();
        }
        assert_eq!(Blob(&existing_data[..]), Blob(data));
    }

    #[test]
    fn all_unit() {
        let mut rng = SeededRng::new();
        let data = rng.gen_iter().take(MAX as usize).collect_vec();

        basic_write_and_close(&data[..MIN as usize]);
        basic_write_and_close(&data[..MAX_CHUNK_SIZE as usize]);
        basic_write_and_close(&data[..(MAX_CHUNK_SIZE as usize * 2)]);
        basic_write_and_close(&data);

        multiple_writes_then_close(&mut rng, &data[..(MIN as usize * 2)]);
        multiple_writes_then_close(&mut rng, &data[..MAX_CHUNK_SIZE as usize]);
        multiple_writes_then_close(&mut rng, &data[..(MAX_CHUNK_SIZE as usize * 2)]);
        multiple_writes_then_close(&mut rng, &data);
    }
}
