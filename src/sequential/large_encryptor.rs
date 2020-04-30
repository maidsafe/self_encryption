// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    medium_encryptor::MediumEncryptor, small_encryptor::SmallEncryptor, utils, SelfEncryptionError,
    Storage, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
use crate::data_map::{ChunkDetails, DataMap};
use std::{cmp, convert::From, mem};
use unwrap::unwrap;
pub const MIN: u64 = 3 * MAX_CHUNK_SIZE as u64 + 1;
const MAX_BUFFER_LEN: usize = (MAX_CHUNK_SIZE + MIN_CHUNK_SIZE) as usize;

// An encryptor for data which will be split into more three chunks.  Calls to `write()` will
// trigger the creation and storing of any completed chunks up to that point except for the first
// two and last two chunks.  These will always be dealt with in `close()` since they may always be
// affected subsequent `write()` calls.
pub struct LargeEncryptor<S: Storage + Send + Sync> {
    storage: S,
    chunks: Vec<ChunkDetails>,
    original_chunks: Option<Vec<ChunkDetails>>,
    chunk_0_data: Vec<u8>,
    chunk_1_data: Vec<u8>,
    buffer: Vec<u8>,
}

impl<S> LargeEncryptor<S>
where
    S: Storage + 'static + Send + Sync,
{
    // Constructor for use with pre-existing `DataMap::Chunks` where there are more than three
    // chunks.  Retrieves the first two and and last two chunks from storage and decrypts them to
    // its internal buffers.
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        storage: S,
        chunks: Vec<ChunkDetails>,
    ) -> Result<LargeEncryptor<S>, SelfEncryptionError<S::Error>> {
        debug_assert!(chunks.len() > 3);
        debug_assert!(MIN <= chunks.iter().fold(0, |acc, chunk| acc + chunk.source_size));
        let mut partial_details = chunks.clone();
        let mut truncated_details_len = chunks.len() - 1;

        let mut chunk_0_data;
        let mut chunk_1_data;
        let mut buffer;
        let buffer_extension;

        {
            // Decrypt first two chunks
            let mut start_iter = partial_details.iter_mut().enumerate();
            let (index, chunk) = unwrap!(start_iter.next());
            let pad_key_iv = utils::get_pad_key_and_iv(index, &chunks);

            chunk_0_data = storage.get(&chunk.hash).await?;
            chunk_0_data = utils::decrypt_chunk(&chunk_0_data, pad_key_iv)?;
            chunk.hash.clear();

            let (index, chunk) = unwrap!(start_iter.next());
            let pad_key_iv = utils::get_pad_key_and_iv(index, &chunks);
            chunk_1_data = storage.get(&chunk.hash).await?;
            chunk_1_data = utils::decrypt_chunk(&chunk_1_data, pad_key_iv)?;
            chunk.hash.clear();

            // If the penultimate chunk is not at MAX_CHUNK_SIZE, decrypt it to `buffer`
            let mut end_iter = start_iter.skip(chunks.len() - 4);
            let (index, chunk) = unwrap!(end_iter.next());
            buffer = if chunk.source_size < MAX_CHUNK_SIZE as u64 {
                let pad_key_iv = utils::get_pad_key_and_iv(index, &chunks);
                truncated_details_len -= 1;
                let another_chunk_data = storage.get(&chunk.hash).await?;

                utils::decrypt_chunk(&another_chunk_data, pad_key_iv)?
            } else {
                Vec::with_capacity(MAX_BUFFER_LEN)
            };

            // Decrypt the last chunk to `buffer`
            let (index, chunk) = unwrap!(end_iter.next());
            let pad_key_iv = utils::get_pad_key_and_iv(index, &chunks);
            let data = storage.get(&chunk.hash).await?;

            buffer_extension = utils::decrypt_chunk(&data, pad_key_iv)?
        }

        // Remove the last one or two chunks' details since they're now in `buffer`
        partial_details.truncate(truncated_details_len);
        buffer.extend(buffer_extension);

        Ok(LargeEncryptor {
            storage,
            chunks: partial_details,
            original_chunks: Some(chunks),
            chunk_0_data,
            chunk_1_data,
            buffer,
        })
    }

    pub async fn from_medium(
        medium_encryptor: MediumEncryptor<S>,
    ) -> Result<Self, SelfEncryptionError<S::Error>> {
        let encryptor = LargeEncryptor {
            storage: medium_encryptor.storage,
            chunks: vec![],
            original_chunks: None,
            chunk_0_data: vec![],
            chunk_1_data: vec![],
            buffer: vec![],
        };

        encryptor.write(&medium_encryptor.buffer).await
    }

    // Stores any chunks which cannot be modified by subsequent `write()` calls and buffers the
    // remainder.  Chunks which cannot be stored yet include the first two chunks and the final
    // chunk.  If the final chunk is smaller than `MIN_CHUNK_SIZE` then the penultimate chunk
    // cannot be stored either.
    pub async fn write(mut self, mut data: &[u8]) -> Result<Self, SelfEncryptionError<S::Error>> {
        self.original_chunks = None;

        // Try filling `chunk_0_data` and `chunk_1_data` buffers first.
        data = self.fill_chunk_buffer(data, 0);
        data = self.fill_chunk_buffer(data, 1);

        let mut all_things = Vec::new();

        while !data.is_empty() {
            let amount = cmp::min(MAX_BUFFER_LEN - self.buffer.len(), data.len());
            // TODO - avoid copying _all_ of `data` to `self_buffer` where full chunks can be
            // encrypted.
            self.buffer.extend_from_slice(&data[..amount]);
            data = &data[amount..];
            // If the buffer's full, encrypt and remove the first `MAX_CHUNK_SIZE` of it.
            if self.buffer.len() == MAX_BUFFER_LEN {
                let mut data_to_encrypt = self.buffer.split_off(MAX_CHUNK_SIZE as usize);
                mem::swap(&mut self.buffer, &mut data_to_encrypt);
                let index = self.chunks.len();
                all_things.push(self.encrypt_chunk(&data_to_encrypt, index).await?);
            }
        }

        Ok(self)
    }

    // This finalises the encryptor - it should not be used again after this call.  Either three or
    // four chunks will be generated and stored by calling this; chunks 0 and 1, the last chunk, and
    // possibly the penultimate chunk if the last chunk would otherwise be too small.  The only
    // exception is where the encryptor didn't receive any `write()` calls, in which case no chunks
    // are stored.
    pub async fn close(mut self) -> Result<(DataMap, S), SelfEncryptionError<S::Error>> {
        if let Some(chunks) = self.original_chunks {
            return Ok((DataMap::Chunks(chunks), self.storage));
        }

        // Handle encrypting and storing the contents of `self.buffer`.
        debug_assert!(self.buffer.len() >= MIN_CHUNK_SIZE as usize);
        debug_assert!(self.buffer.len() <= MAX_BUFFER_LEN);
        let (first_len, need_two_chunks) = if self.buffer.len() <= MAX_CHUNK_SIZE as usize {
            (self.buffer.len(), false)
        } else {
            ((MAX_CHUNK_SIZE - MIN_CHUNK_SIZE) as usize, true)
        };
        let mut index = self.chunks.len();
        let mut swapped_buffer = vec![];

        let mut all_chunks = Vec::with_capacity(4);

        mem::swap(&mut swapped_buffer, &mut self.buffer);
        all_chunks.push(
            self.encrypt_chunk(&swapped_buffer[..first_len], index)
                .await?,
        );
        if need_two_chunks {
            index += 1;
            all_chunks.push(
                self.encrypt_chunk(&swapped_buffer[first_len..], index)
                    .await?,
            );
        }

        // Handle encrypting and storing the contents of the first two chunks' buffers.
        mem::swap(&mut swapped_buffer, &mut self.chunk_0_data);
        all_chunks.push(self.encrypt_chunk(&swapped_buffer, 0).await?);
        mem::swap(&mut swapped_buffer, &mut self.chunk_1_data);
        all_chunks.push(self.encrypt_chunk(&swapped_buffer, 1).await?);

        let mut swapped_chunks = vec![];
        mem::swap(&mut swapped_chunks, &mut self.chunks);

        Ok((DataMap::Chunks(swapped_chunks), self.storage))
    }

    pub fn len(&self) -> u64 {
        self.chunk_0_data.len() as u64
            + self.chunk_1_data.len() as u64
            + self.buffer.len() as u64
            + ((self.chunks.len().saturating_sub(2)) * MAX_CHUNK_SIZE as usize) as u64
    }

    pub fn is_empty(&self) -> bool {
        self.chunk_0_data.is_empty()
    }

    fn fill_chunk_buffer<'b>(&mut self, mut data: &'b [u8], index: u32) -> &'b [u8] {
        let buffer_ref = if index == 0 {
            &mut self.chunk_0_data
        } else {
            &mut self.chunk_1_data
        };
        let amount = cmp::min(MAX_CHUNK_SIZE as usize - buffer_ref.len(), data.len());
        if amount > 0 {
            buffer_ref.extend_from_slice(&data[..amount]);
            data = &data[amount..];
            // If the buffer's full, update `chunks` with the pre-encryption hash and size.
            if buffer_ref.len() == MAX_CHUNK_SIZE as usize {
                self.chunks.push(ChunkDetails {
                    chunk_num: index,
                    hash: vec![],
                    pre_hash: self.storage.generate_address(buffer_ref),
                    source_size: MAX_CHUNK_SIZE as u64,
                });
            }
        }
        data
    }

    async fn encrypt_chunk(
        &mut self,
        data: &[u8],
        index: usize,
    ) -> Result<(), SelfEncryptionError<S::Error>> {
        if index > 1 {
            self.chunks.push(ChunkDetails {
                chunk_num: index as u32,
                hash: vec![],
                pre_hash: self.storage.generate_address(data),
                source_size: data.len() as u64,
            });
        }

        let pad_key_iv = utils::get_pad_key_and_iv(index, &self.chunks);
        let encrypted_contents = utils::encrypt_chunk(data, pad_key_iv)?;

        let hash = self.storage.generate_address(&encrypted_contents);
        self.chunks[index].hash = hash.to_vec();

        self.storage
            .put(hash.to_vec(), encrypted_contents.to_vec())
            .await?;
        Ok(())
    }
}

impl<S: Storage + Send + Sync> From<SmallEncryptor<S>> for LargeEncryptor<S> {
    fn from(small_encryptor: SmallEncryptor<S>) -> LargeEncryptor<S> {
        LargeEncryptor {
            storage: small_encryptor.storage,
            chunks: vec![],
            original_chunks: None,
            chunk_0_data: small_encryptor.buffer,
            chunk_1_data: vec![],
            buffer: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            medium_encryptor::{self, MediumEncryptor},
            small_encryptor::SmallEncryptor,
            utils, MAX_CHUNK_SIZE,
        },
        *,
    };
    use crate::{
        data_map::DataMap,
        self_encryptor::SelfEncryptor,
        test_helpers::{new_test_rng, random_bytes, Blob, SimpleStorage},
    };
    use rand::Rng;

    #[test]
    fn consts() {
        assert_eq!(MIN, medium_encryptor::MAX + 1);
    }

    // Writes all of `data` to a new encryptor in a single call, then closes and reads back via
    // a `SelfEncryptor`.
    async fn basic_write_and_close(data: &[u8]) {
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let mut encryptor = unwrap!(SmallEncryptor::new(storage, vec![])
                .await
                .map(LargeEncryptor::from));
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            encryptor = unwrap!(encryptor.write(data).await);
            assert_eq!(encryptor.len(), data.len() as u64);
            assert!(!encryptor.is_empty());
            unwrap!(encryptor.close().await)
        };

        match data_map {
            DataMap::Chunks(ref chunks) => assert!(chunks.len() > 3),
            _ => panic!("Wrong DataMap type returned."),
        }

        let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map));
        let fetched = unwrap!(self_encryptor.read(0, data.len() as u64).await);
        assert_eq!(Blob(&fetched), Blob(data));
    }

    // Splits `data` into several pieces, then for each piece:
    //  * constructs a new encryptor from existing chunk details (except for the first piece)
    //  * writes the piece
    //  * closes and reads back the full data via a `SelfEncryptor`.
    async fn multiple_writes_then_close<T: Rng>(rng: &mut T, data: &[u8]) {
        let mut storage = SimpleStorage::new();
        let mut existing_data = vec![];
        let data_pieces = utils::make_random_pieces(rng, data, MIN as usize);
        let mut current_chunks = vec![];
        for data in data_pieces {
            let data_map = {
                let mut encryptor = if current_chunks.is_empty() {
                    unwrap!(SmallEncryptor::new(storage, vec![])
                        .await
                        .map(LargeEncryptor::from))
                } else {
                    unwrap!(LargeEncryptor::new(storage, current_chunks).await)
                };
                encryptor = unwrap!(encryptor.write(data).await);
                existing_data.extend_from_slice(data);
                assert_eq!(encryptor.len(), existing_data.len() as u64);

                let (data_map, storage2) = unwrap!(encryptor.close().await);
                storage = storage2;
                data_map
            };

            match data_map {
                DataMap::Chunks(ref chunks) => {
                    assert!(chunks.len() > 3);
                    current_chunks = chunks.clone()
                }
                _ => panic!("Wrong DataMap type returned."),
            }

            let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map));
            assert_eq!(self_encryptor.len(), existing_data.len() as u64);
            let fetched = unwrap!(self_encryptor.read(0, existing_data.len() as u64).await);
            assert_eq!(Blob(&fetched), Blob(&existing_data));

            storage = self_encryptor.into_storage();
        }
        assert_eq!(Blob(&existing_data[..]), Blob(data));
    }

    #[tokio::test]
    async fn all_unit() {
        let mut rng = new_test_rng();
        let data = random_bytes(&mut rng, 5 * MAX_CHUNK_SIZE as usize);

        basic_write_and_close(&data[..MIN as usize]).await;
        basic_write_and_close(&data[..(MAX_CHUNK_SIZE as usize * 4)]).await;
        basic_write_and_close(&data[..=(MAX_CHUNK_SIZE as usize * 4)]).await;
        basic_write_and_close(&data).await;

        multiple_writes_then_close(&mut rng, &data[..(MIN as usize + 100)]).await;
        multiple_writes_then_close(&mut rng, &data).await;

        // Test converting from `MediumEncryptor`.
        let (data_map, storage) = {
            let storage = SimpleStorage::new();
            let mut medium_encryptor = unwrap!(SmallEncryptor::new(storage, vec![])
                .await
                .map(MediumEncryptor::from));

            medium_encryptor = unwrap!(medium_encryptor.write(&data[..(MIN as usize - 1)]).await);
            let mut large_encryptor = unwrap!(LargeEncryptor::from_medium(medium_encryptor).await);
            assert_eq!(large_encryptor.len(), MIN - 1);
            assert!(!large_encryptor.is_empty());
            large_encryptor = unwrap!(large_encryptor.write(&data[(MIN as usize - 1)..]).await);
            assert_eq!(large_encryptor.len(), data.len() as u64);
            assert!(!large_encryptor.is_empty());
            unwrap!(large_encryptor.close().await)
        };

        match data_map {
            DataMap::Chunks(ref chunks) => assert_eq!(chunks.len(), 5),
            _ => panic!("Wrong DataMap type returned."),
        }

        let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map));
        let fetched = unwrap!(self_encryptor.read(0, data.len() as u64).await);
        assert_eq!(Blob(&fetched), Blob(&data));
    }
}
