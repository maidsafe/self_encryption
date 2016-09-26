// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.


use data_map::DataMap;
use futures::{self, BoxFuture, Future};
use super::{SelfEncryptionError, Storage, utils};
use super::large_encryptor::{self, LargeEncryptor};
use super::medium_encryptor::{self, MediumEncryptor};
use super::small_encryptor::SmallEncryptor;

enum StateMachine<S> {
    Small(SmallEncryptor<S>),
    Medium(MediumEncryptor<S>),
    Large(LargeEncryptor<S>),
}

impl<S> StateMachine<S> where S: Storage + Send + 'static,
                              S::Error: Send
{
    fn write(self, data: &[u8]) -> BoxFuture<Self, SelfEncryptionError<S::Error>> {
        match self {
            StateMachine::Small(encryptor) => encryptor.write(data).map(From::from).boxed(),
            StateMachine::Medium(encryptor) => encryptor.write(data).map(From::from).boxed(),
            StateMachine::Large(encryptor) => encryptor.write(data).map(From::from).boxed(),
        }
    }

    fn close(self) -> BoxFuture<(DataMap, S), SelfEncryptionError<S::Error>> {
        match self {
            StateMachine::Small(encryptor) => encryptor.close(),
            StateMachine::Medium(encryptor) => encryptor.close(),
            StateMachine::Large(encryptor) => encryptor.close(),
        }
    }

    fn len(&self) -> u64 {
        match *self {
            StateMachine::Small(ref encryptor) => encryptor.len(),
            StateMachine::Medium(ref encryptor) => encryptor.len(),
            StateMachine::Large(ref encryptor) => encryptor.len(),
        }
    }

    fn is_empty(&self) -> bool {
        match *self {
            StateMachine::Small(ref encryptor) => encryptor.is_empty(),
            StateMachine::Medium(ref encryptor) => encryptor.is_empty(),
            StateMachine::Large(ref encryptor) => encryptor.is_empty(),
        }
    }
}

impl<S> From<SmallEncryptor<S>> for StateMachine<S> {
    fn from(e: SmallEncryptor<S>) -> Self {
        StateMachine::Small(e)
    }
}

impl<S> From<MediumEncryptor<S>> for StateMachine<S> {
    fn from(e: MediumEncryptor<S>) -> Self {
        StateMachine::Medium(e)
    }
}

impl<S> From<LargeEncryptor<S>> for StateMachine<S> {
    fn from(e: LargeEncryptor<S>) -> Self {
        StateMachine::Large(e)
    }
}

/// An encryptor which only permits sequential writes, i.e. there is no ability to specify an offset
/// in the `write()` call; all data is appended sequentially.
///
/// The resulting chunks and `DataMap` are identical to those which would have been produced by a
/// [`SelfEncryptor`](struct.SelfEncryptor.html).
///
/// This encryptor differs from `SelfEncryptor` in that completed chunks will be stored during
/// `write()` calls as opposed to buffering all data until the `close()` call.  This should give
/// more realistic feedback about the progress of fully self-encrypting larger data.
///
/// A further difference is that since the entire data is not held in an internal buffer, this
/// encryptor doesn't need to limit the input data size, i.e. `MAX_FILE_SIZE` does not apply to this
/// encryptor.  (Note that as of writing, there is no way to decrypt data which exceeds this size,
/// since the only decryptor available is `SelfEncryptor`, and this _does_ limit the data size to
/// `MAX_FILE_SIZE`.)
///
/// Due to the reduced complexity, a side effect is that this encryptor outperforms `SelfEncryptor`,
/// particularly for small data (below `MIN_CHUNK_SIZE * 3` bytes) where no chunks are generated.
pub struct Encryptor<S> {
    state: StateMachine<S>,
}

impl<S> Encryptor<S> where S: Storage + Send + 'static,
                           S::Error: Send
{
    /// Creates an `Encryptor`, using an existing `DataMap` if `data_map` is not `None`.
    // TODO - split into two separate c'tors rather than passing optional `DataMap`.
    pub fn new(storage: S, data_map: Option<DataMap>)
               -> BoxFuture<Encryptor<S>, SelfEncryptionError<S::Error>> {
        utils::initialise_rust_sodium();
        match data_map {
            Some(DataMap::Content(content)) => {
                SmallEncryptor::new(storage, content)
                               .map(StateMachine::from)
                               .map(Self::from)
                               .boxed()
            }
            Some(data_map @ DataMap::Chunks(_)) => {
                let chunks = data_map.get_sorted_chunks();
                if chunks.len() == 3 {
                    MediumEncryptor::new(storage, chunks)
                                    .map(StateMachine::from)
                                    .map(Self::from)
                                    .boxed()
                } else {
                    LargeEncryptor::new(storage, chunks)
                                   .map(StateMachine::from)
                                   .map(Self::from)
                                   .boxed()
                }
            }
            Some(DataMap::None) => panic!("Pass `None` rather than `DataMap::None`"),
            None => SmallEncryptor::new(storage, vec![])
                                   .map(StateMachine::from)
                                   .map(Self::from)
                                   .boxed()
        }
    }

    /// Buffers some or all of `data` and stores any completed chunks (i.e. those which cannot be
    /// modified by subsequent `write()` calls).  The internal buffers can only be flushed by
    /// calling `close()`.
    pub fn write(self, data: &[u8]) -> BoxFuture<Self, SelfEncryptionError<S::Error>> {
        let future_new_state = match self.state {
            StateMachine::Small(small) => {
                let new_len = small.len() + data.len() as u64;
                let new_state = if new_len >= large_encryptor::MIN {
                    StateMachine::from(LargeEncryptor::from(small))
                } else if new_len >= medium_encryptor::MIN {
                    StateMachine::from(MediumEncryptor::from(small))
                } else {
                    StateMachine::from(small)
                };

                futures::finished(new_state).boxed()
            }
            StateMachine::Medium(medium) => {
                if medium.len() + data.len() as u64 >= large_encryptor::MIN {
                    LargeEncryptor::from_medium(medium)
                                   .map(StateMachine::from)
                                   .boxed()
                } else {
                    futures::finished(StateMachine::from(medium)).boxed()
                }
            }
            StateMachine::Large(large) => {
                futures::finished(StateMachine::from(large)).boxed()
            }
        };

        let data = data.to_vec();
        future_new_state.and_then(move |state| state.write(&data))
                        .map(Self::from)
                        .boxed()
    }

    /// This finalises the encryptor - it should not be used again after this call.  Internal
    /// buffers are flushed, resulting in up to four chunks being stored.
    pub fn close(self) -> BoxFuture<(DataMap, S), SelfEncryptionError<S::Error>> {
        self.state.close()
    }

    /// Number of bytes of data written, including those handled by previous encryptors.
    ///
    /// E.g. if this encryptor was constructed with a `DataMap` whose `len()` yields 100, and it
    /// then handles a `write()` of 100 bytes, `len()` will return 200.
    pub fn len(&self) -> u64 {
        self.state.len()
    }

    /// Returns true if `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

impl<S> From<StateMachine<S>> for Encryptor<S> {
    fn from(s: StateMachine<S>) -> Self {
        Encryptor {
            state: s,
        }
    }
}

#[cfg(test)]
mod tests {
    use data_map::DataMap;
    use futures::Future;
    use itertools::Itertools;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    use self_encryptor::SelfEncryptor;
    use super::*;
    use super::super::*;
    use test_helpers::SimpleStorage;

    fn read(expected_data: &[u8], storage: SimpleStorage, data_map: &DataMap) -> SimpleStorage {
        let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map.clone()));
        let fetched = unwrap!(self_encryptor.read(0, expected_data.len() as u64).wait());
        assert!(fetched == expected_data);
        self_encryptor.into_storage()
    }

    fn write(data: &[u8],
             storage: SimpleStorage,
             data_map: &mut DataMap,
             expected_len: usize)
             -> SimpleStorage {
        let mut encryptor = unwrap!(Encryptor::new(storage, Some(data_map.clone())).wait());
        encryptor = unwrap!(encryptor.write(data).wait());
        assert_eq!(encryptor.len(), expected_len as u64);
        let (data_map2, storage) = unwrap!(encryptor.close().wait());
        *data_map = data_map2;
        storage
    }

    #[test]
    fn transitions() {
        let mut rng = SeededRng::new();
        let data = rng.gen_iter().take(4 * MAX_CHUNK_SIZE as usize + 1).collect_vec();

        // Write 0 bytes.
        let (mut data_map, mut storage) = {
            let storage = SimpleStorage::new();
            let mut encryptor = unwrap!(Encryptor::new(storage, None).wait());
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            encryptor = unwrap!(encryptor.write(&[]).wait());
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            unwrap!(encryptor.close().wait())
        };

        storage = read(&[], storage, &data_map);

        // Write 1 byte.
        let mut index_start = 0;
        let mut index_end = 1;
        storage = write(&data[index_start..index_end],
                        storage,
                        &mut data_map,
                        index_end);
        storage = read(&data[..index_end], storage, &data_map);

        // Append as far as `small_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize;
        storage = write(&data[index_start..index_end],
                        storage,
                        &mut data_map,
                        index_end);
        storage = read(&data[..index_end], storage, &data_map);

        // Append a further single byte.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize + 1;
        storage = write(&data[index_start..index_end],
                        storage,
                        &mut data_map,
                        index_end);
        storage = read(&data[..index_end], storage, &data_map);

        // Append as far as `medium_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize;
        storage = write(&data[index_start..index_end],
                        storage,
                        &mut data_map,
                        index_end);
        storage = read(&data[..index_end], storage, &data_map);

        // Append a further single byte.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize + 1;
        storage = write(&data[index_start..index_end],
                        storage,
                        &mut data_map,
                        index_end);
        storage = read(&data[..index_end], storage, &data_map);

        // Append remaining bytes.
        index_start = index_end;
        index_end = data.len();
        storage = write(&data[index_start..index_end],
                        storage,
                        &mut data_map,
                        index_end);
        let _ = read(&data[..index_end], storage, &data_map);
    }
}
