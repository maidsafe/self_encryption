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

use std::mem;

use data_map::DataMap;
use super::{SelfEncryptionError, Storage, StorageError, utils};
use super::large_encryptor::{self, LargeEncryptor};
use super::medium_encryptor::{self, MediumEncryptor};
use super::small_encryptor::SmallEncryptor;

enum StateMachine<'a, E: StorageError, S: 'a + Storage<E>> {
    Small(SmallEncryptor<'a, E, S>),
    Medium(MediumEncryptor<'a, E, S>),
    Large(LargeEncryptor<'a, E, S>),
    None,
}

impl<'a, E: StorageError, S: Storage<E>> StateMachine<'a, E, S> {
    fn write(&mut self, data: &[u8]) -> Result<(), SelfEncryptionError<E>> {
        match *self {
            StateMachine::Small(ref mut encryptor) => encryptor.write(data),
            StateMachine::Medium(ref mut encryptor) => encryptor.write(data),
            StateMachine::Large(ref mut encryptor) => encryptor.write(data),
            StateMachine::None => unreachable!(),
        }
    }

    fn close(&mut self) -> Result<DataMap, SelfEncryptionError<E>> {
        match *self {
            StateMachine::Small(ref mut encryptor) => encryptor.close(),
            StateMachine::Medium(ref mut encryptor) => encryptor.close(),
            StateMachine::Large(ref mut encryptor) => encryptor.close(),
            StateMachine::None => unreachable!(),
        }
    }

    fn len(&self) -> u64 {
        match *self {
            StateMachine::Small(ref encryptor) => encryptor.len(),
            StateMachine::Medium(ref encryptor) => encryptor.len(),
            StateMachine::Large(ref encryptor) => encryptor.len(),
            StateMachine::None => unreachable!(),
        }
    }

    fn is_empty(&self) -> bool {
        match *self {
            StateMachine::Small(ref encryptor) => encryptor.is_empty(),
            StateMachine::Medium(ref encryptor) => encryptor.is_empty(),
            StateMachine::Large(ref encryptor) => encryptor.is_empty(),
            StateMachine::None => unreachable!(),
        }
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
pub struct Encryptor<'a, E: StorageError, S: 'a + Storage<E>> {
    state: StateMachine<'a, E, S>,
}

impl<'a, E: StorageError, S: Storage<E>> Encryptor<'a, E, S> {
    /// Creates an `Encryptor`, using an existing `DataMap` if `data_map` is not `None`.
    pub fn new(storage: &'a mut S,
               data_map: Option<DataMap>)
               -> Result<Encryptor<'a, E, S>, SelfEncryptionError<E>> {
        utils::initialise_sodiumoxide();
        let state = match data_map {
            Some(DataMap::Content(content)) => {
                StateMachine::Small(SmallEncryptor::new(storage, content))
            }
            Some(data_map @ DataMap::Chunks(_)) => {
                let chunks = data_map.get_sorted_chunks();
                if chunks.len() == 3 {
                    StateMachine::Medium(try!(MediumEncryptor::new(storage, chunks)))
                } else {
                    StateMachine::Large(try!(LargeEncryptor::new(storage, chunks)))
                }
            }
            Some(DataMap::None) => panic!("Pass `None` rather than `DataMap::None`"),
            None => StateMachine::Small(SmallEncryptor::new(storage, vec![])),
        };
        Ok(Encryptor { state: state })
    }

    /// Buffers some or all of `data` and stores any completed chunks (i.e. those which cannot be
    /// modified by subsequent `write()` calls).  The internal buffers can only be flushed by
    /// calling `close()`.
    pub fn write(&mut self, data: &[u8]) -> Result<(), SelfEncryptionError<E>> {
        match self.state {
            StateMachine::Small(_) => {
                let new_len = self.state.len() + data.len() as u64;
                if new_len >= large_encryptor::MIN {
                    self.transition_to_large();
                } else if new_len >= medium_encryptor::MIN {
                    self.transition_to_medium();
                }
            }
            StateMachine::Medium(_) => {
                if self.state.len() + data.len() as u64 >= large_encryptor::MIN {
                    self.transition_to_large();
                }
            }
            StateMachine::Large(_) => (),
            StateMachine::None => unreachable!(),
        }
        self.state.write(data)
    }

    /// This finalises the encryptor - it should not be used again after this call.  Internal
    /// buffers are flushed, resulting in up to four chunks being stored.
    pub fn close(&mut self) -> Result<DataMap, SelfEncryptionError<E>> {
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

    fn transition_to_medium(&mut self) {
        let mut temp = StateMachine::None;
        mem::swap(&mut temp, &mut self.state);
        temp = match temp {
            StateMachine::Small(encryptor) => StateMachine::Medium(encryptor.into()),
            _ => unreachable!(),
        };
        mem::swap(&mut temp, &mut self.state);
    }

    fn transition_to_large(&mut self) {
        let mut temp = StateMachine::None;
        mem::swap(&mut temp, &mut self.state);
        temp = match temp {
            StateMachine::Small(encryptor) => StateMachine::Large(encryptor.into()),
            StateMachine::Medium(encryptor) => StateMachine::Large(encryptor.into()),
            _ => unreachable!(),
        };
        mem::swap(&mut temp, &mut self.state);
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    use data_map::DataMap;
    use itertools::Itertools;
    use maidsafe_utilities::SeededRng;
    use rand::Rng;
    use self_encryptor::SelfEncryptor;
    use super::super::*;
    use test_helpers::SimpleStorage;

    fn read(expected_data: &[u8], storage: &mut SimpleStorage, data_map: &DataMap) {
        let mut self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map.clone()));
        let fetched = unwrap!(self_encryptor.read(0, expected_data.len() as u64));
        assert!(fetched == expected_data);
    }

    fn write(data: &[u8],
             storage: &mut SimpleStorage,
             data_map: &mut DataMap,
             expected_len: usize) {
        let mut encryptor = unwrap!(Encryptor::new(storage, Some(data_map.clone())));
        unwrap!(encryptor.write(data));
        assert_eq!(encryptor.len(), expected_len as u64);
        *data_map = unwrap!(encryptor.close());
    }

    #[test]
    fn transitions() {
        let mut storage = SimpleStorage::new();
        let mut rng = SeededRng::new();
        let data = rng.gen_iter().take(4 * MAX_CHUNK_SIZE as usize + 1).collect_vec();

        let mut data_map;
        // Write 0 bytes.
        {
            let mut encryptor = unwrap!(Encryptor::new(&mut storage, None));
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            unwrap!(encryptor.write(&[]));
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            data_map = unwrap!(encryptor.close());
        }
        read(&[], &mut storage, &data_map);

        // Write 1 byte.
        let mut index_start = 0;
        let mut index_end = 1;
        write(&data[index_start..index_end],
              &mut storage,
              &mut data_map,
              index_end);
        read(&data[..index_end], &mut storage, &data_map);

        // Append as far as `small_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize;
        write(&data[index_start..index_end],
              &mut storage,
              &mut data_map,
              index_end);
        read(&data[..index_end], &mut storage, &data_map);

        // Append a further single byte.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize + 1;
        write(&data[index_start..index_end],
              &mut storage,
              &mut data_map,
              index_end);
        read(&data[..index_end], &mut storage, &data_map);

        // Append as far as `medium_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize;
        write(&data[index_start..index_end],
              &mut storage,
              &mut data_map,
              index_end);
        read(&data[..index_end], &mut storage, &data_map);

        // Append a further single byte.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize + 1;
        write(&data[index_start..index_end],
              &mut storage,
              &mut data_map,
              index_end);
        read(&data[..index_end], &mut storage, &data_map);

        // Append remaining bytes.
        index_start = index_end;
        index_end = data.len();
        write(&data[index_start..index_end],
              &mut storage,
              &mut data_map,
              index_end);
        read(&data[..index_end], &mut storage, &data_map);
    }
}
