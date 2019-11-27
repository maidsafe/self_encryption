// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    large_encryptor::{self, LargeEncryptor},
    medium_encryptor::{self, MediumEncryptor},
    small_encryptor::SmallEncryptor,
    SelfEncryptionError, Storage,
};
use crate::{
    data_map::DataMap,
    util::{BoxFuture, FutureExt},
};
use futures::{future, Future};
use std::{
    cell::RefCell,
    fmt::{self, Debug},
    mem,
    rc::Rc,
};
use unwrap::unwrap;

enum State<S> {
    Small(SmallEncryptor<S>),
    Medium(MediumEncryptor<S>),
    Large(LargeEncryptor<S>),
    Transitioning,
}

impl<S> State<S>
where
    S: Storage + 'static,
{
    fn write(self, data: &[u8]) -> BoxFuture<Self, SelfEncryptionError<S::Error>> {
        match self {
            State::Small(encryptor) => encryptor.write(data).map(From::from).into_box(),
            State::Medium(encryptor) => encryptor.write(data).map(From::from).into_box(),
            State::Large(encryptor) => encryptor.write(data).map(From::from).into_box(),
            State::Transitioning => unreachable!(),
        }
    }

    fn close(self) -> BoxFuture<(DataMap, S), SelfEncryptionError<S::Error>> {
        match self {
            State::Small(encryptor) => encryptor.close(),
            State::Medium(encryptor) => encryptor.close(),
            State::Large(encryptor) => encryptor.close(),
            State::Transitioning => unreachable!(),
        }
    }

    fn len(&self) -> u64 {
        match *self {
            State::Small(ref encryptor) => encryptor.len(),
            State::Medium(ref encryptor) => encryptor.len(),
            State::Large(ref encryptor) => encryptor.len(),
            State::Transitioning => unreachable!(),
        }
    }

    fn is_empty(&self) -> bool {
        match *self {
            State::Small(ref encryptor) => encryptor.is_empty(),
            State::Medium(ref encryptor) => encryptor.is_empty(),
            State::Large(ref encryptor) => encryptor.is_empty(),
            State::Transitioning => unreachable!(),
        }
    }
}

impl<S> From<SmallEncryptor<S>> for State<S> {
    fn from(e: SmallEncryptor<S>) -> Self {
        State::Small(e)
    }
}

impl<S> From<MediumEncryptor<S>> for State<S> {
    fn from(e: MediumEncryptor<S>) -> Self {
        State::Medium(e)
    }
}

impl<S> From<LargeEncryptor<S>> for State<S> {
    fn from(e: LargeEncryptor<S>) -> Self {
        State::Large(e)
    }
}

impl<S> Debug for State<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "SequentialEncryptor internal state")
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
    state: Rc<RefCell<State<S>>>,
}

impl<S> Encryptor<S>
where
    S: Storage + 'static,
{
    /// Creates an `Encryptor`, using an existing `DataMap` if `data_map` is not `None`.
    // TODO - split into two separate c'tors rather than passing optional `DataMap`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        storage: S,
        data_map: Option<DataMap>,
    ) -> BoxFuture<Encryptor<S>, SelfEncryptionError<S::Error>> {
        match data_map {
            Some(DataMap::Content(content)) => SmallEncryptor::new(storage, content)
                .map(State::from)
                .map(Self::from)
                .into_box(),
            Some(data_map @ DataMap::Chunks(_)) => {
                let chunks = data_map.get_sorted_chunks();
                if chunks.len() == 3 {
                    MediumEncryptor::new(storage, chunks)
                        .map(State::from)
                        .map(Self::from)
                        .into_box()
                } else {
                    LargeEncryptor::new(storage, chunks)
                        .map(State::from)
                        .map(Self::from)
                        .into_box()
                }
            }
            Some(DataMap::None) => panic!("Pass `None` rather than `DataMap::None`"),
            None => SmallEncryptor::new(storage, vec![])
                .map(State::from)
                .map(Self::from)
                .into_box(),
        }
    }

    /// Buffers some or all of `data` and stores any completed chunks (i.e. those which cannot be
    /// modified by subsequent `write()` calls).  The internal buffers can only be flushed by
    /// calling `close()`.
    pub fn write(&self, data: &[u8]) -> BoxFuture<(), SelfEncryptionError<S::Error>> {
        let curr_state = Rc::clone(&self.state);
        let prev_state = mem::replace(&mut *curr_state.borrow_mut(), State::Transitioning);

        let future = match prev_state {
            State::Small(small) => {
                let new_len = small.len() + data.len() as u64;
                let new_state = if new_len >= large_encryptor::MIN {
                    State::from(LargeEncryptor::from(small))
                } else if new_len >= medium_encryptor::MIN {
                    State::from(MediumEncryptor::from(small))
                } else {
                    State::from(small)
                };

                future::ok(new_state).into_box()
            }
            State::Medium(medium) => {
                if medium.len() + data.len() as u64 >= large_encryptor::MIN {
                    LargeEncryptor::from_medium(medium)
                        .map(State::from)
                        .into_box()
                } else {
                    future::ok(State::from(medium)).into_box()
                }
            }
            State::Large(large) => future::ok(State::from(large)).into_box(),
            State::Transitioning => unreachable!(),
        };

        let data = data.to_vec();
        future
            .and_then(move |next_state| next_state.write(&data))
            .map(move |next_state| {
                *curr_state.borrow_mut() = next_state;
            })
            .into_box()
    }

    /// This finalises the encryptor - it should not be used again after this call.  Internal
    /// buffers are flushed, resulting in up to four chunks being stored.
    pub fn close(self) -> BoxFuture<(DataMap, S), SelfEncryptionError<S::Error>> {
        let state = unwrap!(Rc::try_unwrap(self.state));
        let state = state.into_inner();
        state.close()
    }

    /// Number of bytes of data written, including those handled by previous encryptors.
    ///
    /// E.g. if this encryptor was constructed with a `DataMap` whose `len()` yields 100, and it
    /// then handles a `write()` of 100 bytes, `len()` will return 200.
    pub fn len(&self) -> u64 {
        self.state.borrow().len()
    }

    /// Returns true if `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.state.borrow().is_empty()
    }
}

impl<S> From<State<S>> for Encryptor<S> {
    fn from(s: State<S>) -> Self {
        Encryptor {
            state: Rc::new(RefCell::new(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::*, *};
    use crate::{
        data_map::DataMap,
        self_encryptor::SelfEncryptor,
        test_helpers::{new_test_rng, random_bytes, Blob, SimpleStorage},
    };
    use futures::Future;

    fn read(expected_data: &[u8], storage: SimpleStorage, data_map: &DataMap) -> SimpleStorage {
        let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map.clone()));
        let fetched = unwrap!(self_encryptor.read(0, expected_data.len() as u64).wait());
        assert_eq!(Blob(&fetched), Blob(expected_data));
        self_encryptor.into_storage()
    }

    fn write(
        data: &[u8],
        storage: SimpleStorage,
        data_map: &mut DataMap,
        expected_len: usize,
    ) -> SimpleStorage {
        let encryptor = unwrap!(Encryptor::new(storage, Some(data_map.clone())).wait());
        unwrap!(encryptor.write(data).wait());
        assert_eq!(encryptor.len(), expected_len as u64);
        let (data_map2, storage) = unwrap!(encryptor.close().wait());
        *data_map = data_map2;
        storage
    }

    #[test]
    fn transitions() {
        let mut rng = new_test_rng();
        let data = random_bytes(&mut rng, 4 * MAX_CHUNK_SIZE as usize + 1);

        // Write 0 bytes.
        let (mut data_map, mut storage) = {
            let storage = SimpleStorage::new();
            let encryptor = unwrap!(Encryptor::new(storage, None).wait());
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            unwrap!(encryptor.write(&[]).wait());
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            unwrap!(encryptor.close().wait())
        };

        storage = read(&[], storage, &data_map);

        // Write 1 byte.
        let mut index_start = 0;
        let mut index_end = 1;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        );
        storage = read(&data[..index_end], storage, &data_map);

        // Append as far as `small_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        );
        storage = read(&data[..index_end], storage, &data_map);

        // Append a further single byte.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize + 1;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        );
        storage = read(&data[..index_end], storage, &data_map);

        // Append as far as `medium_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        );
        storage = read(&data[..index_end], storage, &data_map);

        // Append a further single byte.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize + 1;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        );
        storage = read(&data[..index_end], storage, &data_map);

        // Append remaining bytes.
        index_start = index_end;
        index_end = data.len();
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        );
        let _ = read(&data[..index_end], storage, &data_map);
    }
}
