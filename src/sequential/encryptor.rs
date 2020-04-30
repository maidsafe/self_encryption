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
use crate::data_map::DataMap;
use std::{
    // cell::Mutex,
    sync::{Arc, Mutex},
    fmt::{self, Debug},
    mem,
    // rc::Arc,
};
use unwrap::unwrap;

enum State<S: Storage + Send + Sync> {
    Small(SmallEncryptor<S>),
    Medium(MediumEncryptor<S>),
    Large(LargeEncryptor<S>),
    Transitioning,
}

impl<S> State<S>
where
    S: Storage + 'static + Send + Sync,
{
    async fn write(self, data: &[u8]) -> Result<Self, SelfEncryptionError<S::Error>> {
        match self {
            State::Small(encryptor) => encryptor.write(data).await.map(From::from),
            State::Medium(encryptor) => encryptor.write(data).await.map(From::from),
            State::Large(encryptor) => encryptor.write(data).await.map(From::from),
            State::Transitioning => unreachable!(),
        }
    }

    async fn close(self) -> Result<(DataMap, S), SelfEncryptionError<S::Error>> {
        match self {
            State::Small(encryptor) => encryptor.close().await,
            State::Medium(encryptor) => encryptor.close().await,
            State::Large(encryptor) => encryptor.close().await,
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

impl<S> From<SmallEncryptor<S>> for State<S> 
where
    S: Storage + 'static + Send + Sync,
    {
    fn from(e: SmallEncryptor<S>) -> Self {
        State::Small(e)
    }
}

impl<S> From<MediumEncryptor<S>> for State<S> 
where
    S: Storage + 'static + Send + Sync,{
    fn from(e: MediumEncryptor<S>) -> Self {
        State::Medium(e)
    }
}

impl<S> From<LargeEncryptor<S>> for State<S> 
where
    S: Storage + 'static + Send + Sync,{
    fn from(e: LargeEncryptor<S>) -> Self {
        State::Large(e)
    }
}

impl<S> Debug for State<S> 
where
    S: Storage + 'static + Send + Sync,{
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
// #[async_trait]
pub struct Encryptor<S: Storage + 'static + Send + Sync> 
// where
//     S: Storage + 'static + Send + Sync
    {
    state: Arc<Mutex<State<S>>>,
}

impl<S> Encryptor<S>
where
    S: Storage + 'static + Send + Sync,
{
    /// Creates an `Encryptor`, using an existing `DataMap` if `data_map` is not `None`.
    // TODO - split into two separate c'tors rather than passing optional `DataMap`.
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        storage: S,
        data_map: Option<DataMap>,
    ) -> Result<Encryptor<S>, SelfEncryptionError<S::Error>> {
        match data_map {
            Some(DataMap::Content(content)) => {
                let state = State::from(SmallEncryptor::new(storage, content).await?);
                Ok(Self::from(state))
            }
            Some(data_map @ DataMap::Chunks(_)) => {
                let chunks = data_map.get_sorted_chunks();
                if chunks.len() == 3 {
                    let state = State::from(MediumEncryptor::new(storage, chunks).await?);
                    Ok(Self::from(state))
                } else {
                    let state = State::from(LargeEncryptor::new(storage, chunks).await?);
                    Ok(Self::from(state))
                }
            }
            Some(DataMap::None) => panic!("Pass `None` rather than `DataMap::None`"),
            None => {
                let the_state = State::from(SmallEncryptor::new(storage, vec![]).await?);
                Ok(Self::from(the_state))
            }
        }
    }

    /// Buffers some or all of `data` and stores any completed chunks (i.e. those which cannot be
    /// modified by subsequent `write()` calls).  The internal buffers can only be flushed by
    /// calling `close()`.
    pub async fn write(&self, data: &[u8]) -> Result<(), SelfEncryptionError<S::Error>> {
        let curr_state = Arc::clone(&self.state);
        let prev_state = mem::replace(&mut *curr_state.lock().unwrap(), State::Transitioning);

        let next_state = match prev_state {
            State::Small(small) => {
                let new_len = small.len() + data.len() as u64;
                if new_len >= large_encryptor::MIN {
                    State::from(LargeEncryptor::from(small))
                } else if new_len >= medium_encryptor::MIN {
                    State::from(MediumEncryptor::from(small))
                } else {
                    State::from(small)
                }
            }
            State::Medium(medium) => {
                if medium.len() + data.len() as u64 >= large_encryptor::MIN {
                    State::from(LargeEncryptor::from_medium(medium).await?)
                } else {
                    State::from(medium)
                }
            }
            State::Large(large) => State::from(large),
            State::Transitioning => unreachable!(),
        };

        let data = data.to_vec();
        let next_state = next_state.write(&data).await?;

        *curr_state.lock().unwrap() = next_state;

        Ok(())
    }

    /// This finalises the encryptor - it should not be used again after this call.  Internal
    /// buffers are flushed, resulting in up to four chunks being stored.
    pub async fn close(self) -> Result<(DataMap, S), SelfEncryptionError<S::Error>> {
        let state = unwrap!(Arc::try_unwrap(self.state));
        let state = state.into_inner().map_err(|_| SelfEncryptionError::Generic("Error closing encryptor due to poisoned mutex".to_string()))?;
        state.close().await
    }

    /// Number of bytes of data written, including those handled by previous encryptors.
    ///
    /// E.g. if this encryptor was constructed with a `DataMap` whose `len()` yields 100, and it
    /// then handles a `write()` of 100 bytes, `len()` will return 200.
    pub fn len(&self) -> u64 {
        self.state.lock().unwrap().len()
    }

    /// Returns true if `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.state.lock().unwrap().is_empty()
    }
}

impl<S> From<State<S>> for Encryptor<S> 
where
    S: Storage + 'static + Send + Sync,
    {
    fn from(s: State<S>) -> Self {
        Encryptor {
            state: Arc::new(Mutex::new(s)),
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

    async fn read(
        expected_data: &[u8],
        storage: SimpleStorage,
        data_map: &DataMap,
    ) -> SimpleStorage {
        let self_encryptor = unwrap!(SelfEncryptor::new(storage, data_map.clone()));
        let fetched = unwrap!(self_encryptor.read(0, expected_data.len() as u64).await);
        assert_eq!(Blob(&fetched), Blob(expected_data));
        self_encryptor.into_storage()
    }

    async fn write(
        data: &[u8],
        storage: SimpleStorage,
        data_map: &mut DataMap,
        expected_len: usize,
    ) -> SimpleStorage {
        let encryptor = unwrap!(Encryptor::new(storage, Some(data_map.clone())).await);
        unwrap!(encryptor.write(data).await);
        assert_eq!(encryptor.len(), expected_len as u64);
        let (data_map2, storage) = unwrap!(encryptor.close().await);
        *data_map = data_map2;
        storage
    }

    #[tokio::test]
    async fn transitions() {
        let mut rng = new_test_rng();
        let data = random_bytes(&mut rng, 4 * MAX_CHUNK_SIZE as usize + 1);

        // Write 0 bytes.
        let (mut data_map, mut storage) = {
            let storage = SimpleStorage::new();
            let encryptor = unwrap!(Encryptor::new(storage, None).await);
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            unwrap!(encryptor.write(&[]).await);
            assert_eq!(encryptor.len(), 0);
            assert!(encryptor.is_empty());
            unwrap!(encryptor.close().await)
        };

        storage = read(&[], storage, &data_map).await;

        // Write 1 byte.
        let mut index_start = 0;
        let mut index_end = 1;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        )
        .await;
        storage = read(&data[..index_end], storage, &data_map).await;

        // Append as far as `small_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        )
        .await;
        storage = read(&data[..index_end], storage, &data_map).await;

        // Append a further single byte.
        index_start = index_end;
        index_end = small_encryptor::MAX as usize + 1;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        )
        .await;
        storage = read(&data[..index_end], storage, &data_map).await;

        // Append as far as `medium_encryptor::MAX` bytes.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        )
        .await;
        storage = read(&data[..index_end], storage, &data_map).await;

        // Append a further single byte.
        index_start = index_end;
        index_end = medium_encryptor::MAX as usize + 1;
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        )
        .await;
        storage = read(&data[..index_end], storage, &data_map).await;

        // Append remaining bytes.
        index_start = index_end;
        index_end = data.len();
        storage = write(
            &data[index_start..index_end],
            storage,
            &mut data_map,
            index_end,
        )
        .await;
        let _ = read(&data[..index_end], storage, &data_map);
    }
}
