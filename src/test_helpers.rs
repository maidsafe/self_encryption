// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(hidden)]

use crate::{ChunkInfo, DataMap, Error};

use bytes::Bytes;
use rand::{self, rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::current_num_threads;
use serde::{de::DeserializeOwned, Serialize};
use std::env;

pub type TestRng = ChaChaRng;

// Create new random number generator suitable for tests. To provide repeatable results, the seed
// can be overridden using the "SEED" env variable. If this variable is not provided, a random one
// is used (to support soak testing). The current seed is printed to stdout.
pub fn new_test_rng() -> Result<TestRng, Error> {
    let seed = if let Ok(seed) = env::var("SEED") {
        seed.parse()?
    } else {
        rand::thread_rng().gen()
    };

    Ok(TestRng::seed_from_u64(seed))
}

pub fn from_rng(rng: &mut TestRng) -> Result<TestRng, Error> {
    Ok(TestRng::from_rng(rng)?)
}

pub fn serialise<T: Serialize>(data: &T) -> Result<Vec<u8>, Error> {
    Ok(bincode::serialize(data)?)
}

pub fn deserialise<T>(data: &[u8]) -> Result<T, Error>
where
    T: Serialize + DeserializeOwned,
{
    match bincode::deserialize(data) {
        Ok(data) => Ok(data),
        Err(_) => Err(Error::Deserialise),
    }
}

/// Generates random bytes using provided `size`.
pub fn random_bytes(size: usize) -> Bytes {
    use rayon::prelude::*;
    let threads = current_num_threads();

    if threads > size {
        let mut rng = OsRng;
        return ::std::iter::repeat(())
            .map(|()| rng.gen::<u8>())
            .take(size)
            .collect();
    }

    let per_thread = size / threads;
    let remainder = size % threads;

    let mut bytes: Vec<u8> = (0..threads)
        .par_bridge()
        .map(|_| vec![0u8; per_thread])
        .map(|mut bytes| {
            let bytes = bytes.as_mut_slice();
            rand::thread_rng().fill(bytes);
            bytes.to_owned()
        })
        .flatten()
        .collect();

    bytes.extend(vec![0u8; remainder]);

    Bytes::from(bytes)
}

pub fn create_test_data_map(chunks: Vec<ChunkInfo>) -> DataMap {
    DataMap::new(chunks)
}

pub fn create_test_data_map_with_child(chunks: Vec<ChunkInfo>, child: usize) -> DataMap {
    DataMap::with_child(chunks, child)
}
