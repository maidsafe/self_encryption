// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(hidden)]

use super::Storage;
use crate::Error;
use async_trait::async_trait;

use bytes::Bytes;
use rand::{self, rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::current_num_threads;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    cmp, env,
    fmt::{self, Debug, Formatter},
    sync::{Arc, RwLock},
};
use tiny_keccak::{Hasher, Sha3};

pub type TestRng = ChaChaRng;

#[derive(PartialEq, Eq)]
pub struct Blob<'a>(pub &'a [u8]);

impl<'a> Debug for Blob<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in self.0[..cmp::min(self.0.len(), 4)].iter() {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "..")?;
        for byte in self.0[cmp::max(4, self.0.len()) - 4..].iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Entry {
    name: Bytes,
    data: Bytes,
}

#[derive(Default, Clone)]
pub struct SimpleStorage {
    entries: Arc<RwLock<Vec<Entry>>>,
}

impl SimpleStorage {
    pub fn new() -> SimpleStorage {
        SimpleStorage {
            entries: Arc::new(RwLock::new(vec![])),
        }
    }

    pub async fn has_chunk(&self, name: &[u8]) -> Result<bool, Error> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::Poison)?
            .iter()
            .any(|entry| entry.name == name))
    }

    pub async fn num_entries(&self) -> Result<usize, Error> {
        Ok(self.entries.read().map_err(|_| Error::Poison)?.len())
    }
}

#[async_trait]
impl Storage for SimpleStorage {
    // type Error = Error;

    async fn get(&self, name: Bytes) -> Result<Bytes, Error> {
        match self
            .entries
            .read()
            .map_err(|_| Error::Poison)?
            .iter()
            .find(|entry| entry.name == name)
        {
            Some(entry) => Ok(entry.data.clone()),
            None => Err(Error::Storage("Chunk missing in storage".into())),
        }
    }

    async fn put(&self, name: Bytes, data: Bytes) -> Result<(), Error> {
        self.entries
            .write()
            .map_err(|_| Error::Poison)?
            .push(Entry { name, data });

        Ok(())
    }

    async fn delete(&self, name: Bytes) -> Result<(), Error> {
        self.entries
            .write()
            .map_err(|_| Error::Poison)?
            .retain(|entry| entry.name != name);

        Ok(())
    }

    async fn generate_address(&self, data: Bytes) -> Result<Bytes, Error> {
        let mut hasher = Sha3::v256();
        let mut output = [0; 32];
        hasher.update(data.as_ref());
        hasher.finalize(&mut output);
        Ok(Bytes::from(output.to_vec()))
    }
}

// Create new random number generator suitable for tests. To provide repeatable results, the seed
// can be overridden using the "SEED" env variable. If this variable is not provided, a random one
// is used (to support soak testing). The current seed is printed to stdout.
pub fn new_test_rng() -> Result<TestRng, Error> {
    let seed = if let Ok(seed) = env::var("SEED") {
        seed.parse()?
    } else {
        rand::thread_rng().gen()
    };

    // println!(
    //     "RNG seed for thread {:?}: {}",
    //     thread::current().name().unwrap(),
    //     seed
    // );

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
pub fn random_bytes(size: usize) -> Vec<u8> {
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

    bytes
}
