// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(hidden)]

use super::{Storage, StorageError};

use async_trait::async_trait;

use rand::{self, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    cmp, env,
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    thread,
};
use tiny_keccak::sha3_256;
use unwrap::unwrap;

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

#[derive(Debug, Clone)]
pub struct SimpleStorageError;

impl Display for SimpleStorageError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Failed to get data from SimpleStorage")
    }
}

impl Error for SimpleStorageError {
    fn description(&self) -> &str {
        "SimpleStorage::get() error"
    }
}

impl StorageError for SimpleStorageError {}

struct Entry {
    name: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Default)]
pub struct SimpleStorage {
    entries: Vec<Entry>,
}

impl SimpleStorage {
    pub fn new() -> SimpleStorage {
        SimpleStorage { entries: vec![] }
    }

    pub fn has_chunk(&self, name: &[u8]) -> bool {
        self.entries.iter().any(|entry| entry.name == name)
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }
}

#[async_trait]
impl Storage for SimpleStorage {
    type Error = SimpleStorageError;

    async fn get(&self, name: &[u8]) -> Result<Vec<u8>, SimpleStorageError> {
        match self.entries.iter().find(|entry| entry.name == name) {
            Some(entry) => Ok(entry.data.clone()),
            None => Err(SimpleStorageError {}),
        }
    }

    async fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Result<(), SimpleStorageError> {
        self.entries.push(Entry { name, data });

        Ok(())
    }

    async fn generate_address(&self, data: &[u8]) -> Vec<u8> {
        sha3_256(data).to_vec()
    }
}

// Create new random number generator suitable for tests. To provide repeatable results, the seed
// can be overridden using the "SEED" env variable. If this variable is not provided, a random one
// is used (to support soak testing). The current seed is printed to stdout.
pub fn new_test_rng() -> TestRng {
    let seed = if let Ok(seed) = env::var("SEED") {
        unwrap!(seed.parse(), "SEED must contain a valid u64 value")
    } else {
        rand::thread_rng().gen()
    };

    println!(
        "RNG seed for thread {:?}: {}",
        unwrap!(thread::current().name()),
        seed
    );

    TestRng::seed_from_u64(seed)
}

pub fn from_rng(rng: &mut TestRng) -> TestRng {
    unwrap!(TestRng::from_rng(rng))
}

pub fn serialise<T: Serialize>(data: &T) -> Vec<u8> {
    unwrap!(bincode::serialize(data))
}

pub fn deserialise<T>(data: &[u8]) -> Option<T>
where
    T: Serialize + DeserializeOwned,
{
    bincode::deserialize(data).ok()
}

pub fn random_bytes<T: Rng>(rng: &mut T, size: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; size];
    rng.fill(bytes.as_mut_slice());
    bytes
}
