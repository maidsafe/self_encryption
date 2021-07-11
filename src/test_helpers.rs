// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(hidden)]

use super::Storage;
use crate::SelfEncryptionError;
use async_trait::async_trait;

use rand::{self, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
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
    name: Vec<u8>,
    data: Vec<u8>,
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

    pub async fn has_chunk(&self, name: &[u8]) -> Result<bool, SelfEncryptionError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| SelfEncryptionError::Poison)?
            .iter()
            .any(|entry| entry.name == name))
    }

    pub async fn num_entries(&self) -> Result<usize, SelfEncryptionError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| SelfEncryptionError::Poison)?
            .len())
    }
}

#[async_trait]
impl Storage for SimpleStorage {
    // type Error = SelfEncryptionError;

    async fn get(&mut self, name: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        match self
            .entries
            .read()
            .map_err(|_| SelfEncryptionError::Poison)?
            .iter()
            .find(|entry| entry.name == name)
        {
            Some(entry) => Ok(entry.data.clone()),
            None => Err(SelfEncryptionError::Storage(
                "Chunk missing in storage".into(),
            )),
        }
    }

    async fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> Result<(), SelfEncryptionError> {
        self.entries
            .write()
            .map_err(|_| SelfEncryptionError::Poison)?
            .push(Entry { name, data });

        Ok(())
    }

    async fn delete(&mut self, name: &[u8]) -> Result<(), SelfEncryptionError> {
        self.entries
            .write()
            .map_err(|_| SelfEncryptionError::Poison)?
            .retain(|entry| entry.name != name);

        Ok(())
    }

    async fn generate_address(&self, data: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        let mut hasher = Sha3::v256();
        let mut output = [0; 32];
        hasher.update(&data);
        hasher.finalize(&mut output);
        Ok(output.to_vec())
    }
}

// Create new random number generator suitable for tests. To provide repeatable results, the seed
// can be overridden using the "SEED" env variable. If this variable is not provided, a random one
// is used (to support soak testing). The current seed is printed to stdout.
pub fn new_test_rng() -> Result<TestRng, SelfEncryptionError> {
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

pub fn from_rng(rng: &mut TestRng) -> Result<TestRng, SelfEncryptionError> {
    Ok(TestRng::from_rng(rng)?)
}

pub fn serialise<T: Serialize>(data: &T) -> Result<Vec<u8>, SelfEncryptionError> {
    Ok(bincode::serialize(data)?)
}

pub fn deserialise<T>(data: &[u8]) -> Result<T, SelfEncryptionError>
where
    T: Serialize + DeserializeOwned,
{
    match bincode::deserialize(data) {
        Ok(data) => Ok(data),
        Err(_) => Err(SelfEncryptionError::Deserialise),
    }
}

pub fn random_bytes<T: Rng>(rng: &mut T, size: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; size];
    rng.fill(bytes.as_mut_slice());
    bytes
}
