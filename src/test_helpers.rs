// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(hidden)]

use super::{Storage, StorageError};
use futures::future;
use std::cmp;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use util::{FutureExt, BoxFuture};

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

impl Storage for SimpleStorage {
    type Error = SimpleStorageError;

    fn get(&self, name: &[u8]) -> BoxFuture<Vec<u8>, SimpleStorageError> {
        let result = match self.entries.iter().find(|entry| entry.name == name) {
            Some(entry) => Ok(entry.data.clone()),
            None => Err(SimpleStorageError {}),
        };

        future::result(result).into_box()
    }

    fn put(&mut self, name: Vec<u8>, data: Vec<u8>) -> BoxFuture<(), SimpleStorageError> {
        self.entries.push(Entry {
            name,
            data,
        });

        future::ok(()).into_box()
    }
}
