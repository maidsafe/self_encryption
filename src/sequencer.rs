// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::MAX_FILE_SIZE;
use memmap::MmapMut;
use std::io::Error as IoError;
use std::io::Write;
use std::ops::{Deref, DerefMut, Index, IndexMut};

pub const MAX_IN_MEMORY_SIZE: usize = 50 * 1024 * 1024;

enum Data {
    Vector(Vec<u8>),
    Mmap(MmapMut),
}

/// Optionally create a sequence of bytes via a vector or memory map.
pub struct Sequencer {
    data: Data,
}

#[cfg_attr(feature = "cargo-clippy", allow(len_without_is_empty))]
impl Sequencer {
    /// Initialise as a vector.
    pub fn new_as_vector() -> Sequencer {
        Sequencer { data: Data::Vector(Vec::with_capacity(MAX_IN_MEMORY_SIZE)) }
    }

    /// Initialise as a memory map
    pub fn new_as_mmap() -> Result<Sequencer, IoError> {
        Ok(Sequencer {
            data: Data::Mmap(MmapMut::map_anon(MAX_FILE_SIZE)?),
        })
    }

    /// Return the current length of the sequencer.
    pub fn len(&self) -> usize {
        match self.data {
            Data::Vector(ref vector) => vector.len(),
            Data::Mmap(ref mmap) => mmap.len(),
        }
    }

    /// Initialise with the Sequencer with 'content'.
    pub fn init(&mut self, content: &[u8]) -> Result<(), IoError> {
        match self.data {
            Data::Vector(ref mut vector) => {
                vector.extend_from_slice(content);
                Ok(())
            }
            Data::Mmap(ref mut mmap) => (&mut mmap[..]).write_all(&content[..]),
        }
    }

    /// Truncate internal object to given size. Note that this affects the vector only since the
    /// memory map is a fixed size.
    pub fn truncate(&mut self, size: usize) {
        if let Data::Vector(ref mut vector) = self.data {
            vector.truncate(size);
        }
    }

    /// Create a memory map if we haven't already done so.
    pub fn create_mapping(&mut self) -> Result<(), IoError> {
        self.data = match self.data {
            Data::Mmap(_) => return Ok(()),
            Data::Vector(ref mut vector) => {
                let mut mmap = MmapMut::map_anon(MAX_FILE_SIZE)?;
                (&mut mmap[..]).write_all(&vector[..])?;
                Data::Mmap(mmap)
            }
        };
        Ok(())
    }
}

impl Index<usize> for Sequencer {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        match self.data {
            Data::Vector(ref vector) => &vector[index],
            Data::Mmap(ref mmap) => &mmap[index],
        }
    }
}

impl IndexMut<usize> for Sequencer {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        match self.data {
            Data::Vector(ref mut vector) => &mut vector[index],
            Data::Mmap(ref mut mmap) => &mut mmap[index],
        }
    }
}

impl Deref for Sequencer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self.data {
            Data::Vector(ref vector) => &*vector,
            Data::Mmap(ref mmap) => &*mmap,
        }
    }
}

impl DerefMut for Sequencer {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self.data {
            Data::Vector(ref mut vector) => &mut *vector,
            Data::Mmap(ref mut mmap) => &mut *mmap,
        }
    }
}

impl Extend<u8> for Sequencer {
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = u8>,
    {
        if let Data::Vector(ref mut vector) = self.data {
            vector.extend(iterable);
        }
    }
}
