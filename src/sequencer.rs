// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::ops::{Deref, DerefMut, Index, IndexMut};

pub struct Sequencer {
    data: Vec<u8>,
}

#[allow(clippy::len_without_is_empty)]
impl Sequencer {
    pub fn new() -> Sequencer {
        Sequencer { data: Vec::new() }
    }

    /// Return the current length of the sequencer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Initialise with the Sequencer with 'content'.
    pub fn init(&mut self, content: &[u8]) {
        self.data.extend_from_slice(content);
    }

    /// Truncate internal object to given size.
    pub fn truncate(&mut self, size: usize) {
        self.data.truncate(size);
    }
}

impl Index<usize> for Sequencer {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        &self.data[index]
    }
}

impl IndexMut<usize> for Sequencer {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        &mut self.data[index]
    }
}

impl Deref for Sequencer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &*self.data
    }
}

impl DerefMut for Sequencer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut *self.data
    }
}

impl Extend<u8> for Sequencer {
    fn extend<I>(&mut self, iterable: I)
    where
        I: IntoIterator<Item = u8>,
    {
        self.data.extend(iterable);
    }
}
