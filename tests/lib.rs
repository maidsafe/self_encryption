// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the Safe Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

extern crate self_encryption;
extern crate rand;
extern crate tempdir;
pub use self_encryption::*;
use rand::{thread_rng, Rng};
use std::sync::{Arc,Mutex};

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes : Vec<u8> = Vec::with_capacity(length);
    for _ in (0..length) {
        bytes.push(rand::random::<u8>());
    }
    bytes
}

const DATA_SIZE : u64 = 20 * 1024 * 1024;

pub struct Entry {
    name: Vec<u8>,
    data: Vec<u8>
}

pub struct MyStorage {
    entries: Arc<Mutex<Vec<Entry>>>
}

impl MyStorage {
    pub fn new() -> MyStorage {
        MyStorage { entries: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn has_chunk(&self, name: Vec<u8>) -> bool {
        let lock = self.entries.lock().unwrap();
        for entry in lock.iter() {
            if entry.name == name { return true }
        }
        false
    }
}

impl Storage for MyStorage {
    fn get(&self, name: Vec<u8>) -> Vec<u8> {
        let lock = self.entries.lock().unwrap();
        for entry in lock.iter() {
            if entry.name == name { return entry.data.to_vec() }
        }
        vec![]
    }

    fn put(&self, name: Vec<u8>, data: Vec<u8>) {
        let mut lock = self.entries.lock().unwrap();
        lock.push(Entry { name : name, data : data })
    }
}


#[test]
fn new_read() {
    let read_size : usize = 4096;
    let mut read_position : usize = 0;
    let content_len : usize = 4 * MAX_CHUNK_SIZE as usize;
    let my_storage = Arc::new(MyStorage::new());
    let original = random_bytes(content_len);
    {
        let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
        se.write(&original, 0);
        {
            let decrypted = se.read(read_position as u64, read_size as u64);
            assert_eq!(original[read_position..(read_position+read_size)].to_vec(),
                       decrypted);

            // read next small part
            read_position += read_size;
            let decrypted = se.read(read_position as u64, read_size as u64);
            assert_eq!(original[read_position ..(read_position+read_size)].to_vec(),
                       decrypted);

            // try to read from end of file, moving the sliding window
            read_position = content_len - 3 * read_size;
            let decrypted = se.read(read_position as u64, read_size as u64);
            assert_eq!(original[read_position ..(read_position+read_size)].to_vec(),
                       decrypted);

            // read again at beginning of file
            read_position = 5usize;
            let decrypted = se.read(read_position as u64, read_size as u64);
            assert_eq!(original[read_position ..(read_position+read_size)].to_vec(),
                       decrypted);

        }

        { // Finish with many small reads
            let mut decrypted : Vec<u8> = Vec::with_capacity(content_len);
            read_position = 0usize;
            for _ in 0..15 {
                decrypted.extend(se.read(read_position as u64, read_size as
                u64).iter().map(|&x| x));
                assert_eq!(original[0..(read_position+read_size)].to_vec(),
                           decrypted);
                read_position += read_size;
            }
        }
        se.close();
    }
}

#[test]
fn write_random_sizes_at_random_positions() {
    let mut rng = thread_rng();
    let my_storage = Arc::new(MyStorage::new());
    let max_broken_size : u64 = 20 * 1024;
    let original = random_bytes(DATA_SIZE as usize);
    // estimate number of broken pieces, not known in advance
    let mut broken_data : Vec<(u64, &[u8])> =
          Vec::with_capacity((DATA_SIZE / max_broken_size) as usize);

    let mut offset : u64 = 0;
    let mut last_piece : u64 = 0;
    while offset < DATA_SIZE {
        let size : u64;
        if DATA_SIZE - offset < max_broken_size {
            size = DATA_SIZE - offset;
            last_piece = offset;
        } else {
            size = rand::random::<u64>() % max_broken_size;
        }
        let piece : (u64, &[u8]) = (offset,
              &original[offset as usize..(offset + size) as usize]);
        broken_data.push(piece);
        offset += size;
    }

    {
        let slice_broken_data = &mut broken_data[..];
        rng.shuffle(slice_broken_data);
    }

    match broken_data.iter()
                     .filter(|&x| x.0 != last_piece)
                     .last() {
        None => panic!("Should never occur. Error in test itself."),
        Some(overlap) => {
            let mut extra : Vec<u8> = overlap.1.to_vec();
            extra.extend(random_bytes(7usize)[..].iter().map(|&x| x));
            let post_overlap : (u64, &[u8]) = (overlap.0, &mut extra[..]);
            let post_position: u64 = overlap.0 + overlap.1.len() as u64;
            let mut wtotal : u64 = 0;

            let mut se = SelfEncryptor::new(my_storage.clone(), datamap::DataMap::None);
            for element in broken_data.iter() {
                se.write(element.1, element.0);
                wtotal += element.1.len() as u64;
            }
            assert_eq!(wtotal, DATA_SIZE);
            let decrypted = se.read(0u64, DATA_SIZE);
            assert_eq!(original, decrypted);

            let mut overwrite = original[0..post_overlap.0 as usize].to_vec();
            overwrite.extend((post_overlap.1).to_vec().iter().map(|&x| x));
            overwrite.extend(original[post_position as usize + 7..DATA_SIZE as
            usize].iter().map(|&x| x));
            se.write(post_overlap.1, post_overlap.0);
            let decrypted = se.read(0u64, DATA_SIZE);
            assert_eq!(overwrite.len(), decrypted.len());
            assert_eq!(overwrite, decrypted);
        }
    }
}

#[test]
// The test writes random-sized pieces at random offsets and checks they can be read back.  The
// pieces may overlap or leave gaps in the file.  Gaps should be filled with 0s when read back.
fn write_random_sizes_out_of_sequence_with_gaps_and_overlaps() {
    let my_storage = Arc::new(MyStorage::new());
    let parts = 20usize;
    assert!(DATA_SIZE / MAX_CHUNK_SIZE as u64 >= parts as u64);
    let mut rng = thread_rng();
    let mut total_size = 0u64;
    let mut data_map = datamap::DataMap::None;
    let mut original = vec![0u8; DATA_SIZE as usize];

    {
        let mut self_encryptor = SelfEncryptor::new(my_storage.clone(), data_map);

        for i in 0..parts {
            // Get random values for the piece size and intended offset
            let piece_size = rng.gen_range(1, MAX_CHUNK_SIZE as usize + 1);
            let offset = rng.gen_range(0, DATA_SIZE - MAX_CHUNK_SIZE as u64);
            total_size = std::cmp::max(total_size, offset + piece_size as u64);
            assert!(DATA_SIZE >= total_size as u64);
            println!("{}\tWriting {} bytes.\tOffset {} bytes.\tTotal size now {} bytes.", i, piece_size,
                     offset, total_size);

            // Create the random piece and copy to the comparison vector.
            let piece = random_bytes(piece_size);
            for a in 0..piece_size {
                original[offset as usize + a] = piece[a];
            }

            // Write the piece to the encryptor and check it can be read back.
            self_encryptor.write(&piece, offset as u64);
            let decrypted = self_encryptor.read(offset, piece_size as u64);
            assert_eq!(decrypted, piece);
            assert_eq!(total_size, self_encryptor.len());
        }

        // Read back DATA_SIZE from the encryptor.  This will contain all that was written, plus likely
        // will be reading past EOF.  Reading past the end shouldn't affect the file size.
        let decrypted = self_encryptor.read(0u64, DATA_SIZE);
        assert_eq!(decrypted.len(), DATA_SIZE as usize);
        assert_eq!(decrypted, original);
        assert_eq!(total_size, self_encryptor.len());

        // Close the encryptor, open a new one with the returned DataMap, and read back DATA_SIZE
        // again.
        data_map = self_encryptor.close();
    }
    
    let mut self_encryptor = SelfEncryptor::new(my_storage.clone(), data_map);
    let decrypted = self_encryptor.read(0u64, DATA_SIZE);
    assert_eq!(decrypted.len(), DATA_SIZE as usize);
    assert_eq!(decrypted, original);
    assert_eq!(total_size, self_encryptor.len());    
}
