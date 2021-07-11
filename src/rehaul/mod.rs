//#![feature(async_stream)]

use std::io::Cursor; // time::Instant

use super::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use crate::{
    encryption::{self, IV_SIZE, KEY_SIZE},
    sequential::{Iv, Key},
    SelfEncryptionError, COMPRESSION_QUALITY,
};
use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

const HASH_SIZE: usize = 32;
const PAD_SIZE: usize = (HASH_SIZE * 3) - KEY_SIZE - IV_SIZE;

struct Pad(pub [u8; PAD_SIZE]);

///
pub trait AddressGen: Send + Sync + 'static + Clone {
    ///
    fn generate(&self, data: &[u8]) -> Vec<u8>;
}

///
pub trait DataReader: Send + Sync + 'static + Clone {
    ///
    fn size(&self) -> usize;
    ///
    fn read(&self, start: usize, end: usize) -> Bytes;
}

///
#[derive(Clone)]
pub struct ChunkInfo {
    ///
    pub index: usize,
    ///
    pub src_hash: Vec<u8>,
    ///
    pub src_size: usize,
}

///
#[derive(Clone)]
pub struct ChunkBatch<R: DataReader, G: AddressGen> {
    file: R,
    address_gen: G,
    file_size: usize,
    chunk_infos: Vec<ChunkInfo>,
}

/// Holds pre- and post-encryption hashes as well as the original
/// (pre-compression) size for a given chunk.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct ChunkIndex {
    /// Index number (starts at 0)
    pub index: usize,
    /// Post-encryption hash of chunk
    pub dst_hash: Vec<u8>,
    /// Pre-encryption hash of chunk
    pub src_hash: Vec<u8>,
    /// Size before encryption and compression (any possible padding depending
    /// on cipher used alters this)
    pub src_size: usize,
}

/// Hash all the chunks.
/// Creates [num cores] batches.
pub fn hashes<R: DataReader, G: AddressGen>(file: R, address_gen: G) -> Vec<ChunkBatch<R, G>> {
    let file_size = file.size();
    let num_chunks = get_num_chunks(file_size);
    // println!("File size: {}, num chunks: {}", file_size, num_chunks);

    // let timer_a = Instant::now();
    let chunk_infos: Vec<_> = (0..num_chunks)
        .into_iter()
        .map(|index| (index, address_gen.clone(), file.clone()))
        .par_bridge()
        .map(|(index, address_gen, file)| {
            let (start, end) = get_start_end_positions(file_size, index);
            let data = file.read(start, end);
            ChunkInfo {
                index,
                src_hash: address_gen.generate(&data),
                src_size: get_chunk_size(file_size, index),
            }
        })
        .collect();

    // let a_elapsed = timer_a.elapsed().as_millis();
    // println!(
    //     "chunk_infos len: {} .. ({} ms)",
    //     chunk_infos.len(),
    //     a_elapsed
    // );

    let mut chunk_infos = chunk_infos.into_iter().peekable();

    let cpus = num_cpus::get();
    let chunks_per_batch = usize::max(1, (num_chunks as f64 / cpus as f64).ceil() as usize);
    let mut batches = vec![];

    while chunk_infos.peek().is_some() {
        let _ = batches.push(ChunkBatch {
            file: file.clone(),
            address_gen: address_gen.clone(),
            file_size,
            chunk_infos: chunk_infos.by_ref().take(chunks_per_batch).collect(),
        });
    }
    //println!("cpus: {}, chunks_per_batch: {}", cpus, chunks_per_batch);

    batches
}

/// Encrypt the chunks
pub fn encrypt<R: DataReader, G: AddressGen>(
    batches: Vec<ChunkBatch<R, G>>,
) -> Vec<Result<ChunkIndex, SelfEncryptionError>> {
    let all_infos = batches
        .iter()
        .map(|b| &b.chunk_infos)
        .flatten()
        .collect_vec()
        .into_iter()
        .sorted_by_key(|c| c.index)
        .cloned()
        .collect_vec();

    //let timer_b = Instant::now();

    let results = batches
        .into_iter()
        .map(|batch| (batch.clone(), all_infos.clone()))
        .par_bridge()
        .map(|(batch, all_infos)| {
            batch
                .chunk_infos
                .par_iter()
                .map(|chunk| {
                    let (start, end) = get_start_end_positions(batch.file_size, chunk.index);
                    let pki = get_pad_key_and_iv(chunk.index, &all_infos, batch.file_size);

                    let data = batch.file.read(start, end);
                    let encrypted = encrypt_chunk(&data, pki)?;
                    let hash = batch.address_gen.generate(&encrypted);

                    Ok(ChunkIndex {
                        index: chunk.index,
                        dst_hash: hash.to_vec(),
                        src_hash: chunk.src_hash.clone(),
                        src_size: chunk.src_size,
                    })
                })
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect();

    // let b_elapsed = timer_b.elapsed().as_millis();
    // println!("chunks encrypted .. ({} ms)", b_elapsed);

    results
}

fn encrypt_chunk(content: &[u8], pki: (Pad, Key, Iv)) -> Result<Vec<u8>, SelfEncryptionError> {
    let (pad, key, iv) = pki;
    let mut compressed = vec![];
    let enc_params = BrotliEncoderParams {
        quality: COMPRESSION_QUALITY,
        ..Default::default()
    };
    let result = brotli::BrotliCompress(&mut Cursor::new(content), &mut compressed, &enc_params);
    if result.is_err() {
        return Err(SelfEncryptionError::Compression);
    }
    let encrypted = encryption::encrypt(&compressed, &key, &iv)?;
    Ok(xor(&encrypted, &pad))
}

fn get_pad_key_and_iv(
    chunk_index: usize,
    chunk_hashes: &[ChunkInfo],
    file_size: usize,
) -> (Pad, Key, Iv) {
    let n_1 = get_previous_chunk_index(file_size, chunk_index);
    let n_2 = get_previous_chunk_index(file_size, n_1);
    let src_hash = &chunk_hashes[chunk_index].src_hash;
    let n_1_src_hash = &chunk_hashes[n_1].src_hash;
    let n_2_src_hash = &chunk_hashes[n_2].src_hash;
    //assert_eq!(n_1_src_hash.len(), HASH_SIZE);
    //assert_eq!(n_2_src_hash.len(), HASH_SIZE);

    let mut pad = [0u8; PAD_SIZE];
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];

    for (pad_iv_el, element) in pad
        .iter_mut()
        .zip(src_hash.iter().chain(n_2_src_hash.iter()))
    {
        *pad_iv_el = *element;
    }

    for (key_el, element) in key.iter_mut().chain(iv.iter_mut()).zip(n_1_src_hash.iter()) {
        *key_el = *element;
    }

    (Pad(pad), Key(key), Iv(iv))
}

// Returns the number of chunks according to file size.
fn get_num_chunks(file_size: usize) -> usize {
    if file_size < (3 * MIN_CHUNK_SIZE) {
        return 0;
    }
    if file_size < (3 * MAX_CHUNK_SIZE) {
        return 3;
    }
    if file_size % MAX_CHUNK_SIZE == 0 {
        file_size / MAX_CHUNK_SIZE
    } else {
        (file_size / MAX_CHUNK_SIZE) + 1
    }
}

// Returns the size of a chunk according to file size.
fn get_chunk_size(file_size: usize, chunk_index: usize) -> usize {
    if file_size < 3 * MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * MAX_CHUNK_SIZE {
        if chunk_index < 2 {
            return file_size / 3;
        } else {
            return file_size - (2 * (file_size / 3));
        }
    }
    if chunk_index < get_num_chunks(file_size) - 2 {
        return MAX_CHUNK_SIZE;
    }
    let remainder = file_size % MAX_CHUNK_SIZE;
    let penultimate = (get_num_chunks(file_size) - 2) == chunk_index;
    if remainder == 0 {
        return MAX_CHUNK_SIZE;
    }
    if remainder < MIN_CHUNK_SIZE {
        if penultimate {
            MAX_CHUNK_SIZE - MIN_CHUNK_SIZE
        } else {
            MIN_CHUNK_SIZE + remainder
        }
    } else if penultimate {
        MAX_CHUNK_SIZE
    } else {
        remainder
    }
}

// Returns the [start, end) half-open byte range of a chunk.
fn get_start_end_positions(file_size: usize, chunk_index: usize) -> (usize, usize) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start;
    let last = (get_num_chunks(file_size) - 1) == chunk_index;
    if last {
        start = get_chunk_size(file_size, 0) * (chunk_index - 1)
            + get_chunk_size(file_size, chunk_index - 1);
    } else {
        start = get_chunk_size(file_size, 0) * chunk_index;
    }
    (start, start + get_chunk_size(file_size, chunk_index))
}

fn get_previous_chunk_index(file_size: usize, chunk_index: usize) -> usize {
    if get_num_chunks(file_size) == 0 {
        return 0;
    }
    (get_num_chunks(file_size) + chunk_index - 1) % get_num_chunks(file_size)
}

// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
fn xor(data: &[u8], &Pad(pad): &Pad) -> Vec<u8> {
    data.iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::{encrypt, hashes, DataReader, FileReader, MemFileReader, SelfEncryptionError};
    use crate::{
        rehaul::{get_num_chunks, Generator},
        test_helpers::{new_test_rng, random_bytes},
    };
    use bytes::Bytes;
    use tempfile::tempdir;

    #[test]
    fn mem_reader() -> Result<(), SelfEncryptionError> {
        let file_size = 3000_000_000;

        let reader = get_mem_reader(file_size)?;

        run_test(file_size, reader)
    }

    #[test]
    fn disk_reader() -> Result<(), SelfEncryptionError> {
        let file_size = 30_000_000;

        let reader = get_disk_reader(file_size)?;

        run_test(file_size, reader)
    }

    fn run_test(file_size: usize, reader: impl DataReader) -> Result<(), SelfEncryptionError> {
        assert_eq!(file_size, reader.size());

        let address_gen = Generator {};

        let total_timer = Instant::now();

        let batch_timer = Instant::now();
        let batches = hashes(reader, address_gen);
        let batch_time = batch_timer.elapsed();

        let encrypt_timer = Instant::now();
        let chunk_details = encrypt(batches);
        let encrypt_time = encrypt_timer.elapsed();

        let total_time = total_timer.elapsed();

        println!(
            "Batch time: {}, encrypt time: {}, total: {}",
            batch_time.as_millis(),
            encrypt_time.as_millis(),
            total_time.as_millis()
        );

        let num_chunks = get_num_chunks(file_size);
        assert_eq!(num_chunks, chunk_details.len());
        assert!(chunk_details.into_iter().all(|r| r.is_ok()));

        Ok(())
    }

    fn get_mem_reader(file_size: usize) -> Result<impl DataReader, SelfEncryptionError> {
        let mut rng: rand_chacha::ChaCha20Rng = new_test_rng()?;
        let the_bytes = random_bytes(&mut rng, file_size);
        Ok(MemFileReader::new(Bytes::from(the_bytes)))
    }

    fn get_disk_reader(file_size: usize) -> Result<impl DataReader, SelfEncryptionError> {
        let bytes = vec![0_u8; file_size];

        // Create a directory inside of `std::env::temp_dir()`.
        println!("Creating file of {} bytes..", file_size);
        let dir = tempdir()?;
        let file_path = dir.path().join("big-file.db");
        let file = std::fs::File::create(file_path.as_path())?;
        std::fs::write(file_path.as_path(), bytes)?;
        file.sync_all()?;
        println!("File created.");

        Ok(FileReader::new(file_path))
    }
}

use tiny_keccak::{Hasher, Sha3};

///
#[derive(Clone)]
pub struct Generator {}

impl AddressGen for Generator {
    fn generate(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3::v256();
        let mut output = [0; 32];
        hasher.update(&data);
        hasher.finalize(&mut output);
        output.to_vec()
    }
}

///
#[derive(Clone)]
pub struct MemFileReader {
    data: Bytes,
}

impl MemFileReader {
    ///
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl DataReader for MemFileReader {
    fn size(&self) -> usize {
        self.data.len()
    }

    fn read(&self, start: usize, end: usize) -> Bytes {
        self.data.slice(start..end)
    }
}

///
#[derive(Clone)]
pub struct FileReader {
    size: usize,
    path: std::path::PathBuf,
}

impl FileReader {
    ///
    pub fn new(path: std::path::PathBuf) -> Self {
        use std::fs;
        let metadata = fs::metadata(path.as_path()).unwrap();
        Self {
            path,
            size: metadata.len() as usize,
        }
    }
}

use positioned_io_preview as positioned_io;

impl DataReader for FileReader {
    fn size(&self) -> usize {
        self.size
    }

    fn read(&self, start: usize, end: usize) -> Bytes {
        use positioned_io::{RandomAccessFile, ReadAt};
        let raf = RandomAccessFile::open(self.path.as_path()).unwrap();
        let mut buf = vec![0; end]; // This line creates a vector of size `end` where every element is initialized to 0.
        let _bytes_read = raf.read_at(start as u64, &mut buf).unwrap();
        Bytes::from(buf)
    }
}
