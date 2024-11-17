use crate::encryption::{Iv, Key, Pad, IV_SIZE, KEY_SIZE, PAD_SIZE};
use bytes::Bytes;
use xor_name::XorName;

/// Helper function to XOR a data with a pad (pad will be rotated to fill the length)
pub(crate) fn xor(data: &Bytes, &Pad(pad): &Pad) -> Bytes {
    let vec: Vec<_> = data
        .iter()
        .zip(pad.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect();
    Bytes::from(vec)
}

pub fn extract_hashes(data_map: &crate::DataMap) -> Vec<XorName> {
    data_map.infos().iter().map(|c| c.src_hash).collect()
}

pub(crate) fn get_pad_key_and_iv(chunk_index: usize, chunk_hashes: &[XorName]) -> (Pad, Key, Iv) {
    let (n_1, n_2) = get_n_1_n_2(chunk_index, chunk_hashes.len());

    let src_hash = &chunk_hashes[chunk_index];
    let n_1_src_hash = &chunk_hashes[n_1];
    let n_2_src_hash = &chunk_hashes[n_2];

    get_pki(src_hash, n_1_src_hash, n_2_src_hash)
}

pub(crate) fn get_n_1_n_2(chunk_index: usize, total_num_chunks: usize) -> (usize, usize) {
    match chunk_index {
        0 => (total_num_chunks - 1, total_num_chunks - 2),
        1 => (0, total_num_chunks - 1),
        n => (n - 1, n - 2),
    }
}

pub(crate) fn get_pki(
    src_hash: &XorName,
    n_1_src_hash: &XorName,
    n_2_src_hash: &XorName,
) -> (Pad, Key, Iv) {
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
pub(crate) fn get_num_chunks(file_size: usize) -> usize {
    if file_size < (3 * crate::MIN_CHUNK_SIZE) {
        return 0;
    }
    if file_size < (3 * *crate::MAX_CHUNK_SIZE) {
        return 3;
    }
    if file_size % *crate::MAX_CHUNK_SIZE == 0 {
        file_size / *crate::MAX_CHUNK_SIZE
    } else {
        (file_size / *crate::MAX_CHUNK_SIZE) + 1
    }
}

// Returns the size of a chunk according to file size.
pub(crate) fn get_chunk_size(file_size: usize, chunk_index: usize) -> usize {
    if file_size < 3 * crate::MIN_CHUNK_SIZE {
        return 0;
    }
    if file_size < 3 * *crate::MAX_CHUNK_SIZE {
        if chunk_index < 2 {
            return file_size / 3;
        } else {
            // When the file_size % 3 > 0, the third (last) chunk includes the remainder
            return file_size - (2 * (file_size / 3));
        }
    }
    let total_chunks = get_num_chunks(file_size);
    if chunk_index < total_chunks - 2 {
        return *crate::MAX_CHUNK_SIZE;
    }
    let remainder = file_size % *crate::MAX_CHUNK_SIZE;
    let penultimate = (total_chunks - 2) == chunk_index;
    if remainder == 0 {
        return *crate::MAX_CHUNK_SIZE;
    }
    if remainder < crate::MIN_CHUNK_SIZE {
        if penultimate {
            *crate::MAX_CHUNK_SIZE - crate::MIN_CHUNK_SIZE
        } else {
            crate::MIN_CHUNK_SIZE + remainder
        }
    } else if penultimate {
        *crate::MAX_CHUNK_SIZE
    } else {
        remainder
    }
}

// Returns the [start, end) half-open byte range of a chunk.
pub(crate) fn get_start_end_positions(file_size: usize, chunk_index: usize) -> (usize, usize) {
    if get_num_chunks(file_size) == 0 {
        return (0, 0);
    }
    let start = get_start_position(file_size, chunk_index);
    (start, start + get_chunk_size(file_size, chunk_index))
}

pub(crate) fn get_start_position(file_size: usize, chunk_index: usize) -> usize {
    let total_chunks = get_num_chunks(file_size);
    if total_chunks == 0 {
        return 0;
    }
    let last = (total_chunks - 1) == chunk_index;
    let first_chunk_size = get_chunk_size(file_size, 0);
    if last {
        first_chunk_size * (chunk_index - 1) + get_chunk_size(file_size, chunk_index - 1)
    } else {
        first_chunk_size * chunk_index
    }
}

#[allow(dead_code)]
pub(crate) fn get_chunk_index(file_size: usize, position: usize) -> usize {
    let num_chunks = get_num_chunks(file_size);
    if num_chunks == 0 {
        return 0; // FIX THIS SHOULD NOT BE ALLOWED
    }

    let chunk_size = get_chunk_size(file_size, 0);
    let remainder = file_size % chunk_size;

    if remainder == 0
        || remainder >= crate::MIN_CHUNK_SIZE
        || position < file_size - remainder - crate::MIN_CHUNK_SIZE
    {
        usize::min(position / chunk_size, num_chunks - 1)
    } else {
        num_chunks - 1
    }
}
