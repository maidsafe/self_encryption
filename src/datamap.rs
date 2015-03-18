
/// Struct holds pre and post encryption hashes as well as original chunk size
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkDetails {
  /// index number (starts at 0)
  pub chunk_num: u32,
  /// Post encryption hash of chunk
  pub hash: Vec<u8>,
  /// Pre encryption hash of chunk
  pub pre_hash: Vec<u8>,
  /// size before encryption (compression alters this as well as any poss padding
  /// depending on cipher used)
  pub source_size: u64
}

impl ChunkDetails {
  pub fn new() -> ChunkDetails {
    ChunkDetails { chunk_num : 0, hash : Vec::new(), pre_hash : Vec::new(), source_size : 0 }
  }
}

impl Clone for ChunkDetails {
  fn clone(&self) -> ChunkDetails {
    return ChunkDetails {
      chunk_num: self.chunk_num,
      hash: self.hash.to_vec(),
      pre_hash: self.pre_hash.to_vec(),
      source_size: self.source_size
    };
  }
}

/// Holds the infomation that required to recover the content of the encrypted file
/// Depends on the file size, such info can be held as vector of ChunkDetail, or as raw data directly
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum DataMap {
  /// if file was large enough (larger than 3072 bytes, 3 * MIN_CHUNK_SIZE)
  /// this holds the list of chunks' info to decrypt it
  Chunks(Vec<ChunkDetails>),
  /// very small files (less than 3072 bytes, 3 * MIN_CHUNK_SIZE) are put here in entirely
  Content(Vec<u8>),
  /// empty datamap
  None
  }

impl DataMap {
  /// original size of file in datamap
  pub fn len(&self)->u64 {
    let size = 0u64;
    match *self {
      DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks),
        DataMap::Content(ref content) => content.len() as u64,
        DataMap::None => 0u64
    }
  }
  /// returning the list of chunk info if present
  pub fn get_chunks(&self)->Vec<ChunkDetails> {
    match *self {
      DataMap::Chunks(ref chunks) => return chunks.to_vec(),
        _                         => panic!("no chunks")
    }
  }

  /// we require this to be a sorted list to allow get_pad_iv_key to get the correct
  /// pre encryption hashes for decrypt/encrypt
  pub fn get_sorted_chunks(&self)->Vec<ChunkDetails> {
    match *self {
      DataMap::Chunks(ref chunks) =>  {
                                        let mut result = chunks.to_vec();
                                        DataMap::chunks_sort(result.as_mut_slice());
                                        result
                                      },
        _                           => panic!("no chunks")
    }
  }

  /// content stored as chunks or as raw
  pub fn has_chunks(&self)->bool {
    match *self {
      DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks) > 0,
        _ => false,
    }
  }

  /// iterate through the chunks to figure out the total size, i.e. the file size
  fn chunks_size(chunks: &Vec<ChunkDetails>)->u64 {
    let mut size = 0u64;
    for i in chunks.iter() {
      size += i.source_size
    }
    return size
  }
  /// sorting list of chunks using bubble sort
  /// TODO : change to use other quick sort algorithm to improve the performance
  fn chunks_sort(chunks: &mut [ChunkDetails]) {
    let (mut i, len) = (0, chunks.len());
    while i < len {
        let (mut j, mut cur_min) = (i + 1, i);
        while j < len {
            if chunks[j].chunk_num < chunks[cur_min].chunk_num {
                cur_min = j;
            }
            j = j + 1;
        }
        chunks.swap(i, cur_min);
        i = i + 1;
    }
  }
}

