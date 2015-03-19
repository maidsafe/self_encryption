
/// Struct holds pre and post encryption hashes as well as original chunk size
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
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
    ChunkDetails {
      chunk_num: 0,
      hash: vec![],
      pre_hash: vec![],
      source_size: 0
    }
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
  pub fn len(&self) -> u64 {
    match *self {
      DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks),
      DataMap::Content(ref content) => content.len() as u64,
      DataMap::None => 0
    }
  }

  /// returning the list of chunk info if present
  pub fn get_chunks(&self) -> Vec<ChunkDetails> {
    match *self {
      DataMap::Chunks(ref chunks) => chunks.to_vec(),
      _ => panic!("no chunks")
    }
  }

  /// we require this to be a sorted list to allow get_pad_iv_key to get the correct
  /// pre encryption hashes for decrypt/encrypt
  pub fn get_sorted_chunks(&self) -> Vec<ChunkDetails> {
    match *self {
      DataMap::Chunks(ref chunks) =>  {
        let mut result = chunks.to_vec();
        DataMap::chunks_sort(&mut result);
        result
      },
      _ => panic!("no chunks")
    }
  }

  /// content stored as chunks or as raw
  pub fn has_chunks(&self) -> bool {
    match *self {
      DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks) > 0,
      _ => false,
    }
  }

  /// iterate through the chunks to figure out the total size, i.e. the file size
  fn chunks_size(chunks: &[ChunkDetails]) -> u64 {
    chunks.iter().fold(0, |acc, chunk| acc + chunk.source_size)
  }

  /// sorting list of chunks using quicksort
  fn chunks_sort(chunks: &mut [ChunkDetails]) {
    chunks.sort_by(|a, b| a.chunk_num.cmp(&b.chunk_num));
  }
}

