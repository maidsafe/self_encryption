
/// data map records vector
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

/// Holds pre and post encryption hashes as well as original chunk size
#[derive(PartialEq, Eq, PartialOrd, Ord)] 
pub enum DataMap {
  /// if file was large enough this holds the data to decrypt it
  Chunks(Vec<ChunkDetails>),
  /// very small files are put here in entirety (defined in lib as MIN_CHUNK_SIZE)
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
  /// we require this to be a sorted list to allow get_pad_iv_key to get the correct 
  /// pre encryption hashes for decrypt/encrypt
  pub fn get_sorted_chunks(&self)->&Vec<ChunkDetails> {
    self.sort();
    match *self {
      DataMap::Chunks(ref chunks) => &chunks, 
        _                           => panic!("no chunks")
    }
  }

  pub fn sort(&self) {
    assert!(self.has_chunks());
//    self.sort(); 
  }
  /// chunks or all content stored in a single field
  pub  fn has_chunks(&self)->bool {
    match *self {
      DataMap::Chunks(ref chunks) => DataMap::chunks_size(chunks) > 0, 
        _ => false, 
    }
  }
  fn chunks_size(chunks: &Vec<ChunkDetails>)->u64 {
    let mut size = 0u64;
    for i in chunks.iter() {
      size += i.source_size
    }
    return size
  }
  }

