
/// Holds pre and post encryption hashes as well as original chunk size


struct ChunkDetails {
  chunk_num: u32,
  hash: Vec<u8>,
  pre_hash: Vec<u8>,
  source_size: u64
  }

enum DataMap {
  Chunks(Vec<ChunkDetails>),
  Content(Vec<u8>)
  }

impl DataMap {
  fn len(&self)->u64 {
    let size = 0u64;
      match *self {
       DataMap::Chunks(ref chunks) => 0u64, 
       DataMap::Content(ref content) => content.len() as u64, 
        }
    }
  }

