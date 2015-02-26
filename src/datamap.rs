
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
       DataMap::Chunks(ref chunks) => DataMap::ChunksLength(chunks), 
       DataMap::Content(ref content) => content.len() as u64, 
        }
    }
  fn has_chunks(&self)->bool {
      match *self {
       DataMap::Chunks(ref chunks) => true, 
       _ => false, 
        }
    }
    fn ChunksLength(chunks: &Vec<ChunkDetails>)->u64 {
        let mut size = 0u64;
        for i in chunks.iter() {
            size += i.source_size
          }
          return size
      }
      fn empty(&self)->bool {
         self.len() == 0u64
        }
  }

