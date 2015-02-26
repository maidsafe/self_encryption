

/// data map records vector
pub struct ChunkDetails {
  chunk_num: u32,
  hash: Vec<u8>,
  pre_hash: Vec<u8>,
  source_size: u64
  }

/// Holds pre and post encryption hashes as well as original chunk size
pub enum DataMap {
  Chunks(Vec<ChunkDetails>),
  Content(Vec<u8>)
  }

impl DataMap {
      /// original size of file in datamap
  pub fn len(&self)->u64 {
    let size = 0u64;
      match *self {
       DataMap::Chunks(ref chunks) => DataMap::chunks_length(chunks), 
       DataMap::Content(ref content) => content.len() as u64, 
        }
    }
    /// chunks or all content stored in a single field
 pub  fn has_chunks(&self)->bool {
      match *self {
       DataMap::Chunks(ref chunks) => true, 
       _ => false, 
        }
    }
    fn chunks_length(chunks: &Vec<ChunkDetails>)->u64 {
        let mut size = 0u64;
        for i in chunks.iter() {
            size += i.source_size
          }
          return size
      }
      /// Empty datamap, no entries
      // [TODO]: remove as this is no longer valid - 2015-02-26 04:31pm
    pub fn empty(&self)->bool {
         self.len() == 0u64
        }
  }

