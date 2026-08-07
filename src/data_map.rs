// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt::{self, Debug, Formatter, Write};
use xor_name::XorName;

/// Holds the information that is required to recover the content of the encrypted file.
/// This is held as a vector of `ChunkInfo`, i.e. a list of the file's chunk hashes.
/// Only files larger than 3072 bytes (3 * MIN_CHUNK_SIZE) can be self-encrypted.
/// Smaller files will have to be batched together.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DataMap {
    /// List of chunk hashes
    pub chunk_identifiers: Vec<ChunkInfo>,
    /// Child value, None means root data map and any other valuesignifies how
    /// many levels of data map we have shrunk
    pub child: Option<usize>,
}

impl DataMap {
    /// Serialize DataMap to bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize DataMap from bytes (v1 versioned format).
    /// Delegates to the `Deserialize` impl which handles version checking.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[allow(clippy::len_without_is_empty)]
impl DataMap {
    /// A new instance from a vec of partial keys.
    ///
    /// Sorts on instantiation.
    /// The algorithm requires this to be a sorted list to allow get_pad_iv_key to obtain the
    /// correct pre-encryption hashes for decryption/encryption.
    pub fn new(mut keys: Vec<ChunkInfo>) -> Self {
        keys.sort_by_key(|a| a.index);
        Self {
            chunk_identifiers: keys,
            child: None,
        }
    }

    /// Creates a new DataMap with a specified child value
    pub fn with_child(mut keys: Vec<ChunkInfo>, child: usize) -> Self {
        keys.sort_by_key(|a| a.index);
        Self {
            chunk_identifiers: keys,
            child: Some(child),
        }
    }

    /// Original (pre-encryption) size of the file.
    pub fn original_file_size(&self) -> usize {
        DataMap::total_size(&self.chunk_identifiers)
    }

    /// Returns the list of chunks pre and post encryption hashes if present.
    pub fn infos(&self) -> &[ChunkInfo] {
        &self.chunk_identifiers
    }

    /// Returns the child value if set
    pub fn child(&self) -> Option<usize> {
        self.child
    }

    /// Iterates through the keys to figure out the total size of the data, i.e. the file size.
    fn total_size(keys: &[ChunkInfo]) -> usize {
        keys.iter().fold(0, |acc, chunk| acc + chunk.src_size)
    }

    /// Returns the number of chunks in the DataMap
    pub fn len(&self) -> usize {
        self.chunk_identifiers.len()
    }

    /// Returns true if this DataMap has a child value
    pub fn is_child(&self) -> bool {
        self.child.is_some()
    }
}

impl Serialize for DataMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // For JSON and other human-readable formats, use struct format
            let mut st = serializer.serialize_struct("DataMap", 2)?;
            st.serialize_field("chunk_identifiers", &self.chunk_identifiers)?;
            st.serialize_field("child", &self.child)?;
            st.end()
        } else {
            // For binary formats, prepend a version byte
            // Version 1: New format with chunk_identifiers and child fields
            #[derive(Serialize)]
            struct VersionedDataMap<'a> {
                version: u8,
                chunk_identifiers: &'a [ChunkInfo],
                child: &'a Option<usize>,
            }

            let versioned = VersionedDataMap {
                version: 1u8,
                chunk_identifiers: &self.chunk_identifiers,
                child: &self.child,
            };

            versioned.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for DataMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct DataMapVisitor;

            impl<'de> Visitor<'de> for DataMapVisitor {
                type Value = DataMap;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        f,
                        "a DataMap struct with chunk_identifiers and optional child"
                    )
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut chunks: Option<Vec<ChunkInfo>> = None;
                    let mut child: Option<Option<usize>> = None;

                    while let Some(key) = map.next_key::<&str>()? {
                        match key {
                            "chunk_identifiers" => chunks = Some(map.next_value()?),
                            "child" => child = Some(map.next_value()?),
                            _ => {
                                let _: de::IgnoredAny = map.next_value()?;
                            }
                        }
                    }

                    let chunk_identifiers =
                        chunks.ok_or_else(|| de::Error::missing_field("chunk_identifiers"))?;
                    Ok(DataMap {
                        chunk_identifiers,
                        child: child.flatten(),
                    })
                }
            }

            deserializer.deserialize_any(DataMapVisitor)
        } else {
            #[derive(Deserialize)]
            struct VersionedDataMap {
                version: u8,
                chunk_identifiers: Vec<ChunkInfo>,
                child: Option<usize>,
            }

            let versioned = VersionedDataMap::deserialize(deserializer)?;
            if versioned.version == 1 {
                Ok(DataMap {
                    chunk_identifiers: versioned.chunk_identifiers,
                    child: versioned.child,
                })
            } else {
                Err(de::Error::custom(format!(
                    "unsupported DataMap version: {ver}",
                    ver = versioned.version
                )))
            }
        }
    }
}

impl Debug for DataMap {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(formatter, "DataMap:")?;
        if let Some(child) = self.child {
            writeln!(formatter, "    child: {child}")?;
        }
        let len = self.chunk_identifiers.len();
        for (index, chunk) in self.chunk_identifiers.iter().enumerate() {
            if index + 1 == len {
                write!(formatter, "        {chunk:?}")?
            } else {
                writeln!(formatter, "        {chunk:?}")?
            }
        }
        Ok(())
    }
}

/// This is - in effect - a partial decryption key for an encrypted chunk of data.
///
/// It holds pre- and post-encryption hashes as well as the original
/// (pre-compression) size for a given chunk.
/// This information is required for successful recovery of a chunk, as well as for the
/// encryption/decryption of it's two immediate successors, modulo the number of chunks in the
/// corresponding DataMap.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct ChunkInfo {
    /// Index number (zero-based)
    pub index: usize,
    /// Post-encryption hash of chunk
    pub dst_hash: XorName,
    /// Pre-encryption hash of chunk
    pub src_hash: XorName,
    /// Size before encryption and compression (any possible padding depending
    /// on cipher used alters this)
    pub src_size: usize,
}

fn debug_bytes<V: AsRef<[u8]>>(input: V) -> String {
    let input_ref = input.as_ref();
    if input_ref.is_empty() {
        return "<empty>".to_owned();
    }
    if input_ref.len() <= 6 {
        let mut ret = String::new();
        for byte in input_ref.iter() {
            let _ = write!(ret, "{byte:02x}");
        }
        return ret;
    }
    // Safety: len > 6 is guaranteed by the early return above, so all indices are valid.
    let len = input_ref.len();
    format!(
        "{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
        input_ref[0],
        input_ref[1],
        input_ref[2],
        input_ref[len - 3],
        input_ref[len - 2],
        input_ref[len - 1]
    )
}

impl Debug for ChunkInfo {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "ChunkInfo {{ index: {}, dst_hash: {}, src_hash: {}, src_size: {} }}",
            self.index,
            debug_bytes(self.dst_hash),
            debug_bytes(self.src_hash),
            self.src_size
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn create_test_chunk_info(index: usize) -> ChunkInfo {
        ChunkInfo {
            index,
            dst_hash: crate::hash::content_hash(format!("dst_{index}").as_bytes()),
            src_hash: crate::hash::content_hash(format!("src_{index}").as_bytes()),
            src_size: 1024 * (index + 1),
        }
    }

    #[test]
    fn test_deserialize_new_format_json() {
        // Create a DataMap with the new format
        let chunks = vec![create_test_chunk_info(0), create_test_chunk_info(1)];
        let data_map = DataMap::with_child(chunks.clone(), 5);

        // Serialize to JSON
        let json = serde_json::to_string(&data_map).unwrap();

        // Verify the JSON contains the expected structure
        assert!(json.contains("\"chunk_identifiers\""));
        assert!(json.contains("\"child\":5"));

        // Deserialize back
        let deserialized: DataMap = serde_json::from_str(&json).unwrap();

        // Verify
        assert_eq!(deserialized.chunk_identifiers.len(), 2);
        assert_eq!(deserialized.child, Some(5));
        assert_eq!(deserialized.chunk_identifiers[0].index, 0);
        assert_eq!(deserialized.chunk_identifiers[1].index, 1);
    }

    #[test]
    fn test_new_format_without_child_json() {
        // Create a DataMap without child
        let chunks = vec![create_test_chunk_info(0)];
        let data_map = DataMap::new(chunks.clone());

        // Serialize and deserialize
        let json = serde_json::to_string(&data_map).unwrap();
        let deserialized: DataMap = serde_json::from_str(&json).unwrap();

        // Verify
        assert_eq!(deserialized.chunk_identifiers.len(), 1);
        assert_eq!(deserialized.child, None);
    }

    #[test]
    fn test_bincode_new_format() {
        // Create and serialize with new format
        let chunks = vec![create_test_chunk_info(0)];
        let data_map = DataMap::with_child(chunks, 3);

        let bytes = data_map.to_bytes().unwrap();
        let deserialized = DataMap::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.chunk_identifiers.len(), 1);
        assert_eq!(deserialized.child, Some(3));
    }

    #[test]
    fn test_bincode_version_byte() {
        // Verify that new format includes version byte
        let chunks = vec![create_test_chunk_info(0)];
        let data_map = DataMap::new(chunks);

        let bytes = data_map.to_bytes().unwrap();

        // First byte should be the version (1)
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 1u8);
    }

    #[test]
    fn test_preserve_chunk_order() {
        // Ensure that chunk ordering is preserved through serialization
        let chunks = vec![
            create_test_chunk_info(2),
            create_test_chunk_info(0),
            create_test_chunk_info(1),
        ];

        // DataMap::new should sort them
        let data_map = DataMap::new(chunks);
        assert_eq!(data_map.chunk_identifiers[0].index, 0);
        assert_eq!(data_map.chunk_identifiers[1].index, 1);
        assert_eq!(data_map.chunk_identifiers[2].index, 2);

        // Serialize and deserialize
        let json = serde_json::to_string(&data_map).unwrap();
        let deserialized: DataMap = serde_json::from_str(&json).unwrap();

        // Order should be preserved
        assert_eq!(deserialized.chunk_identifiers[0].index, 0);
        assert_eq!(deserialized.chunk_identifiers[1].index, 1);
        assert_eq!(deserialized.chunk_identifiers[2].index, 2);
    }

    #[test]
    fn test_error_handling_for_corrupted_data() {
        // Test with completely invalid data
        let invalid_data = b"this is not valid bincode data";
        assert!(DataMap::from_bytes(invalid_data).is_err());

        // Test with partial data (truncated)
        let chunks = vec![create_test_chunk_info(0)];
        let data_map = DataMap::new(chunks);
        let valid_bytes = data_map.to_bytes().unwrap();
        let truncated_bytes = &valid_bytes[..valid_bytes.len() - 5];
        assert!(DataMap::from_bytes(truncated_bytes).is_err());

        // Test with wrong version number
        let mut wrong_version_data = valid_bytes.clone();
        if let Some(first) = wrong_version_data.first_mut() {
            *first = 99u8;
        }
        assert!(DataMap::from_bytes(&wrong_version_data).is_err());
    }

    #[test]
    fn test_bincode_version_byte_consistency() {
        let chunks = vec![create_test_chunk_info(0)];
        let data_map = DataMap::new(chunks.clone());
        let bytes = data_map.to_bytes().unwrap();

        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 1u8);

        let data_map_with_child = DataMap::with_child(chunks, 42);
        let bytes_with_child = data_map_with_child.to_bytes().unwrap();
        assert_eq!(bytes_with_child[0], 1u8);
    }

    #[test]
    fn test_round_trip_serialization_consistency() {
        let chunks = vec![create_test_chunk_info(0), create_test_chunk_info(1)];

        let data_map = DataMap::with_child(chunks.clone(), 3);
        let bytes = data_map.to_bytes().unwrap();
        let deserialized = DataMap::from_bytes(&bytes).unwrap();
        assert_eq!(data_map, deserialized);

        let data_map_no_child = DataMap::new(chunks);
        let bytes_no_child = data_map_no_child.to_bytes().unwrap();
        let deserialized_no_child = DataMap::from_bytes(&bytes_no_child).unwrap();
        assert_eq!(data_map_no_child, deserialized_no_child);
    }
}
