// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Example demonstrating random access decryption with StreamingDecrypt.
//!
//! This example shows how to use the new random access features added to
//! StreamingDecrypt, allowing you to read specific byte ranges from encrypted
//! files without sequential iteration.

use bytes::Bytes;
use self_encryption::{encrypt, streaming_decrypt, test_helpers::random_bytes, Result};
use std::collections::HashMap;
use xor_name::XorName;

fn main() -> Result<()> {
    println!("=== StreamingDecrypt Random Access Example ===\n");

    // Create some test data - make it large enough to span multiple chunks
    let file_size = 2_000_000; // 2MB
    let original_data = random_bytes(file_size);
    println!("Created test data of {} bytes", original_data.len());

    // Encrypt the data
    let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;
    println!("Encrypted into {} chunks", encrypted_chunks.len());

    // Create a simple storage backend using HashMap
    let mut storage = HashMap::new();
    for chunk in encrypted_chunks {
        let hash = XorName::from_content(&chunk.content);
        storage.insert(hash, chunk.content.to_vec());
    }
    println!("Stored {} chunks in storage", storage.len());

    // Create chunk retrieval function
    let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
        let mut results = Vec::new();
        for &(index, hash) in hashes {
            if let Some(data) = storage.get(&hash) {
                results.push((index, Bytes::from(data.clone())));
            } else {
                return Err(self_encryption::Error::Generic(format!(
                    "Chunk not found: {}",
                    hex::encode(hash)
                )));
            }
        }
        Ok(results)
    };

    // Create streaming decrypt instance
    let stream = streaming_decrypt(&data_map, get_chunks)?;
    println!("Created streaming decrypt instance\n");

    // === Random Access Examples ===

    println!("=== Random Access Examples ===");

    // Example 1: Get a specific range using range() method
    println!("\n1. Getting bytes 1000-2000 using range() method:");
    let range_data = stream.range(1000..2000)?;
    println!("   Retrieved {} bytes", range_data.len());

    // Verify correctness
    assert_eq!(range_data.as_ref(), &original_data[1000..2000]);
    println!("   ✓ Data matches original");

    // Example 2: Get data from a position to the end
    println!("\n2. Getting data from byte 1_500_000 to end:");
    let from_data = stream.range_from(1_500_000)?;
    println!("   Retrieved {} bytes", from_data.len());

    assert_eq!(from_data.as_ref(), &original_data[1_500_000..]);
    println!("   ✓ Data matches original");

    // Example 3: Get first N bytes
    println!("\n3. Getting first 10,000 bytes:");
    let first_data = stream.range_to(10_000)?;
    println!("   Retrieved {} bytes", first_data.len());

    assert_eq!(first_data.as_ref(), &original_data[..10_000]);
    println!("   ✓ Data matches original");

    // Example 4: Get entire file content
    println!("\n4. Getting entire file content:");
    let full_data = stream.range_full()?;
    println!("   Retrieved {} bytes", full_data.len());

    assert_eq!(full_data.as_ref(), &original_data[..]);
    println!("   ✓ Data matches original");

    // Example 5: Get inclusive range
    println!("\n5. Getting inclusive range [500_000, 500_999]:");
    let inclusive_data = stream.range_inclusive(500_000, 500_999)?;
    println!("   Retrieved {} bytes", inclusive_data.len());

    assert_eq!(inclusive_data.as_ref(), &original_data[500_000..501_000]);
    println!("   ✓ Data matches original");

    // Example 6: Get using direct get_range method
    println!("\n6. Using get_range directly for 5000 bytes at position 100_000:");
    let direct_range = stream.get_range(100_000, 5000)?;
    println!("   Retrieved {} bytes", direct_range.len());

    assert_eq!(direct_range.as_ref(), &original_data[100_000..105_000]);
    println!("   ✓ Data matches original");

    // === Performance Demonstration ===

    println!("\n=== Performance Demonstration ===");

    // Show that we can access random parts without processing everything
    let positions = [
        (50_000, 1000),
        (800_000, 2000),
        (1_200_000, 1500),
        (300_000, 800),
        (1_800_000, 1200),
    ];

    println!("\nAccessing {} random ranges:", positions.len());
    for (i, (start, len)) in positions.iter().enumerate() {
        let range_data = stream.get_range(*start, *len)?;
        println!(
            "   Range {}: {} bytes at position {} ✓",
            i + 1,
            range_data.len(),
            start
        );

        // Verify correctness
        assert_eq!(range_data.as_ref(), &original_data[*start..*start + *len]);
    }

    // === Edge Cases ===

    println!("\n=== Edge Cases ===");

    // Test range beyond file size
    println!("\n1. Testing range beyond file size:");
    let beyond_range = stream.get_range(file_size + 1000, 500)?;
    println!(
        "   Requesting range beyond file: {} bytes returned",
        beyond_range.len()
    );
    assert_eq!(beyond_range.len(), 0);

    // Test range that partially exceeds file size
    println!("\n2. Testing range that partially exceeds file size:");
    let partial_exceed = stream.get_range(file_size - 100, 200)?;
    println!(
        "   Requesting 200 bytes with only 100 available: {} bytes returned",
        partial_exceed.len()
    );
    assert_eq!(partial_exceed.len(), 100);
    assert_eq!(partial_exceed.as_ref(), &original_data[file_size - 100..]);

    // Test zero-length range
    println!("\n3. Testing zero-length range:");
    let zero_len = stream.get_range(1000, 0)?;
    println!("   Zero-length range: {} bytes returned", zero_len.len());
    assert_eq!(zero_len.len(), 0);

    println!("\n=== All Tests Passed! ===");
    println!("\nStreamingDecrypt now supports efficient random access to any byte range");
    println!("in encrypted files, enabling use cases like:");
    println!("• Seeking to specific positions in large files");
    println!("• Reading file headers or metadata");
    println!("• Implementing file viewers with pagination");
    println!("• Extracting specific sections without full decryption");

    Ok(())
}
