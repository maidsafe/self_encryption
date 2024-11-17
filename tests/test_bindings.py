import os
import tempfile
from pathlib import Path
from typing import List
import pytest
from self_encryption import (
    DataMap,
    EncryptedChunk,
    XorName,
    encrypt,
    encrypt_from_file,
    decrypt,
    decrypt_from_storage,
    shrink_data_map,
    streaming_decrypt_from_storage,
    verify_chunk,
)

def test_basic_encryption_decryption():
    # Test data
    data = b"x" * 10_000_000  # 10MB of data
    
    # Encrypt
    data_map, chunks = encrypt(data)
    assert len(chunks) > 0
    
    # Decrypt
    decrypted = decrypt(data_map, chunks)
    assert data == decrypted

def test_file_encryption_decryption():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        input_path = Path(temp_dir) / "input.dat"
        data = b"x" * 10_000_000
        input_path.write_bytes(data)
        
        # Create output directory for chunks
        chunk_dir = Path(temp_dir) / "chunks"
        chunk_dir.mkdir()
        
        # Encrypt file
        data_map, chunk_names = encrypt_from_file(str(input_path), str(chunk_dir))
        
        # Create chunk retrieval function
        def get_chunk(hash_hex: str) -> bytes:
            chunk_path = chunk_dir / hash_hex
            return chunk_path.read_bytes()
        
        # Decrypt to new file
        output_path = Path(temp_dir) / "output.dat"
        decrypt_from_storage(data_map, str(output_path), get_chunk)
        
        # Verify
        assert input_path.read_bytes() == output_path.read_bytes()

def test_data_map_shrinking():
    # Create large data to ensure multiple chunks
    data = b"x" * 10_000_000
    
    # Encrypt
    data_map, chunks = encrypt(data)
    
    # Track stored chunks
    stored_chunks = {}
    def store_chunk(hash_hex: str, content: bytes) -> None:
        stored_chunks[hash_hex] = content
    
    # Shrink data map
    shrunk_map, shrink_chunks = shrink_data_map(data_map, store_chunk)
    
    # Verify child level is set
    assert shrunk_map.child() is not None
    assert shrunk_map.is_child()
    
    # Collect all chunks
    all_chunks = chunks + shrink_chunks
    
    # Decrypt using all chunks
    decrypted = decrypt(shrunk_map, all_chunks)
    assert data == decrypted

def test_comprehensive_encryption_decryption():
    test_sizes = [
        (2 * 1024 * 1024, "2MB"),
        (5 * 1024 * 1024, "5MB"),
        (10 * 1024 * 1024, "10MB"),
    ]
    
    for size, name in test_sizes:
        print(f"\nTesting {name} file")
        data = b"x" * size
        
        # Test in-memory encryption/decryption
        data_map1, chunks1 = encrypt(data)
        decrypted1 = decrypt(data_map1, chunks1)
        assert data == decrypted1
        print(f"✓ In-memory encryption/decryption successful")
        
        # Test file-based encryption/decryption
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup paths
            input_path = Path(temp_dir) / "input.dat"
            chunk_dir = Path(temp_dir) / "chunks"
            output_path = Path(temp_dir) / "output.dat"
            
            # Write test data
            input_path.write_bytes(data)
            chunk_dir.mkdir()
            
            # Encrypt file
            data_map2, chunk_names = encrypt_from_file(str(input_path), str(chunk_dir))
            
            # Create chunk retrieval function
            def get_chunk(hash_hex: str) -> bytes:
                chunk_path = chunk_dir / hash_hex
                return chunk_path.read_bytes()
            
            # Decrypt file
            decrypt_from_storage(data_map2, str(output_path), get_chunk)
            
            # Verify
            assert data == output_path.read_bytes()
            print(f"✓ File-based encryption/decryption successful")
            
            # Verify data maps
            assert data_map1.len() == data_map2.len()
            assert data_map1.child() == data_map2.child()
            print(f"✓ Data maps match")

def test_streaming_decryption():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        input_path = Path(temp_dir) / "input.dat"
        data = b"x" * 10_000_000  # 10MB
        input_path.write_bytes(data)
        
        # Create output directory for chunks
        chunk_dir = Path(temp_dir) / "chunks"
        chunk_dir.mkdir()
        
        # Encrypt file
        data_map, chunk_names = encrypt_from_file(str(input_path), str(chunk_dir))
        
        # Create parallel chunk retrieval function
        def get_chunks(hash_hexes: List[str]) -> List[bytes]:
            return [
                (chunk_dir / hash_hex).read_bytes()
                for hash_hex in hash_hexes
            ]
        
        # Decrypt using streaming
        output_path = Path(temp_dir) / "output.dat"
        streaming_decrypt_from_storage(data_map, str(output_path), get_chunks)
        
        # Verify
        assert input_path.read_bytes() == output_path.read_bytes()

def test_verify_chunk():
    # Create some test data and encrypt it
    data = b"x" * 10_000_000
    data_map, chunks = encrypt(data)
    
    # Get the first chunk and its hash
    chunk = chunks[0]
    chunk_info = data_map.infos()[0]
    
    # Use dst_hash from chunk info and content from chunk
    chunk_content = chunk.content()
    
    # Create XorName from the content
    xor_name = XorName.from_content(chunk_content)
    
    # Print debug info
    print(f"Chunk hash (XorName): {''.join(format(b, '02x') for b in xor_name.as_bytes())}")
    print(f"Content length: {len(chunk_content)}")
    
    # Verify valid chunk
    verified_chunk = verify_chunk(xor_name, chunk_content)
    assert isinstance(verified_chunk, EncryptedChunk)
    assert verified_chunk.content() == chunk_content
    
    # Test with corrupted content
    corrupted_content = bytearray(chunk_content)
    corrupted_content[0] ^= 1  # Flip one bit
    with pytest.raises(ValueError, match="Chunk content hash mismatch"):
        verify_chunk(xor_name, bytes(corrupted_content))

if __name__ == "__main__":
    pytest.main([__file__]) 