import os
import tempfile
from pathlib import Path
import pytest
from self_encryption import (
    PyDataMap,
    PyEncryptedChunk,
    py_encrypt,
    py_encrypt_from_file,
    py_decrypt,
    py_decrypt_from_storage,
    py_shrink_data_map,
)

def test_basic_encryption_decryption():
    # Test data
    data = b"x" * 10_000_000  # 10MB of data
    
    # Encrypt
    data_map, chunks = py_encrypt(data)
    assert len(chunks) > 0
    
    # Decrypt
    decrypted = py_decrypt(data_map, chunks)
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
        data_map, chunk_names = py_encrypt_from_file(str(input_path), str(chunk_dir))
        
        # Create chunk retrieval function
        def get_chunk(hash_hex: str):
            chunk_path = chunk_dir / hash_hex
            return chunk_path.read_bytes()
        
        # Decrypt to new file
        output_path = Path(temp_dir) / "output.dat"
        py_decrypt_from_storage(data_map, str(output_path), get_chunk)
        
        # Verify
        assert input_path.read_bytes() == output_path.read_bytes()

def test_data_map_shrinking():
    # Create large data to ensure multiple chunks
    data = b"x" * 10_000_000
    
    # Encrypt
    data_map, chunks = py_encrypt(data)
    
    # Track stored chunks
    stored_chunks = {}
    def store_chunk(hash_bytes, content):
        stored_chunks[hash_bytes.hex()] = content
    
    # Shrink data map
    shrunk_map, shrink_chunks = py_shrink_data_map(data_map, store_chunk)
    
    # Verify child level is set
    assert shrunk_map.child() is not None
    assert shrunk_map.is_child()
    
    # Collect all chunks
    all_chunks = chunks + shrink_chunks
    
    # Decrypt using all chunks
    decrypted = py_decrypt(shrunk_map, all_chunks)
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
        data_map1, chunks1 = py_encrypt(data)
        decrypted1 = py_decrypt(data_map1, chunks1)
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
            data_map2, chunk_names = py_encrypt_from_file(str(input_path), str(chunk_dir))
            
            # Create chunk retrieval function
            def get_chunk(hash_hex: str):
                chunk_path = chunk_dir / hash_hex
                return chunk_path.read_bytes()
            
            # Decrypt file
            py_decrypt_from_storage(data_map2, str(output_path), get_chunk)
            
            # Verify
            assert data == output_path.read_bytes()
            print(f"✓ File-based encryption/decryption successful")
            
            # Verify data maps
            assert data_map1.len() == data_map2.len()
            assert data_map1.child() == data_map2.child()
            print(f"✓ Data maps match")

if __name__ == "__main__":
    pytest.main([__file__]) 