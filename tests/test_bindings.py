import tempfile
from pathlib import Path
import pytest
from self_encryption import (
    PyDataMap,
    encrypt,
    encrypt_from_file,
    decrypt,
    decrypt_from_storage,
    streaming_decrypt_from_storage,
)

def test_direct_encryption_decryption():
    # Test data
    data = b"Hello, World!" * 1000
    
    # Encrypt
    data_map, chunks = encrypt(data)
    
    # Decrypt
    decrypted = decrypt(data_map, chunks)
    
    # Verify
    assert data == decrypted

def test_file_encryption_decryption():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        input_path = Path(temp_dir) / "input.dat"
        data = b"x" * 1_000_000  # 1MB
        input_path.write_bytes(data)
        
        # Create output directory for chunks
        chunk_dir = Path(temp_dir) / "chunks"
        chunk_dir.mkdir()
        
        # Encrypt file
        result = encrypt_from_file(str(input_path), str(chunk_dir))
        data_map, chunk_names = result
        
        # Define chunk getter
        def get_chunk(chunk_name: str) -> bytes:
            chunk_path = Path(chunk_dir) / chunk_name
            return chunk_path.read_bytes()
        
        # Decrypt to new file
        output_path = Path(temp_dir) / "output.dat"
        decrypt_from_storage(data_map, str(output_path), get_chunk)
        
        # Verify
        assert input_path.read_bytes() == output_path.read_bytes()

def test_streaming_decryption():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        input_path = Path(temp_dir) / "input.dat"
        data = b"x" * 1_000_000  # 1MB
        input_path.write_bytes(data)
        
        # Create output directory for chunks
        chunk_dir = Path(temp_dir) / "chunks"
        chunk_dir.mkdir()
        
        # Encrypt file
        result = encrypt_from_file(str(input_path), str(chunk_dir))
        data_map, chunk_names = result
        
        # Define chunk getter
        def get_chunks(chunk_names: list) -> list:
            return [
                (Path(chunk_dir) / chunk_name).read_bytes()
                for chunk_name in chunk_names
            ]
        
        # Decrypt using streaming
        output_path = Path(temp_dir) / "output.dat"
        streaming_decrypt_from_storage(data_map, str(output_path), get_chunks)
        
        # Verify
        assert input_path.read_bytes() == output_path.read_bytes()

def test_data_map_json():
    # Create a DataMap with empty chunk infos
    chunk_infos = []
    data_map = PyDataMap(chunk_infos)
    
    # Convert to JSON
    json_str = data_map.to_json()
    
    # Convert back from JSON
    data_map2 = PyDataMap.from_json(json_str)
    
    # Verify
    assert data_map.to_json() == data_map2.to_json()

if __name__ == "__main__":
    pytest.main([__file__]) 