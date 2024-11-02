import os
import tempfile
from self_encryption import (
    DataMap, 
    EncryptedChunk,
    encrypt_bytes,
    decrypt_chunks,
    encrypt_file,
    decrypt_from_files,
    py_shrink_data_map,
    py_get_root_data_map
)

def test_basic_encryption():
    # Test basic encryption/decryption
    data = b"Hello, World!" * 1000  # Make it large enough for encryption
    data_map, chunks = encrypt_bytes(data)
    decrypted = decrypt_chunks(data_map, chunks)
    assert data == decrypted

def test_file_operations():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        input_path = os.path.join(temp_dir, "input.txt")
        with open(input_path, "wb") as f:
            f.write(b"Hello, World!" * 1000)

        # Create chunk directory
        chunk_dir = os.path.join(temp_dir, "chunks")
        os.makedirs(chunk_dir)

        # Test file encryption
        data_map, chunk_names = encrypt_file(input_path, chunk_dir)
        
        # Test file decryption
        output_path = os.path.join(temp_dir, "output.txt")
        decrypt_from_files(chunk_dir, data_map, output_path)

        # Verify content
        with open(input_path, "rb") as f:
            original = f.read()
        with open(output_path, "rb") as f:
            decrypted = f.read()
        assert original == decrypted

def test_data_map_operations():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        input_path = os.path.join(temp_dir, "input.txt")
        with open(input_path, "wb") as f:
            f.write(b"Hello, World!" * 1000)

        chunk_dir = os.path.join(temp_dir, "chunks")
        os.makedirs(chunk_dir)

        # Get initial data map
        data_map, _ = encrypt_file(input_path, chunk_dir)

        # Test shrinking
        shrunk_map = py_shrink_data_map(data_map, chunk_dir)
        
        # Test getting root map
        root_map = py_get_root_data_map(shrunk_map, chunk_dir)

        # Verify we can still decrypt using root map
        output_path = os.path.join(temp_dir, "output.txt")
        decrypt_from_files(chunk_dir, root_map, output_path)

        with open(input_path, "rb") as f:
            original = f.read()
        with open(output_path, "rb") as f:
            decrypted = f.read()
        assert original == decrypted

if __name__ == "__main__":
    test_basic_encryption()
    test_file_operations()
    test_data_map_operations()
    print("All tests passed!") 