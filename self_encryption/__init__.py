"""
self_encryption - A convergent encryption library with obfuscation

This library provides a secure way to encrypt data that supports deduplication while
maintaining strong security through content obfuscation and chunk interdependencies.

Key Features:
    - Content-based chunking for deduplication
    - Convergent encryption with obfuscation
    - Self-validating chunks through content hashing
    - Streaming operations for large files
    - Parallel chunk processing
    - Both in-memory and file-based operations
    - Command-line interface for all operations

Basic Usage:
    >>> from self_encryption import encrypt, decrypt
    >>> data = b"Hello, World!" * 1000  # Must be at least 3072 bytes
    >>> data_map, chunks = encrypt(data)
    >>> decrypted = decrypt(data_map, chunks)
    >>> assert data == decrypted

File Operations:
    >>> from pathlib import Path
    >>> from self_encryption import encrypt_from_file, decrypt_from_storage
    >>> data_map, chunk_names = encrypt_from_file("input.dat", "chunks/")
    >>> def get_chunk(hash_hex):
    ...     return (Path("chunks") / hash_hex).read_bytes()
    >>> decrypt_from_storage(data_map, "output.dat", get_chunk)

Streaming Operations:
    >>> from self_encryption import streaming_encrypt_from_file
    >>> def store_chunk(name, content):
    ...     (Path("chunks") / name).write_bytes(content)
    >>> data_map = streaming_encrypt_from_file("large_file.dat", store_chunk)
    >>> print(f"Created {data_map.len()} chunks")

Command Line Usage:
    The library includes a command-line interface for all operations:

    # Encrypt a file
    $ self-encryption encrypt-file input.dat chunks/

    # Decrypt a file
    $ self-encryption decrypt-file data_map.json chunks/ output.dat

    # Verify a chunk
    $ self-encryption verify chunks/abc123.dat

    # Shrink a data map
    $ self-encryption shrink data_map.json chunks/ optimized_map.json

    For more information about CLI commands:
    $ self-encryption --help

Classes:
    DataMap - Contains metadata about encrypted chunks
        Methods:
            new(chunk_infos) -> DataMap
            with_child(chunk_infos, child) -> DataMap
            child() -> Optional[int]
            is_child() -> bool
            len() -> int
            infos() -> List[Tuple[int, bytes, bytes, int]]

    EncryptedChunk - Represents an encrypted chunk of data
        Methods:
            new(content: bytes) -> EncryptedChunk
            content() -> bytes
            from_bytes(content: bytes) -> EncryptedChunk

    XorName - Content-addressed names for chunks
        Methods:
            new(bytes) -> XorName
            from_content(content) -> XorName
            as_bytes() -> bytes

Functions:
    encrypt(data: bytes) -> Tuple[DataMap, List[EncryptedChunk]]
        Encrypt data in memory, returning a data map and encrypted chunks.
        The input data must be at least 3072 bytes.

    encrypt_from_file(input_path: str, output_dir: str) -> Tuple[DataMap, List[str]]
        Encrypt a file and store chunks to disk. Returns a data map and chunk names.
        The input file must be at least 3072 bytes.

    streaming_encrypt_from_file(input_path: str, store_chunk: Callable[[str, bytes], None]) -> DataMap
        Stream-encrypt a file and store chunks using a custom storage backend.
        Memory efficient for large files. Returns only the data map.

    decrypt(data_map: DataMap, chunks: List[EncryptedChunk]) -> bytes
        Decrypt data using provided chunks in memory.

    decrypt_from_storage(data_map: DataMap, output_path: str, get_chunk: Callable) -> None
        Decrypt data using chunks from storage, writing directly to a file.
        Suitable for files that can fit in memory.

    streaming_decrypt_from_storage(data_map: DataMap, output_path: str, get_chunks: Callable) -> None
        Decrypt data using parallel chunk retrieval for improved performance.
        Optimized for large files and remote storage backends.
        Retrieves multiple chunks in parallel for better throughput.

    shrink_data_map(data_map: DataMap, store_chunk: Callable) -> Tuple[DataMap, List[EncryptedChunk]]
        Shrink a data map by recursively encrypting it. Useful for large files.

    verify_chunk(name: XorName, content: bytes) -> EncryptedChunk
        Verify the integrity of an encrypted chunk.

For more detailed documentation about specific functions or classes:
    >>> help(self_encryption.DataMap)
    >>> help(self_encryption.encrypt)
"""

from ._self_encryption import (
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
    streaming_encrypt_from_file,
)

from .cli import cli

__version__ = "0.32.2"

__all__ = [
    "DataMap",
    "EncryptedChunk",
    "XorName",
    "encrypt",
    "encrypt_from_file",
    "decrypt",
    "decrypt_from_storage",
    "shrink_data_map",
    "streaming_decrypt_from_storage",
    "verify_chunk",
    "streaming_encrypt_from_file",
    "cli",
]