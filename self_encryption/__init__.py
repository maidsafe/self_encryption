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

Advanced Features:
    - Hierarchical data maps for large files
    - Streaming decryption with parallel chunk retrieval
    - Chunk verification and validation
    - XorName operations for content addressing

Classes:
    DataMap - Contains metadata about encrypted chunks
    EncryptedChunk - Represents an encrypted chunk of data
    XorName - Content-addressed names for chunks

Functions:
    encrypt(data: bytes) -> Tuple[DataMap, List[EncryptedChunk]]
    encrypt_from_file(input_path: str, output_dir: str) -> Tuple[DataMap, List[str]]
    decrypt(data_map: DataMap, chunks: List[EncryptedChunk]) -> bytes
    decrypt_from_storage(data_map: DataMap, output_path: str, get_chunk: Callable) -> None
    shrink_data_map(data_map: DataMap, store_chunk: Callable) -> Tuple[DataMap, List[EncryptedChunk]]
    streaming_decrypt_from_storage(data_map: DataMap, output_path: str, get_chunks: Callable) -> None
    verify_chunk(name: XorName, content: bytes) -> EncryptedChunk

For more information about specific functions or classes, use help() on the individual items:
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
)

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
] 