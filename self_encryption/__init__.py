"""
Self-encryption library with convergent encryption and obfuscation.

This library provides tools for self-encrypting data into chunks that can be
stored and retrieved independently. It uses convergent encryption to ensure
that identical data produces identical chunks.

Key Features:
    - Content-based chunking for efficient storage
    - Convergent encryption for deduplication
    - Chunk obfuscation for enhanced security
    - Streaming support for large files
    - CLI interface for easy access

Classes:
    DataMap: Contains metadata about encrypted chunks and their relationships.
        Tracks chunk identifiers, sizes, and relationships for reconstruction.
        
    EncryptedChunk: Represents an encrypted piece of data.
        Contains the encrypted content and metadata for verification.
        
    XorName: Content-addressed identifier for chunks.
        Provides deterministic naming based on chunk content.
        
    ChunkInfo: Metadata about a single chunk in a DataMap.
        Stores source and destination hashes, sizes, and indices.

Functions:
    encrypt(data: bytes) -> Tuple[DataMap, List[EncryptedChunk]]:
        Encrypt raw data into chunks. Returns a data map and list of chunks.
        
    decrypt(data_map: DataMap, chunks: List[EncryptedChunk]) -> bytes:
        Decrypt data using a data map and list of chunks.
        
    encrypt_from_file(input_path: str, output_dir: str) -> Tuple[DataMap, List[str]]:
        Encrypt a file and store its chunks. Returns a data map and chunk names.
        
    decrypt_from_storage(data_map: DataMap, output_path: str, get_chunk: Callable) -> None:
        Decrypt data using stored chunks and a chunk retrieval function.
        
    streaming_decrypt_from_storage(data_map: DataMap, output_path: str, get_chunks: Callable) -> None:
        Stream-based decryption for large files using batched chunk retrieval.

CLI Commands:
    encrypt-file: Encrypt a file and store its chunks
    decrypt-file: Decrypt a file using stored chunks
    verify: Verify the integrity of an encrypted chunk
    shrink: Optimize a data map by consolidating chunks

Example:
    >>> from self_encryption import encrypt, decrypt
    >>> data = b"Hello, World!"
    >>> data_map, chunks = encrypt(data)
    >>> decrypted = decrypt(data_map, chunks)
    >>> assert data == bytes(decrypted)
"""

try:
    from importlib.metadata import version
    __version__ = version("self_encryption")
except ImportError:
    from importlib_metadata import version  # type: ignore
    __version__ = version("self_encryption")
except Exception:
    __version__ = "unknown"

try:
    from ._self_encryption import (
        PyDataMap,
        PyEncryptedChunk,
        PyXorName,
        PyChunkInfo,
        encrypt,
        decrypt,
        encrypt_from_file,
        decrypt_from_storage,
        streaming_decrypt_from_storage,
    )
    DataMap = PyDataMap
    EncryptedChunk = PyEncryptedChunk
    XorName = PyXorName
    ChunkInfo = PyChunkInfo
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import Rust module: {e}")
    DataMap = None
    EncryptedChunk = None
    XorName = None
    ChunkInfo = None
    encrypt = None
    decrypt = None
    encrypt_from_file = None
    decrypt_from_storage = None
    streaming_decrypt_from_storage = None

from .cli import cli

__all__ = [
    "DataMap",
    "EncryptedChunk",
    "XorName",
    "ChunkInfo",
    "encrypt",
    "decrypt",
    "encrypt_from_file",
    "decrypt_from_storage",
    "streaming_decrypt_from_storage",
    "cli",
]