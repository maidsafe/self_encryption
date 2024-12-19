try:
    from ._self_encryption import (
        PyDataMap as DataMap,
        PyXorName as XorName,
        EncryptResult,
        encrypt_from_file,
        decrypt_from_storage,
        streaming_decrypt_from_storage,
        MIN_CHUNK_SIZE,
        MIN_ENCRYPTABLE_BYTES,
        MAX_CHUNK_SIZE,
        COMPRESSION_QUALITY,
    )
    from .cli import cli
except ImportError as e:
    import sys
    print(f"Error importing self_encryption: {e}", file=sys.stderr)
    raise

__all__ = [
    'DataMap',
    'XorName',
    'EncryptResult',
    'encrypt_from_file',
    'decrypt_from_storage',
    'streaming_decrypt_from_storage',
    'MIN_CHUNK_SIZE',
    'MIN_ENCRYPTABLE_BYTES',
    'MAX_CHUNK_SIZE',
    'COMPRESSION_QUALITY',
    'cli',
]