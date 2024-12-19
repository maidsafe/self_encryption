#!/usr/bin/env python3
"""
self-encryption - Command line interface for self_encryption library

This CLI provides access to all functionality of the self_encryption library,
including encryption, decryption, and advanced features like streaming operations.

The self-encryption algorithm provides:
- Convergent encryption: Same data produces same encrypted chunks
- Obfuscation: Data is split into chunks and interdependent
- Deduplication: Identical chunks are stored only once
- Streaming: Large files can be processed efficiently

Example usage:
    # Encrypt a file
    $ self_encryption encrypt-file input.dat chunks/

    # Decrypt a file
    $ self_encryption decrypt-file data_map.json chunks/ output.dat

    # Decrypt a large file using streaming
    $ self_encryption decrypt-file data_map.json chunks/ output.dat --streaming
"""

import click
from pathlib import Path
import sys

from . import (
    PyDataMap,
    encrypt_from_file,
    decrypt_from_storage,
    streaming_decrypt_from_storage,
)

def print_error(message: str) -> None:
    """Print error message in red.
    
    Args:
        message (str): The error message to print.
    """
    click.secho(f"Error: {message}", fg='red', err=True)

@click.group()
@click.version_option()
def cli() -> None:
    """
    self-encryption - A convergent encryption tool with obfuscation
    
    This tool provides secure data encryption that supports deduplication while
    maintaining strong security through content obfuscation and chunk interdependencies.

    The self-encryption algorithm works by:
    1. Splitting data into chunks
    2. Encrypting each chunk using its own content as the key
    3. Creating interdependencies between chunks for added security
    4. Storing metadata in a DataMap for later reconstruction
    """
    pass

@cli.command()
@click.argument('input-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('output-dir', type=click.Path(file_okay=False))
@click.option('--json', is_flag=True, help='Output data map in JSON format')
def encrypt_file(input_file: str, output_dir: str, json: bool) -> None:
    """
    Encrypt a file and store its chunks.

    The encrypted chunks will be stored in OUTPUT-DIR, and the data map will be
    printed to stdout. The data map is required for later decryption.

    The encryption process:
    1. Reads the input file
    2. Splits it into chunks
    3. Encrypts each chunk
    4. Stores chunks in OUTPUT-DIR
    5. Outputs the DataMap to stdout

    Example:
        $ self_encryption encrypt-file input.dat chunks/
    """
    try:
        data_map, chunk_names = encrypt_from_file(input_file, output_dir)
        click.echo(data_map.to_json())
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

@cli.command()
@click.argument('data-map-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('chunks-dir', type=click.Path(exists=True, file_okay=False))
@click.argument('output-file', type=click.Path(dir_okay=False))
@click.option('--streaming', is_flag=True, help='Use streaming decryption')
def decrypt_file(data_map_file: str, chunks_dir: str, output_file: str, streaming: bool) -> None:
    """
    Decrypt a file using its data map and stored chunks.

    Reads the data map from DATA-MAP-FILE, retrieves chunks from CHUNKS-DIR,
    and writes the decrypted data to OUTPUT-FILE.

    The decryption process:
    1. Reads the DataMap from DATA-MAP-FILE
    2. Retrieves encrypted chunks from CHUNKS-DIR
    3. Decrypts chunks in the correct order
    4. Writes decrypted data to OUTPUT-FILE

    With --streaming:
    - Chunks are retrieved and processed in parallel
    - Memory usage is optimized for large files
    - Decryption is generally faster

    Example:
        $ self_encryption decrypt-file data_map.json chunks/ output.dat
        $ self_encryption decrypt-file data_map.json chunks/ output.dat --streaming
    """
    try:
        # Read data map from file
        data_map_str = Path(data_map_file).read_text()
        try:
            data_map = PyDataMap.from_json(data_map_str)
        except Exception as e:
            print_error(f"Failed to parse data map: {e}")
            sys.exit(1)
        
        chunks_path = Path(chunks_dir)
        
        if streaming:
            def get_chunks(chunk_names: list) -> list:
                return [
                    (chunks_path / chunk_name).read_bytes()
                    for chunk_name in chunk_names
                ]
            streaming_decrypt_from_storage(data_map, output_file, get_chunks)
        else:
            def get_chunk(chunk_name: str) -> bytes:
                chunk_path = chunks_path / chunk_name
                return chunk_path.read_bytes()
            decrypt_from_storage(data_map, output_file, get_chunk)
            
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

if __name__ == '__main__':
    cli()
