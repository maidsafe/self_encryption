#!/usr/bin/env python3
"""
self-encryption-cli - Command line interface for self_encryption library.

This module provides a command-line interface to the self_encryption library,
offering easy access to encryption, decryption, and advanced features through
simple commands.

The CLI is built using Click and provides the following commands:
    - encrypt-file: Encrypt a file and store its chunks
    - decrypt-file: Decrypt a file using stored chunks
    - verify: Verify the integrity of an encrypted chunk
    - shrink: Optimize a data map by consolidating chunks

Each command provides detailed help information accessible via --help.

Example Usage:
    # Encrypt a file
    $ self-encryption encrypt-file input.dat chunks/

    # Decrypt a file
    $ self-encryption decrypt-file data_map.json chunks/ output.dat

    # Use streaming decryption for large files
    $ self-encryption decrypt-file --streaming data_map.json chunks/ output.dat

    # Verify a chunk's integrity
    $ self-encryption verify chunks/abc123.dat

    # Optimize a data map
    $ self-encryption shrink data_map.json chunks/ optimized_map.json
"""

import click
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any
import sys
import json

from ._self_encryption import (
    PyDataMap as DataMap,
    PyXorName as XorName,
    encrypt_from_file,
    decrypt_from_storage,
    streaming_decrypt_from_storage,
)

def print_error(message: str) -> None:
    """
    Print an error message in red to stderr.

    Args:
        message (str): The error message to display.
    """
    click.secho(f"Error: {message}", fg='red', err=True)

@click.group()
@click.version_option()
def cli() -> None:
    """
    self-encryption - A convergent encryption tool with obfuscation.

    This tool provides secure data encryption that supports deduplication while
    maintaining strong security through content obfuscation and chunk interdependencies.

    Key Features:
        - Content-based chunking for efficient storage
        - Convergent encryption for deduplication
        - Chunk obfuscation for enhanced security
        - Streaming support for large files
    """
    pass

@cli.command()
@click.argument('input-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('output-dir', type=click.Path(file_okay=False))
@click.option('--json', is_flag=True, help='Output data map in JSON format')
def encrypt_file(input_file: str, output_dir: str, json: bool) -> None:
    """
    Encrypt a file and store its chunks.

    This command takes an input file, encrypts it using self-encryption,
    and stores the resulting chunks in the specified output directory.
    The data map required for later decryption is printed to stdout.

    Args:
        input_file (str): Path to the file to encrypt.
        output_dir (str): Directory where encrypted chunks will be stored.
        json (bool): Whether to format output as JSON.

    Example:
        $ self-encryption encrypt-file input.dat chunks/
    """
    try:
        result = encrypt_from_file(input_file, output_dir)
        data_map, chunk_names = result
        click.echo(data_map.to_json())
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

@cli.command()
@click.argument('data-map-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('chunks-dir', type=click.Path(exists=True, file_okay=False))
@click.argument('output-file', type=click.Path(dir_okay=False))
@click.option('--streaming', is_flag=True, help='Use streaming decryption for large files')
def decrypt_file(data_map_file: str, chunks_dir: str, output_file: str, streaming: bool) -> None:
    """
    Decrypt a file using stored chunks.

    This command reads a data map from a file, retrieves the necessary chunks
    from the specified directory, and reconstructs the original file. For large
    files, the --streaming option can be used to reduce memory usage.

    Args:
        data_map_file (str): Path to the JSON file containing the data map.
        chunks_dir (str): Directory containing the encrypted chunks.
        output_file (str): Path where the decrypted file will be written.
        streaming (bool): Whether to use streaming decryption.

    Example:
        $ self-encryption decrypt-file data_map.json chunks/ output.dat
    """
    try:
        # Read data map from file
        with open(data_map_file, 'r') as f:
            data_map = DataMap.from_json(f.read())

        # Create chunk getter function
        def get_chunk(chunk_name: str) -> bytes:
            """Retrieve a single chunk by name."""
            chunk_path = Path(chunks_dir) / chunk_name
            return chunk_path.read_bytes()

        # Create chunk getter function for streaming
        def get_chunks(chunk_names: List[str]) -> List[bytes]:
            """Retrieve multiple chunks by name."""
            return [
                (Path(chunks_dir) / chunk_name).read_bytes()
                for chunk_name in chunk_names
            ]

        # Decrypt using appropriate method
        if streaming:
            streaming_decrypt_from_storage(data_map, output_file, get_chunks)
        else:
            decrypt_from_storage(data_map, output_file, get_chunk)

    except Exception as e:
        print_error(str(e))
        sys.exit(1)

@cli.command()
@click.argument('chunk-file', type=click.Path(exists=True, dir_okay=False))
def verify(chunk_file: str) -> None:
    """
    Verify the integrity of an encrypted chunk.

    This command checks if a chunk's content matches its XorName identifier.
    The chunk filename should be its XorName in hexadecimal format.

    Args:
        chunk_file (str): Path to the chunk file to verify.

    Example:
        $ self-encryption verify chunk_abc123.dat
    """
    try:
        chunk_path = Path(chunk_file)
        content = chunk_path.read_bytes()
        name = XorName.from_hex(chunk_path.stem)
        chunk = verify_chunk(name, content)
        click.echo(f"Chunk {chunk_path.name} verified successfully")
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

@cli.command()
@click.argument('data-map-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('chunks-dir', type=click.Path(exists=True, file_okay=False))
@click.argument('output-map-file', type=click.Path())
def shrink(data_map_file: str, chunks_dir: str, output_map_file: str) -> None:
    """
    Shrink a data map by consolidating its chunks.

    This command optimizes storage by identifying and consolidating duplicate
    chunks. It reads the original data map, processes the chunks, and creates
    a new optimized data map.

    Args:
        data_map_file (str): Path to the input data map JSON file.
        chunks_dir (str): Directory containing the encrypted chunks.
        output_map_file (str): Path where the optimized data map will be written.

    Example:
        $ self-encryption shrink data_map.json chunks/ optimized_map.json
    """
    try:
        # Read data map from file
        with open(data_map_file, 'r') as f:
            data_map = DataMap.from_json(f.read())
        
        chunks_path = Path(chunks_dir)
        
        def store_chunk(chunk: EncryptedChunk) -> None:
            """Store a chunk to disk."""
            chunk_path = chunks_path / chunk.name.hex()
            chunk_path.write_bytes(chunk.content)
        
        new_data_map, _ = shrink_data_map(data_map, store_chunk)
        
        # Write new data map to file
        with open(output_map_file, 'w') as f:
            f.write(new_data_map.to_json())
            
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

if __name__ == '__main__':
    cli()
