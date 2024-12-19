#!/usr/bin/env python3
"""
self-encryption-cli - Command line interface for self_encryption library

This CLI provides access to all functionality of the self_encryption library,
including encryption, decryption, and advanced features like streaming operations
and chunk verification.
"""

import click
from pathlib import Path
from typing import Optional
import sys

from ._self_encryption import (
    PyDataMap as DataMap,
    PyXorName as XorName,
    encrypt_from_file,
    decrypt_from_storage,
    streaming_decrypt_from_storage,
)

def print_error(message: str):
    """Print error message in red."""
    click.secho(f"Error: {message}", fg='red', err=True)

@click.group()
@click.version_option()
def cli():
    """
    self-encryption - A convergent encryption tool with obfuscation
    
    This tool provides secure data encryption that supports deduplication while
    maintaining strong security through content obfuscation and chunk interdependencies.
    """
    pass

@cli.command()
@click.argument('input-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('output-dir', type=click.Path(file_okay=False))
@click.option('--json', is_flag=True, help='Output data map in JSON format')
def encrypt_file(input_file: str, output_dir: str, json: bool):
    """
    Encrypt a file and store its chunks.

    The encrypted chunks will be stored in OUTPUT-DIR, and the data map will be
    printed to stdout. The data map is required for later decryption.

    Example:
        $ self-encryption encrypt-file input.dat chunks/
    """
    try:
        result = encrypt_from_file(input_file, output_dir)
        data_map = result.data_map
        click.echo(data_map.to_json())
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

@cli.command()
@click.argument('data-map-file', type=click.Path(exists=True, dir_okay=False))
@click.argument('chunks-dir', type=click.Path(exists=True, file_okay=False))
@click.argument('output-file', type=click.Path(dir_okay=False))
@click.option('--streaming', is_flag=True, help='Use streaming decryption')
def decrypt_file(data_map_file: str, chunks_dir: str, output_file: str, streaming: bool):
    """
    Decrypt a file using its data map and stored chunks.

    Reads the data map from DATA-MAP-FILE, retrieves chunks from CHUNKS-DIR,
    and writes the decrypted data to OUTPUT-FILE.

    Example:
        $ self-encryption decrypt-file data_map.json chunks/ output.dat
    """
    try:
        # Read data map from file
        data_map_str = Path(data_map_file).read_text()
        try:
            data_map = DataMap.from_json(data_map_str)
        except Exception as e:
            print_error(f"Failed to parse data map: {e}")
            sys.exit(1)
        
        if streaming:
            streaming_decrypt_from_storage(data_map, output_file, chunks_dir)
        else:
            decrypt_from_storage(data_map, output_file, chunks_dir)
            
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

@cli.command()
@click.argument('chunk-file', type=click.Path(exists=True, dir_okay=False))
def verify(chunk_file: str):
    """
    Verify the integrity of an encrypted chunk.

    Checks if the chunk's content matches its XorName.

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
def shrink(data_map_file: str, chunks_dir: str, output_map_file: str):
    """
    Shrink a data map by consolidating its chunks.

    Reads the data map from DATA-MAP-FILE, processes chunks from CHUNKS-DIR,
    and writes the optimized data map to OUTPUT-MAP-FILE.

    Example:
        $ self-encryption shrink data_map.json chunks/ optimized_map.json
    """
    try:
        # Read data map from file
        with open(data_map_file, 'r') as f:
            data_map = DataMap.from_json(f.read())
        
        chunks_path = Path(chunks_dir)
        
        def store_chunk(chunk: EncryptedChunk) -> None:
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
