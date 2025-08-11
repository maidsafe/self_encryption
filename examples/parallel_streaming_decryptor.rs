use bytes::Bytes;
use clap::Parser;
use rayon::prelude::*;
use self_encryption::{deserialize, streaming_decrypt_from_storage, DataMap, Error, Result};
use std::{fs::File, io::Read, path::Path};
use xor_name::XorName;

/// Parallel streaming decryptor for self-encrypted files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the data map file
    #[arg(short, long, required = true)]
    data_map: String,

    /// Directory containing the encrypted chunks
    #[arg(short, long, required = true)]
    chunks_dir: String,

    /// Path where the decrypted file should be written
    #[arg(short, long, required = true)]
    output: String,
}

fn validate_paths(args: &Args) -> Result<()> {
    // Check data map file exists and is readable
    if !Path::new(&args.data_map).exists() {
        return Err(Error::Generic(format!(
            "Data map file does not exist: {}",
            args.data_map
        )));
    }

    // Check chunks directory exists and is readable
    let chunks_dir = Path::new(&args.chunks_dir);
    if !chunks_dir.exists() {
        return Err(Error::Generic(format!(
            "Chunks directory does not exist: {}",
            args.chunks_dir
        )));
    }
    if !chunks_dir.is_dir() {
        return Err(Error::Generic(format!(
            "Chunks path is not a directory: {}",
            args.chunks_dir
        )));
    }

    // Check output parent directory exists and is writable
    let output_path = Path::new(&args.output);
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            return Err(Error::Generic(format!(
                "Output directory does not exist: {}",
                parent.display()
            )));
        }
        // Try to verify write permissions
        if !parent
            .metadata()
            .map(|m| m.permissions().readonly())
            .unwrap_or(true)
        {
            return Err(Error::Generic(format!(
                "Output directory is not writable: {}",
                parent.display()
            )));
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate all paths before proceeding
    validate_paths(&args)?;

    // Load the data map from file
    let data_map = load_data_map(&args.data_map)?;

    // Implement the parallel chunk retrieval function
    let get_chunk_parallel = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
        hashes
            .par_iter()
            .map(|(i, hash)| {
                let chunk_path = Path::new(&args.chunks_dir).join(hex::encode(hash));
                let mut chunk_data = Vec::new();
                File::open(&chunk_path)
                    .and_then(|mut file| file.read_to_end(&mut chunk_data))
                    .map_err(|e| Error::Generic(format!("Failed to read chunk: {e}")))?;
                Ok((*i, Bytes::from(chunk_data)))
            })
            .collect()
    };

    // Use the streaming decryption function
    streaming_decrypt_from_storage(&data_map, Path::new(&args.output), get_chunk_parallel)?;

    println!("Successfully decrypted file to: {}", args.output);

    Ok(())
}

// Helper function to load data map from a file
fn load_data_map(path: &str) -> Result<DataMap> {
    let mut file =
        File::open(path).map_err(|e| Error::Generic(format!("Failed to open data map: {e}")))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| Error::Generic(format!("Failed to read data map: {e}")))?;
    deserialize(&data)
}
