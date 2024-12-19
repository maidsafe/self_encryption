use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use serde::{Deserialize, Serialize};

use crate::{
    decrypt_from_storage as rust_decrypt_from_storage, encrypt_from_file as rust_encrypt_from_file,
    streaming_decrypt_from_storage as rust_streaming_decrypt_from_storage, DataMap, EncryptedChunk,
};

/// A Python wrapper for the DataMap struct.
///
/// DataMap contains metadata about encrypted chunks, including their order,
/// sizes, and interdependencies. It is required for decryption.
///
/// Example:
///     # Create a DataMap from JSON
///     data_map = PyDataMap.from_json(json_str)
///
///     # Convert DataMap to JSON for storage
///     json_str = data_map.to_json()
#[pyclass]
#[derive(Clone)]
pub struct PyDataMap {
    inner: DataMap,
}

/// A Python wrapper for the EncryptedChunk struct.
///
/// EncryptedChunk represents an encrypted piece of data along with its
/// metadata like size and hash. Chunks are stored separately and
/// referenced by the DataMap.
///
/// Example:
///     # Access chunk metadata
///     chunk = PyEncryptedChunk(...)
///     size = chunk.content_size()
///     hash = chunk.hash()
#[pyclass]
#[derive(Clone)]
pub struct PyEncryptedChunk {
    inner: EncryptedChunk,
}

#[pymethods]
impl PyDataMap {
    /// Create a new DataMap from a JSON string.
    ///
    /// Args:
    ///     json_str (str): A JSON string containing the DataMap data.
    ///
    /// Returns:
    ///     PyDataMap: A new DataMap instance.
    ///
    /// Raises:
    ///     ValueError: If the JSON string is invalid or missing required fields.
    #[staticmethod]
    pub fn from_json(json_str: &str) -> PyResult<Self> {
        let inner = serde_json::from_str(json_str)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {}", e)))?;
        Ok(Self { inner })
    }

    /// Convert the DataMap to a JSON string.
    ///
    /// Returns:
    ///     str: A JSON string representation of the DataMap.
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize: {}", e))
        })
    }
}

#[pymethods]
impl PyEncryptedChunk {
    /// Get the size of the original content before encryption.
    ///
    /// Returns:
    ///     int: The size in bytes of the original content.
    pub fn content_size(&self) -> usize {
        self.inner.content_size()
    }

    /// Get the hash of the encrypted chunk.
    ///
    /// Returns:
    ///     bytes: The SHA256 hash of the encrypted chunk.
    pub fn hash(&self) -> Vec<u8> {
        self.inner.hash().to_vec()
    }
}

/// Encrypt a file and store its chunks.
///
/// This function reads a file, splits it into chunks, encrypts them,
/// and stores them in the specified directory.
///
/// Args:
///     input_file (str): Path to the file to encrypt.
///     output_dir (str): Directory to store the encrypted chunks.
///
/// Returns:
///     tuple: A tuple containing:
///         - PyDataMap: The data map required for decryption
///         - list: List of chunk filenames that were created
///
/// Raises:
///     OSError: If the input file cannot be read or chunks cannot be written.
///     ValueError: If the input parameters are invalid.
#[pyfunction]
pub fn encrypt_from_file(input_file: &str, output_dir: &str) -> PyResult<(PyDataMap, Vec<String>)> {
    let (data_map, chunk_names) = rust_encrypt_from_file(input_file, output_dir)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("Encryption failed: {}", e)))?;
    Ok((PyDataMap { inner: data_map }, chunk_names))
}

/// Decrypt data using a DataMap and stored chunks.
///
/// This function retrieves encrypted chunks using the provided callback,
/// decrypts them according to the DataMap, and writes the result to a file.
///
/// Args:
///     data_map (PyDataMap): The data map containing chunk metadata.
///     output_file (str): Path where the decrypted data will be written.
///     get_chunk (callable): Function that takes a chunk name and returns its bytes.
///
/// Raises:
///     OSError: If chunks cannot be retrieved or output cannot be written.
///     ValueError: If the data map is invalid or chunks are corrupted.
#[pyfunction]
pub fn decrypt_from_storage(
    data_map: PyDataMap,
    output_file: &str,
    get_chunk: &PyAny,
) -> PyResult<()> {
    let get_chunk_wrapper = |name: &str| -> Result<Vec<u8>, String> {
        let bytes = get_chunk
            .call1((name,))
            .map_err(|e| format!("Failed to call get_chunk: {}", e))?;
        let bytes = bytes
            .downcast::<PyBytes>()
            .map_err(|e| format!("get_chunk must return bytes: {}", e))?;
        Ok(bytes.as_bytes().to_vec())
    };

    rust_decrypt_from_storage(&data_map.inner, output_file, get_chunk_wrapper)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("Decryption failed: {}", e)))
}

/// Decrypt data using streaming for better performance with large files.
///
/// This function uses parallel processing and streaming to efficiently
/// decrypt large files while minimizing memory usage.
///
/// Args:
///     data_map (PyDataMap): The data map containing chunk metadata.
///     output_file (str): Path where the decrypted data will be written.
///     get_chunks (callable): Function that takes a list of chunk names and returns their bytes.
///
/// Raises:
///     OSError: If chunks cannot be retrieved or output cannot be written.
///     ValueError: If the data map is invalid or chunks are corrupted.
#[pyfunction]
pub fn streaming_decrypt_from_storage(
    data_map: PyDataMap,
    output_file: &str,
    get_chunks: &PyAny,
) -> PyResult<()> {
    let get_chunks_wrapper = |names: &[String]| -> Result<Vec<Vec<u8>>, String> {
        let chunks = get_chunks
            .call1((names,))
            .map_err(|e| format!("Failed to call get_chunks: {}", e))?;
        let chunks = chunks
            .iter()
            .map_err(|e| format!("get_chunks must return a list: {}", e))?;
        let mut result = Vec::new();
        for chunk in chunks {
            let chunk = chunk.map_err(|e| format!("Failed to iterate chunks: {}", e))?;
            let bytes = chunk
                .downcast::<PyBytes>()
                .map_err(|e| format!("get_chunks must return bytes: {}", e))?;
            result.push(bytes.as_bytes().to_vec());
        }
        Ok(result)
    };

    rust_streaming_decrypt_from_storage(&data_map.inner, output_file, get_chunks_wrapper).map_err(
        |e| pyo3::exceptions::PyOSError::new_err(format!("Streaming decryption failed: {}", e)),
    )
}

/// Initialize the Python module.
#[pymodule]
fn self_encryption(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyDataMap>()?;
    m.add_class::<PyEncryptedChunk>()?;
    m.add_function(wrap_pyfunction!(encrypt_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_from_storage, m)?)?;
    m.add_function(wrap_pyfunction!(streaming_decrypt_from_storage, m)?)?;
    Ok(())
}
