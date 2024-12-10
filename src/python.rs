/// Python bindings for self-encryption functionality.
///
/// This module provides Python bindings for the self-encryption library, which implements
/// convergent encryption with content deduplication and obfuscation. The library splits
/// data into chunks, encrypts them independently, and creates a data map that describes
/// how to reassemble the original data.
///
/// Key Features:
///   - Content-based chunking for deduplication
///   - Convergent encryption with obfuscation
///   - Self-validating chunks through content hashing
///   - Streaming operations for large files
///   - Parallel chunk processing
///   - Both in-memory and file-based operations
///
/// Basic Usage:
///   ```python
///   from self_encryption import encrypt, decrypt
///   
///   # In-memory encryption
///   data = b"Hello, World!" * 1000  # Must be at least 3072 bytes
///   data_map, chunks = encrypt(data)
///   decrypted = decrypt(data_map, chunks)
///   assert data == decrypted
///   
///   # File-based encryption
///   from pathlib import Path
///   data_map, chunk_names = encrypt_from_file("input.dat", "chunks/")
///   
///   # Custom storage backend
///   def get_chunk(hash_hex):
///       return (Path("chunks") / hash_hex).read_bytes()
///   decrypt_from_storage(data_map, "output.dat", get_chunk)
///   ```
use crate::{
    decrypt as rust_decrypt, decrypt_from_storage as rust_decrypt_from_storage,
    encrypt as rust_encrypt, encrypt_from_file as rust_encrypt_from_file,
    shrink_data_map as rust_shrink_data_map,
    streaming_decrypt_from_storage as rust_streaming_decrypt_from_storage,
    streaming_encrypt_from_file as rust_streaming_encrypt_from_file, ChunkInfo,
    DataMap as RustDataMap, EncryptedChunk as RustEncryptedChunk, Error, Result,
};
use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use std::path::PathBuf;
use xor_name::XorName;

#[pyclass(name = "DataMap")]
/// A data map containing information about encrypted chunks.
///
/// The DataMap contains metadata about how a file was split and encrypted into chunks,
/// including the hashes needed to verify and decrypt the chunks.
///
/// Attributes:
///     child (Optional[int]): The child level of this data map, if it's part of a hierarchy
///     len (int): The number of chunks in this data map
///
/// Methods:
///     is_child() -> bool: Check if this is a child data map
///     infos() -> List[Tuple[int, bytes, bytes, int]]: Get chunk information
#[derive(Clone)]
struct PyDataMap {
    inner: RustDataMap,
}

#[pyclass(name = "EncryptedChunk")]
/// An encrypted chunk of data.
///
/// Represents a single encrypted chunk of data that was created during the encryption process.
///
/// Methods:
///     content() -> bytes: Get the encrypted content of this chunk
///     from_bytes(content: bytes) -> EncryptedChunk: Create a new chunk from bytes
#[derive(Clone)]
struct PyEncryptedChunk {
    inner: RustEncryptedChunk,
}

#[pyclass(name = "XorName")]
#[derive(Clone)]
struct PyXorName {
    inner: XorName,
}

#[pymethods]
impl PyDataMap {
    #[new]
    /// Create a new DataMap from chunk information.
    ///
    /// Args:
    ///     chunk_infos: List of tuples containing (index, dst_hash, src_hash, src_size)
    ///
    /// Returns:
    ///     DataMap: A new data map instance
    fn new(chunk_infos: Vec<(usize, Vec<u8>, Vec<u8>, usize)>) -> Self {
        let infos = chunk_infos
            .into_iter()
            .map(|(index, dst_hash, src_hash, src_size)| ChunkInfo {
                index,
                dst_hash: XorName::from_content(&dst_hash),
                src_hash: XorName::from_content(&src_hash),
                src_size,
            })
            .collect();
        Self {
            inner: RustDataMap::new(infos),
        }
    }

    #[staticmethod]
    /// Create a new DataMap with a child level.
    ///
    /// Args:
    ///     chunk_infos: List of tuples containing (index, dst_hash, src_hash, src_size)
    ///     child: The child level for this data map
    ///
    /// Returns:
    ///     DataMap: A new data map instance with the specified child level
    fn with_child(chunk_infos: Vec<(usize, Vec<u8>, Vec<u8>, usize)>, child: usize) -> Self {
        let infos = chunk_infos
            .into_iter()
            .map(|(index, dst_hash, src_hash, src_size)| ChunkInfo {
                index,
                dst_hash: XorName::from_content(&dst_hash),
                src_hash: XorName::from_content(&src_hash),
                src_size,
            })
            .collect();
        Self {
            inner: RustDataMap::with_child(infos, child),
        }
    }

    /// Get the child level of this data map.
    ///
    /// Returns:
    ///     Optional[int]: The child level if this is a child data map, None otherwise
    fn child(&self) -> Option<usize> {
        self.inner.child()
    }

    /// Check if this is a child data map.
    ///
    /// Returns:
    ///     bool: True if this is a child data map, False otherwise
    fn is_child(&self) -> bool {
        self.inner.is_child()
    }

    /// Get the number of chunks in this data map.
    ///
    /// Returns:
    ///     int: The number of chunks
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// Get information about all chunks in this data map.
    ///
    /// Returns:
    ///     List[Tuple[int, bytes, bytes, int]]: List of tuples containing
    ///         (index, dst_hash, src_hash, src_size) for each chunk
    fn infos(&self) -> Vec<(usize, Vec<u8>, Vec<u8>, usize)> {
        self.inner
            .infos()
            .into_iter()
            .map(|info| {
                (
                    info.index,
                    info.dst_hash.0.to_vec(),
                    info.src_hash.0.to_vec(),
                    info.src_size,
                )
            })
            .collect()
    }
}

#[pymethods]
impl PyEncryptedChunk {
    #[new]
    /// Create a new EncryptedChunk from bytes.
    ///
    /// Args:
    ///     content (bytes): The encrypted content
    ///
    /// Returns:
    ///     EncryptedChunk: A new encrypted chunk instance
    fn new(content: Vec<u8>) -> Self {
        Self {
            inner: RustEncryptedChunk {
                content: Bytes::from(content),
            },
        }
    }

    /// Get the content of this chunk.
    ///
    /// Returns:
    ///     bytes: The encrypted content
    fn content(&self) -> &[u8] {
        &self.inner.content
    }

    #[classmethod]
    /// Create a new EncryptedChunk from Python bytes.
    ///
    /// Args:
    ///     content (bytes): The encrypted content
    ///
    /// Returns:
    ///     EncryptedChunk: A new encrypted chunk instance
    fn from_bytes(_cls: &PyType, content: &PyBytes) -> PyResult<Self> {
        Ok(Self::new(content.as_bytes().to_vec()))
    }
}

#[pymethods]
impl PyXorName {
    #[new]
    fn new(bytes: &PyBytes) -> Self {
        Self {
            inner: XorName::from_content(bytes.as_bytes()),
        }
    }

    #[staticmethod]
    fn from_content(content: &PyBytes) -> Self {
        Self {
            inner: XorName::from_content(content.as_bytes()),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.inner.0.to_vec()
    }
}

#[pyfunction]
/// Encrypt data in memory.
///
/// This function takes raw bytes, splits them into chunks, and encrypts each chunk
/// independently. It returns both the data map (which describes how to reassemble
/// the chunks) and the encrypted chunks themselves.
///
/// The minimum input size is 3072 bytes, as this is required for the chunking
/// algorithm to work effectively.
///
/// Args:
///     data (bytes): The data to encrypt (must be at least 3072 bytes)
///
/// Returns:
///     Tuple[DataMap, List[EncryptedChunk]]: A tuple containing:
///         - DataMap: Contains metadata about the encrypted chunks
///         - List[EncryptedChunk]: The list of encrypted chunks
///
/// Raises:
///     ValueError: If the input data is too small or encryption fails
///     
/// Example:
///     ```python
///     data = b"Hello, World!" * 1000
///     data_map, chunks = encrypt(data)
///     ```
fn encrypt(_py: Python<'_>, data: &PyBytes) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let bytes = Bytes::from(data.as_bytes().to_vec());
    let (data_map, chunks) = rust_encrypt(bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((
        PyDataMap { inner: data_map },
        chunks
            .into_iter()
            .map(|c| PyEncryptedChunk { inner: c })
            .collect(),
    ))
}

#[pyfunction]
/// Encrypt a file and store chunks to disk.
///
/// This function reads a file, splits it into chunks, encrypts each chunk, and
/// stores the encrypted chunks in the specified output directory. The chunks are
/// named using their content hash (XorName) in hexadecimal format.
///
/// The input file must be at least 3072 bytes in size.
///
/// Args:
///     input_path (str): Path to the input file to encrypt
///     output_dir (str): Directory where encrypted chunks will be stored
///
/// Returns:
///     Tuple[DataMap, List[str]]: A tuple containing:
///         - DataMap: Contains metadata about the encrypted chunks
///         - List[str]: List of chunk filenames (hex format of their XorNames)
///
/// Raises:
///     ValueError: If the input file is too small or encryption fails
///     OSError: If there are file system errors
///     
/// Example:
///     ```python
///     data_map, chunk_names = encrypt_from_file("input.dat", "chunks/")
///     print(f"Created {len(chunk_names)} chunks")
///     ```
fn encrypt_from_file(input_path: String, output_dir: String) -> PyResult<(PyDataMap, Vec<String>)> {
    let (data_map, chunk_names) =
        rust_encrypt_from_file(&PathBuf::from(input_path), &PathBuf::from(output_dir))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((
        PyDataMap { inner: data_map },
        chunk_names
            .into_iter()
            .map(|name| hex::encode(name.0))
            .collect(),
    ))
}

#[pyfunction]
/// Decrypt data using provided chunks in memory.
///
/// This function takes a data map and its corresponding encrypted chunks and
/// reassembles the original data. All operations are performed in memory.
///
/// Args:
///     data_map (DataMap): The data map containing chunk metadata
///     chunks (List[EncryptedChunk]): The encrypted chunks to decrypt
///
/// Returns:
///     bytes: The decrypted original data
///
/// Raises:
///     ValueError: If decryption fails or chunks are invalid
///     
/// Example:
///     ```python
///     decrypted = decrypt(data_map, chunks)
///     with open("output.dat", "wb") as f:
///         f.write(decrypted)
///     ```
fn decrypt(data_map: &PyDataMap, chunks: Vec<PyEncryptedChunk>) -> PyResult<Py<PyBytes>> {
    let chunks: Vec<RustEncryptedChunk> = chunks.into_iter().map(|c| c.inner).collect();
    let result = rust_decrypt(&data_map.inner, &chunks)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Python::with_gil(|py| Ok(PyBytes::new(py, &result).into()))
}

#[pyfunction]
/// Decrypt data using chunks from storage, writing directly to a file.
///
/// This function decrypts data by retrieving chunks from a storage backend using
/// the provided callback function. It writes the decrypted data directly to the
/// specified output file, making it suitable for large files that shouldn't be
/// held entirely in memory.
///
/// Args:
///     data_map (DataMap): The data map containing chunk metadata
///     output_path (str): Path where the decrypted file will be written
///     get_chunk (Callable[[str], bytes]): Function that retrieves chunks by their hex name
///
/// Raises:
///     ValueError: If decryption fails or chunks are invalid
///     OSError: If there are file system errors
///     
/// Example:
///     ```python
///     def get_chunk(hex_name):
///         chunk_path = Path("chunks") / hex_name
///         return chunk_path.read_bytes()
///     
///     decrypt_from_storage(data_map, "output.dat", get_chunk)
///     ```
fn decrypt_from_storage(
    py: Python<'_>,
    data_map: &PyDataMap,
    output_path: String,
    py_get_chunk: PyObject,
) -> PyResult<()> {
    let mut get_chunk = |hash: XorName| -> Result<Bytes> {
        let hash_hex = hex::encode(hash.0);
        let result = py_get_chunk
            .call1(py, (hash_hex,))
            .map_err(|e| Error::Generic(format!("Python callback error: {}", e)))?;
        let chunk_data: Vec<u8> = result
            .extract(py)
            .map_err(|e| Error::Generic(format!("Python data extraction error: {}", e)))?;
        Ok(Bytes::from(chunk_data))
    };

    rust_decrypt_from_storage(&data_map.inner, &PathBuf::from(output_path), &mut get_chunk)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
/// Decrypt data with parallel chunk retrieval for improved performance.
///
/// This function is optimized for performance when working with large files and
/// remote storage backends. It retrieves multiple chunks in parallel and writes
/// the decrypted data directly to a file.
///
/// Key features:
///   - Parallel chunk retrieval for better throughput
///   - Streaming write to output file
///   - Memory efficient for large files
///   - Optimized for remote storage backends
///
/// Args:
///     data_map (DataMap): The data map containing chunk metadata
///     output_path (str): Path where the decrypted file will be written
///     get_chunks (Callable[[List[str]], List[bytes]]): Function that retrieves multiple
///         chunks in parallel, given their hex names. Should accept a list of hex names
///         and return a list of chunk contents in the same order.
///
/// Raises:
///     ValueError: If decryption fails or chunks are invalid
///     OSError: If there are file system errors
///     
/// Example:
///     ```python
///     from concurrent.futures import ThreadPoolExecutor
///     from pathlib import Path
///     
///     def get_chunks(hex_names):
///         # Parallel chunk retrieval using thread pool
///         def get_one(name):
///             chunk_path = Path("chunks") / name
///             return chunk_path.read_bytes()
///             
///         with ThreadPoolExecutor(max_workers=4) as executor:
///             return list(executor.map(get_one, hex_names))
///     
///     streaming_decrypt_from_storage(data_map, "output.dat", get_chunks)
///     ```
fn streaming_decrypt_from_storage(
    py: Python<'_>,
    data_map: &PyDataMap,
    output_path: String,
    py_get_chunks: PyObject,
) -> PyResult<()> {
    let get_chunk_parallel = |hashes: &[XorName]| -> Result<Vec<Bytes>> {
        let hash_hexes: Vec<String> = hashes.iter().map(|h| hex::encode(h.0)).collect();
        let chunks = py_get_chunks
            .call1(py, (hash_hexes,))
            .map_err(|e| Error::Generic(format!("Python callback error: {}", e)))?;
        let chunk_data: Vec<Vec<u8>> = chunks
            .extract(py)
            .map_err(|e| Error::Generic(format!("Python data extraction error: {}", e)))?;
        Ok(chunk_data.into_iter().map(Bytes::from).collect())
    };

    rust_streaming_decrypt_from_storage(
        &data_map.inner,
        &PathBuf::from(output_path),
        get_chunk_parallel,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
/// Stream-encrypt a file and store chunks using a custom storage backend.
///
/// This function reads and encrypts a file in chunks, using less memory than the standard
/// encrypt_from_file function. It's ideal for large files and custom storage backends.
///
/// Key features:
///   - Memory efficient streaming encryption
///   - Custom storage backend support
///   - Parallel processing where possible
///   - Maintains encryption security properties
///
/// Args:
///     input_path (str): Path to the input file to encrypt
///     store_chunk (Callable[[str, bytes], None]): Function to store encrypted chunks.
///         Takes two arguments:
///         - chunk_name (str): The hex name (XorName) of the chunk
///         - content (bytes): The encrypted chunk content
///
/// Returns:
///     DataMap: Contains metadata about the encrypted chunks
///
/// Raises:
///     ValueError: If the input file is too small or encryption fails
///     OSError: If there are file system errors
///     
/// Example:
///     ```python
///     def store_chunk(name, content):
///         chunk_path = Path("chunks") / name
///         chunk_path.write_bytes(content)
///     
///     data_map = streaming_encrypt_from_file("large_file.dat", store_chunk)
///     print(f"Created {data_map.len()} chunks")
///     ```
fn streaming_encrypt_from_file(
    _py: Python<'_>,
    input_path: String,
    py_store_chunk: PyObject,
) -> PyResult<PyDataMap> {
    let input_path = PathBuf::from(input_path);

    // Create a closure that calls the Python store_chunk function
    let mut store_chunk = |name: XorName, content: Bytes| -> Result<()> {
        // Convert data outside of the Python context
        let bytes: &[u8] = name.as_ref();
        let name_hex = hex::encode(bytes);
        let content_bytes = content.to_vec();

        // Acquire the GIL and call the Python function
        let result: Result<()> = Python::with_gil(|py| {
            let args = (name_hex, PyBytes::new(py, &content_bytes));
            py_store_chunk
                .call1(py, args)
                .map(|_| ())
                .map_err(|e| Error::Python(format!("Store chunk failed: {}", e)))?;
            Ok(())
        });
        result
    };

    // Call the Rust streaming encryption function
    match rust_streaming_encrypt_from_file(&input_path, &mut store_chunk) {
        Ok(data_map) => Ok(PyDataMap { inner: data_map }),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Streaming encryption failed: {}",
            e
        ))),
    }
}

#[pyfunction]
/// Verify the integrity of an encrypted chunk.
///
/// This function checks if an encrypted chunk's content matches its XorName,
/// ensuring the chunk hasn't been corrupted or tampered with.
///
/// Args:
///     name (XorName): The expected XorName of the chunk
///     content (bytes): The chunk's content to verify
///
/// Returns:
///     EncryptedChunk: A verified encrypted chunk object
///
/// Raises:
///     ValueError: If the chunk's content doesn't match its name
///     
/// Example:
///     ```python
///     chunk = verify_chunk(name, content)
///     assert chunk.content() == content
///     ```
fn verify_chunk(name: &PyXorName, content: &PyBytes) -> PyResult<PyEncryptedChunk> {
    match crate::verify_chunk(name.inner, content.as_bytes()) {
        Ok(chunk) => Ok(PyEncryptedChunk { inner: chunk }),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            e.to_string(),
        )),
    }
}

#[pyfunction]
/// Shrink a data map by recursively encrypting it.
///
/// This is useful for handling large files that produce large data maps.
///
/// Args:
///     data_map (DataMap): The data map to shrink
///     store_chunk (Callable[[str, bytes], None]): Function to store new chunks
///
/// Returns:
///     Tuple[DataMap, List[EncryptedChunk]]: The shrunk data map and new chunks
///
/// Raises:
///     ValueError: If shrinking fails
fn shrink_data_map(
    py: Python<'_>,
    data_map: &PyDataMap,
    py_store_chunk: PyObject,
) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let mut store_chunk = |hash: XorName, content: Bytes| -> Result<()> {
        let hash_hex = hex::encode(hash.0);
        let content_vec = content.to_vec();
        let _ = py_store_chunk
            .call1(py, (hash_hex, content_vec))
            .map_err(|e| Error::Generic(format!("Python callback error: {}", e)))?;
        Ok(())
    };

    let (shrunk_map, chunks) = rust_shrink_data_map(data_map.inner.clone(), &mut store_chunk)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((
        PyDataMap { inner: shrunk_map },
        chunks
            .into_iter()
            .map(|c| PyEncryptedChunk { inner: c })
            .collect(),
    ))
}

#[pymodule]
fn _self_encryption(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyDataMap>()?;
    m.add_class::<PyEncryptedChunk>()?;
    m.add_class::<PyXorName>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_from_storage, m)?)?;
    m.add_function(wrap_pyfunction!(shrink_data_map, m)?)?;
    m.add_function(wrap_pyfunction!(streaming_decrypt_from_storage, m)?)?;
    m.add_function(wrap_pyfunction!(streaming_encrypt_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(verify_chunk, m)?)?;
    Ok(())
}
