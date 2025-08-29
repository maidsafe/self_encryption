use crate::{
    decrypt_from_storage as rust_decrypt_from_storage, encrypt_from_file as rust_encrypt_from_file,
    streaming_decrypt_from_storage as rust_streaming_decrypt_from_storage, ChunkInfo, DataMap,
    EncryptedChunk, XorName,
};
use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyInt, PyTuple};
use std::borrow::Cow;
use std::path::Path;

/// A Python wrapper for the XorName struct.
///
/// XorName is a 32-byte array used for content addressing and chunk identification.
/// It is used to uniquely identify chunks based on their content.
///
/// Example:
///     # Create a XorName from bytes
///     name = PyXorName.from_content(b"some data")
///
///     # Get the underlying bytes
///     bytes = name.as_bytes()
#[pyclass]
#[derive(Clone)]
pub struct PyXorName {
    inner: XorName,
}

#[pymethods]
impl PyXorName {
    /// Create a new XorName from content bytes.
    ///
    /// Args:
    ///     content (bytes): The content to hash into a XorName.
    ///
    /// Returns:
    ///     PyXorName: A new XorName instance.
    #[staticmethod]
    pub fn from_content(content: &[u8]) -> Self {
        Self {
            inner: XorName::from_content(content),
        }
    }

    /// Get the underlying bytes of the XorName.
    ///
    /// Returns:
    ///     bytes: The 32-byte array.
    pub fn as_bytes(&self) -> Cow<'_, [u8]> {
        self.inner.0.to_vec().into()
    }
}

/// A Python wrapper for the ChunkInfo struct.
///
/// ChunkInfo contains metadata about a single chunk in a DataMap,
/// including its index, size, and hashes.
///
/// Example:
///     # Create a ChunkInfo
///     info = PyChunkInfo(index=0, dst_hash=dst, src_hash=src, src_size=1024)
#[pyclass]
#[derive(Clone)]
pub struct PyChunkInfo {
    inner: ChunkInfo,
}

#[pymethods]
impl PyChunkInfo {
    #[new]
    pub fn new(index: usize, dst_hash: PyXorName, src_hash: PyXorName, src_size: usize) -> Self {
        Self {
            inner: ChunkInfo {
                index,
                dst_hash: dst_hash.inner,
                src_hash: src_hash.inner,
                src_size,
            },
        }
    }

    #[getter]
    pub fn index(&self) -> usize {
        self.inner.index
    }

    #[getter]
    pub fn dst_hash(&self) -> PyXorName {
        PyXorName {
            inner: self.inner.dst_hash,
        }
    }

    #[getter]
    pub fn src_hash(&self) -> PyXorName {
        PyXorName {
            inner: self.inner.src_hash,
        }
    }

    #[getter]
    pub fn src_size(&self) -> usize {
        self.inner.src_size
    }
}

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
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))?;
        Ok(Self { inner })
    }

    /// Convert the DataMap to a JSON string.
    ///
    /// Returns:
    ///     str: A JSON string representation of the DataMap.
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize: {e}"))
        })
    }

    /// Create a new DataMap from a list of chunk infos.
    ///
    /// Args:
    ///     chunk_infos (list[PyChunkInfo]): List of chunk metadata.
    ///
    /// Returns:
    ///     PyDataMap: A new DataMap instance.
    #[new]
    pub fn new(chunk_infos: Vec<PyChunkInfo>) -> Self {
        let inner_infos = chunk_infos.into_iter().map(|info| info.inner).collect();
        Self {
            inner: DataMap::new(inner_infos),
        }
    }

    /// Create a new DataMap with a child level.
    ///
    /// Args:
    ///     chunk_infos (list[PyChunkInfo]): List of chunk metadata.
    ///     child (int): The child level value.
    ///
    /// Returns:
    ///     PyDataMap: A new DataMap instance with the specified child level.
    #[staticmethod]
    pub fn with_child(chunk_infos: Vec<PyChunkInfo>, child: usize) -> Self {
        let inner_infos = chunk_infos.into_iter().map(|info| info.inner).collect();
        Self {
            inner: DataMap::with_child(inner_infos, child),
        }
    }

    /// Get the child level of the DataMap.
    ///
    /// Returns:
    ///     Optional[int]: The child level if present, None otherwise.
    pub fn child(&self) -> Option<usize> {
        self.inner.child()
    }

    /// Get the list of chunk infos.
    ///
    /// Returns:
    ///     list[PyChunkInfo]: The list of chunk metadata.
    pub fn infos(&self) -> Vec<PyChunkInfo> {
        self.inner
            .infos()
            .iter()
            .map(|info| PyChunkInfo {
                inner: info.clone(),
            })
            .collect()
    }

    /// Get the number of chunks in the DataMap.
    ///
    /// Returns:
    ///     int: The number of chunks.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if this is a child DataMap.
    ///
    /// Returns:
    ///     bool: True if this is a child DataMap, False otherwise.
    pub fn is_child(&self) -> bool {
        self.inner.is_child()
    }
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
impl PyEncryptedChunk {
    /// Get the size of the original content before encryption.
    ///
    /// Returns:
    ///     int: The size in bytes of the original content.
    pub fn content_size(&self) -> usize {
        self.inner.content.len()
    }

    /// Get the hash of the encrypted chunk.
    ///
    /// Returns:
    ///     bytes: The SHA256 hash of the encrypted chunk.
    pub fn hash(&self) -> Cow<'_, [u8]> {
        XorName::from_content(&self.inner.content).0.to_vec().into()
    }
}

/// Encrypt raw data into chunks.
///
/// This function takes raw data, splits it into chunks, encrypts them,
/// and returns a DataMap and list of encrypted chunks.
///
/// Args:
///     data (bytes): The data to encrypt.
///
/// Returns:
///     tuple: A tuple containing:
///         - PyDataMap: The data map required for decryption
///         - list[PyEncryptedChunk]: The list of encrypted chunks
///
/// Raises:
///     ValueError: If the data is too small (less than MIN_ENCRYPTABLE_BYTES).
#[pyfunction]
pub fn encrypt(data: &[u8]) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let bytes = Bytes::copy_from_slice(data);
    let (data_map, chunks) = crate::encrypt(bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encryption failed: {e}")))?;
    let py_chunks = chunks
        .into_iter()
        .map(|chunk| PyEncryptedChunk { inner: chunk })
        .collect();
    Ok((PyDataMap { inner: data_map }, py_chunks))
}

/// Decrypt data using a DataMap and chunks.
///
/// This function takes a DataMap and list of encrypted chunks,
/// decrypts them, and returns the original data.
///
/// Args:
///     data_map (PyDataMap): The data map containing chunk metadata.
///     chunks (list[PyEncryptedChunk]): The list of encrypted chunks.
///
/// Returns:
///     bytes: The decrypted data.
///
/// Raises:
///     ValueError: If decryption fails or chunks are missing/corrupted.
#[pyfunction]
pub fn decrypt(
    data_map: &PyDataMap,
    chunks: Vec<PyEncryptedChunk>,
) -> PyResult<std::borrow::Cow<'_, [u8]>> {
    let inner_chunks = chunks
        .into_iter()
        .map(|chunk| chunk.inner)
        .collect::<Vec<_>>();
    let bytes = crate::decrypt(&data_map.inner, &inner_chunks)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {e}")))?;
    Ok(bytes.to_vec().into())
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
    let input_path = Path::new(input_file);
    let output_path = Path::new(output_dir);
    let (data_map, chunk_names) = rust_encrypt_from_file(input_path, output_path).map_err(|e| {
        pyo3::exceptions::PyOSError::new_err(format!("Failed to encrypt file: {e}"))
    })?;
    let chunk_names = chunk_names.iter().map(|name| hex::encode(name.0)).collect();
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
    get_chunk: Bound<'_, PyAny>,
) -> PyResult<()> {
    let output_path = Path::new(output_file);
    let get_chunk_wrapper = |name: XorName| -> crate::Result<Bytes> {
        let name_str = hex::encode(name.0);
        let chunk = get_chunk
            .call1((name_str,))
            .map_err(|e| crate::Error::Python(format!("Failed to call get_chunk: {e}")))?;
        let bytes = chunk
            .downcast::<PyBytes>()
            .map_err(|e| crate::Error::Python(format!("get_chunk must return bytes: {e}")))?;
        Ok(Bytes::copy_from_slice(bytes.as_bytes()))
    };

    rust_decrypt_from_storage(&data_map.inner, output_path, get_chunk_wrapper)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("Decryption failed: {e}")))
}

/// Decrypt data using streaming for better performance with large files.
///
/// This function uses parallel processing and streaming to efficiently
/// decrypt large files while minimizing memory usage.
///
/// Args:
///     data_map (PyDataMap): The data map containing chunk metadata.
///     output_file (str): Path where the decrypted data will be written.
///     get_chunks (callable): Function that takes a list of (index, chunk_name) tuples
///                           and returns a list of (index, bytes) tuples.
///                           Example: get_chunks([(0, "abc123"), (1, "def456")])
///                           should return [(0, b"chunk0_data"), (1, b"chunk1_data")]
///
/// Raises:
///     OSError: If chunks cannot be retrieved or output cannot be written.
///     ValueError: If the data map is invalid or chunks are corrupted.
#[pyfunction]
pub fn streaming_decrypt_from_storage(
    data_map: PyDataMap,
    output_file: &str,
    get_chunks: Bound<'_, PyAny>,
) -> PyResult<()> {
    let output_path = Path::new(output_file);
    let get_chunks_wrapper = |names: &[(usize, XorName)]| -> crate::Result<Vec<(usize, Bytes)>> {
        let name_strs: Vec<(usize, String)> =
            names.iter().map(|(i, x)| (*i, hex::encode(x.0))).collect();
        let chunks = get_chunks
            .call1((name_strs,))
            .map_err(|e| crate::Error::Python(format!("Failed to call get_chunks: {e}")))?;
        let chunks = chunks
            .try_iter()
            .map_err(|e| crate::Error::Python(format!("get_chunks must return a list: {e}")))?;
        let mut result = Vec::new();
        for chunk in chunks {
            let chunk = chunk
                .map_err(|e| crate::Error::Python(format!("Failed to iterate chunks: {e}")))?;

            // Downcast to individual components instead of tuple
            let chunk_tuple = chunk
                .downcast::<PyTuple>()
                .map_err(|e| crate::Error::Python(format!("get_chunks must return tuple: {e}")))?;

            if chunk_tuple.len() != 2 {
                return Err(crate::Error::Python(
                    "get_chunks must return tuples of length 2".to_string(),
                ));
            }

            let index_item = chunk_tuple.get_item(0)?;
            let index = index_item
                .downcast::<PyInt>()
                .map_err(|e| crate::Error::Python(format!("First element must be integer: {e}")))?
                .extract::<usize>()
                .map_err(|e| crate::Error::Python(format!("Failed to extract index: {e}")))?;

            let bytes_item = chunk_tuple.get_item(1)?;
            let bytes = bytes_item
                .downcast::<PyBytes>()
                .map_err(|e| crate::Error::Python(format!("Second element must be bytes: {e}")))?;

            result.push((index, Bytes::copy_from_slice(bytes.as_bytes())));
        }
        Ok(result)
    };

    rust_streaming_decrypt_from_storage(&data_map.inner, output_path, get_chunks_wrapper).map_err(
        |e| pyo3::exceptions::PyOSError::new_err(format!("Streaming decryption failed: {e}")),
    )
}

/// Initialize the Python module.
#[pymodule]
#[pyo3(name = "_self_encryption")]
fn self_encryption_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDataMap>()?;
    m.add_class::<PyEncryptedChunk>()?;
    m.add_class::<PyXorName>()?;
    m.add_class::<PyChunkInfo>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_from_storage, m)?)?;
    m.add_function(wrap_pyfunction!(streaming_decrypt_from_storage, m)?)?;
    Ok(())
}
