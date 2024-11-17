use crate::{
    decrypt as rust_decrypt,
    decrypt_from_storage as rust_decrypt_from_storage,
    encrypt as rust_encrypt,
    encrypt_from_file as rust_encrypt_from_file,
    shrink_data_map as rust_shrink_data_map,
    streaming_decrypt_from_storage as rust_streaming_decrypt_from_storage,
    ChunkInfo, DataMap as RustDataMap, EncryptedChunk as RustEncryptedChunk, Error, Result,
};
use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use std::path::PathBuf;
use xor_name::XorName;

#[pyclass(name = "DataMap")]
#[derive(Clone)]
struct PyDataMap {
    inner: RustDataMap,
}

#[pyclass(name = "EncryptedChunk")]
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

    fn child(&self) -> Option<usize> {
        self.inner.child()
    }

    fn is_child(&self) -> bool {
        self.inner.is_child()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

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
    fn new(content: Vec<u8>) -> Self {
        Self {
            inner: RustEncryptedChunk {
                content: Bytes::from(content),
            },
        }
    }

    fn content(&self) -> &[u8] {
        &self.inner.content
    }

    #[classmethod]
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
fn encrypt(_py: Python<'_>, data: &PyBytes) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let bytes = Bytes::from(data.as_bytes().to_vec());
    let (data_map, chunks) = rust_encrypt(bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    
    Ok((
        PyDataMap { inner: data_map },
        chunks.into_iter().map(|c| PyEncryptedChunk { inner: c }).collect(),
    ))
}

#[pyfunction]
fn encrypt_from_file(input_path: String, output_dir: String) -> PyResult<(PyDataMap, Vec<String>)> {
    let (data_map, chunk_names) = rust_encrypt_from_file(
        &PathBuf::from(input_path),
        &PathBuf::from(output_dir),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((
        PyDataMap { inner: data_map },
        chunk_names.into_iter().map(|name| hex::encode(name.0)).collect(),
    ))
}

#[pyfunction]
fn decrypt(data_map: &PyDataMap, chunks: Vec<PyEncryptedChunk>) -> PyResult<Py<PyBytes>> {
    let chunks: Vec<RustEncryptedChunk> = chunks.into_iter().map(|c| c.inner).collect();
    let result = rust_decrypt(&data_map.inner, &chunks)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    
    Python::with_gil(|py| Ok(PyBytes::new(py, &result).into()))
}

#[pyfunction]
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
        chunks.into_iter().map(|c| PyEncryptedChunk { inner: c }).collect(),
    ))
}

#[pyfunction]
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

    rust_streaming_decrypt_from_storage(&data_map.inner, &PathBuf::from(output_path), get_chunk_parallel)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
fn verify_chunk(name: &PyXorName, content: &PyBytes) -> PyResult<PyEncryptedChunk> {
    match crate::verify_chunk(name.inner, content.as_bytes()) {
        Ok(chunk) => Ok(PyEncryptedChunk { inner: chunk }),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())),
    }
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
    m.add_function(wrap_pyfunction!(verify_chunk, m)?)?;
    Ok(())
}
