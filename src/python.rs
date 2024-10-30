use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;
use bytes::Bytes;

use crate::{
    DataMap, EncryptedChunk, StreamSelfEncryptor, StreamSelfDecryptor,
    encrypt, decrypt_full_set, encrypt_from_file, decrypt_from_chunk_files,
};

#[pyclass(name = "EncryptedChunk")]
#[derive(Clone)]
struct PyEncryptedChunk {
    #[pyo3(get)]
    content: Vec<u8>,
}

#[pymethods]
impl PyEncryptedChunk {
    #[new]
    fn new(content: Vec<u8>) -> Self {
        PyEncryptedChunk { content }
    }
}

#[pyclass(name = "DataMap")]
struct PyDataMap {
    inner: DataMap,
}

#[pymethods]
impl PyDataMap {
    #[new]
    fn new() -> Self {
        PyDataMap {
            inner: DataMap::new(Vec::new())
        }
    }

    fn serialize(&self) -> PyResult<Vec<u8>> {
        bincode::serialize(&self.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    #[staticmethod]
    fn deserialize(data: &[u8]) -> PyResult<Self> {
        let inner = bincode::deserialize(data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(PyDataMap { inner })
    }
}

#[pyclass(name = "StreamSelfEncryptor")]
struct PyStreamSelfEncryptor {
    inner: StreamSelfEncryptor,
}

#[pymethods]
impl PyStreamSelfEncryptor {
    #[new]
    fn new(file_path: String, chunk_dir: Option<String>) -> PyResult<Self> {
        let chunk_dir = chunk_dir.map(PathBuf::from);
        let inner = StreamSelfEncryptor::encrypt_from_file(
            PathBuf::from(file_path), 
            chunk_dir
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok(PyStreamSelfEncryptor { inner })
    }

    fn next_encryption(&mut self) -> PyResult<(Option<PyEncryptedChunk>, Option<PyDataMap>)> {
        let (chunk, data_map) = self.inner.next_encryption()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let chunk = chunk.map(|c| PyEncryptedChunk { content: c.content.to_vec() });
        let data_map = data_map.map(|dm| PyDataMap { inner: dm });
        
        Ok((chunk, data_map))
    }
}

#[pyclass(name = "StreamSelfDecryptor")]
struct PyStreamSelfDecryptor {
    inner: StreamSelfDecryptor,
}

#[pymethods]
impl PyStreamSelfDecryptor {
    #[new]
    fn new(output_path: String, data_map: &PyDataMap) -> PyResult<Self> {
        let inner = StreamSelfDecryptor::decrypt_to_file(
            PathBuf::from(output_path),
            &data_map.inner
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok(PyStreamSelfDecryptor { inner })
    }

    fn next_encrypted(&mut self, chunk: &PyEncryptedChunk) -> PyResult<bool> {
        let encrypted_chunk = EncryptedChunk {
            content: Bytes::from(chunk.content.clone()),
        };
        
        self.inner.next_encrypted(encrypted_chunk)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

#[pyfunction]
fn encrypt_bytes(data: &[u8]) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let (data_map, chunks) = encrypt(Bytes::from(data.to_vec()))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let py_chunks = chunks.into_iter()
        .map(|c| PyEncryptedChunk { content: c.content.to_vec() })
        .collect();

    Ok((PyDataMap { inner: data_map }, py_chunks))
}

#[pyfunction]
fn decrypt_chunks<'py>(py: Python<'py>, data_map: &PyDataMap, chunks: Vec<PyEncryptedChunk>) -> PyResult<&'py PyBytes> {
    let chunks: Vec<EncryptedChunk> = chunks.into_iter()
        .map(|c| EncryptedChunk { content: Bytes::from(c.content) })
        .collect();

    let result = decrypt_full_set(&data_map.inner, &chunks)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok(PyBytes::new(py, &result))
}

#[pyfunction]
fn encrypt_file(file_path: String, output_dir: String) -> PyResult<(PyDataMap, Vec<String>)> {
    let (data_map, chunk_names) = encrypt_from_file(
        &PathBuf::from(file_path),
        &PathBuf::from(output_dir)
    ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let chunk_filenames: Vec<String> = chunk_names.into_iter()
        .map(|name| hex::encode(name))
        .collect();

    Ok((PyDataMap { inner: data_map }, chunk_filenames))
}

#[pyfunction]
fn decrypt_from_files(
    chunk_dir: String,
    data_map: &PyDataMap,
    output_path: String
) -> PyResult<()> {
    decrypt_from_chunk_files(
        &PathBuf::from(chunk_dir),
        &data_map.inner,
        &PathBuf::from(output_path)
    ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pymodule]
fn self_encryption(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyEncryptedChunk>()?;
    m.add_class::<PyDataMap>()?;
    m.add_class::<PyStreamSelfEncryptor>()?;
    m.add_class::<PyStreamSelfDecryptor>()?;
    m.add_function(wrap_pyfunction!(encrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_chunks, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_file, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_from_files, m)?)?;
    Ok(())
} 