use crate::{
    decrypt, decrypt_from_storage, encrypt, encrypt_from_file, shrink_data_map,
    ChunkInfo, DataMap, EncryptedChunk, Error, Result,
};
use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;
use xor_name::XorName;
use pyo3::types::PyType;

#[pyclass]
#[derive(Clone)]
struct PyDataMap {
    inner: DataMap,
}

#[pyclass]
#[derive(Clone)]
struct PyEncryptedChunk {
    inner: EncryptedChunk,
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
            inner: DataMap::new(infos),
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
            inner: DataMap::with_child(infos, child),
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
            inner: EncryptedChunk {
                content: Bytes::from(content),
            },
        }
    }

    fn content(&self) -> Vec<u8> {
        self.inner.content.to_vec()
    }

    // Add a classmethod to create from Python bytes
    #[classmethod]
    fn from_bytes(_cls: &PyType, content: &PyBytes) -> PyResult<Self> {
        Ok(Self::new(content.as_bytes().to_vec()))
    }
}

#[pyfunction]
fn py_encrypt(data: &PyBytes) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let bytes = Bytes::from(data.as_bytes().to_vec());
    let (data_map, chunks) = encrypt(bytes).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    
    Ok((
        PyDataMap { inner: data_map },
        chunks.into_iter().map(|c| PyEncryptedChunk { inner: c }).collect(),
    ))
}

#[pyfunction]
fn py_encrypt_from_file(input_path: String, output_dir: String) -> PyResult<(PyDataMap, Vec<Vec<u8>>)> {
    let (data_map, chunk_names) = encrypt_from_file(
        &PathBuf::from(input_path),
        &PathBuf::from(output_dir),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((
        PyDataMap { inner: data_map },
        chunk_names.into_iter().map(|name| name.0.to_vec()).collect(),
    ))
}

#[pyfunction]
fn py_decrypt(data_map: &PyDataMap, chunks: Vec<PyEncryptedChunk>) -> PyResult<Vec<u8>> {
    let chunks: Vec<EncryptedChunk> = chunks.into_iter().map(|c| c.inner).collect();
    let result = decrypt(&data_map.inner, &chunks)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(result.to_vec())
}

#[pyfunction]
fn py_decrypt_from_storage(
    data_map: &PyDataMap,
    output_path: String,
    py_get_chunk: PyObject,
    py: Python<'_>,
) -> PyResult<()> {
    let mut get_chunk = |hash: XorName| -> Result<Bytes> {
        let hash_vec = hash.0.to_vec();
        let result = py_get_chunk
            .call1(py, (hash_vec,))
            .map_err(|e| Error::Generic(format!("Python callback error: {}", e)))?;
        let chunk_data: Vec<u8> = result
            .extract(py)
            .map_err(|e| Error::Generic(format!("Python data extraction error: {}", e)))?;
        Ok(Bytes::from(chunk_data))
    };

    decrypt_from_storage(&data_map.inner, &PathBuf::from(output_path), &mut get_chunk)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
fn py_shrink_data_map(
    data_map: &PyDataMap,
    py_store_chunk: PyObject,
    py: Python<'_>,
) -> PyResult<(PyDataMap, Vec<PyEncryptedChunk>)> {
    let mut store_chunk = |hash: XorName, content: Bytes| -> Result<()> {
        let hash_vec = hash.0.to_vec();
        let content_vec = content.to_vec();
        let _ = py_store_chunk
            .call1(py, (hash_vec, content_vec))
            .map_err(|e| Error::Generic(format!("Python callback error: {}", e)))?;
        Ok(())
    };

    let (shrunk_map, chunks) = shrink_data_map(data_map.inner.clone(), &mut store_chunk)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((
        PyDataMap { inner: shrunk_map },
        chunks.into_iter().map(|c| PyEncryptedChunk { inner: c }).collect(),
    ))
}

#[pymodule]
fn self_encryption(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyDataMap>()?;
    m.add_class::<PyEncryptedChunk>()?;
    m.add_function(wrap_pyfunction!(py_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_from_storage, m)?)?;
    m.add_function(wrap_pyfunction!(py_shrink_data_map, m)?)?;
    Ok(())
}
