use pyo3::prelude::*;
use crate::{encrypt, decrypt_full_set, DataMap, EncryptedChunk};
use bytes::Bytes;

#[pyclass]
struct PyDataMap {
    inner: DataMap
}

#[pymethods]
impl PyDataMap {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        let bytes = Bytes::from(data.to_vec());
        let (data_map, _) = encrypt(bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Encryption failed: {}", e))
        })?;
        Ok(PyDataMap { inner: data_map })
    }

    fn encrypt(mut slf: PyRefMut<'_, Self>, _py: Python<'_>, data: &[u8]) -> PyResult<Vec<Vec<u8>>> {
        let bytes = Bytes::from(data.to_vec());
        let (data_map, chunks) = encrypt(bytes).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Encryption failed: {}", e))
        })?;
        
        slf.inner = data_map;
        
        Ok(chunks.into_iter().map(|c| c.content.to_vec()).collect())
    }

    fn decrypt(slf: PyRef<'_, Self>, _py: Python<'_>, chunks: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
        let encrypted_chunks: Vec<EncryptedChunk> = chunks
            .into_iter()
            .map(|c| EncryptedChunk { content: Bytes::from(c) })
            .collect();

        let decrypted = decrypt_full_set(&slf.inner, &encrypted_chunks).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Decryption failed: {}", e))
        })?;

        Ok(decrypted.to_vec())
    }
}

#[pymodule]
#[pyo3(name = "self_encryption")]
fn self_encryption(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyDataMap>()?;
    Ok(())
} 