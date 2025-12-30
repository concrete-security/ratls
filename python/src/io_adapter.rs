use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::io;

/// Adapter for calling Python socket methods from Rust.
///
/// This provides synchronous I/O operations that call Python's ssl.SSLSocket.
pub struct PySocketAdapter {
    /// Python socket object's recv method bound to the socket
    read_fn: PyObject,
    /// Python socket object's sendall method bound to the socket
    write_fn: PyObject,
}

impl PySocketAdapter {
    /// Create a new adapter from a Python socket object.
    ///
    /// The socket should have `recv` and `sendall` methods (like ssl.SSLSocket).
    pub fn new(_py: Python<'_>, socket: &Bound<'_, PyAny>) -> PyResult<Self> {
        let read_fn = socket.getattr("recv")?.unbind();
        let write_fn = socket.getattr("sendall")?.unbind();

        Ok(Self { read_fn, write_fn })
    }

    /// Synchronously read from the Python socket.
    pub fn read(&self, size: usize) -> io::Result<Vec<u8>> {
        Python::with_gil(|py| {
            let result = self
                .read_fn
                .call1(py, (size,))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let bytes = result
                .downcast_bound::<PyBytes>(py)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            Ok(bytes.as_bytes().to_vec())
        })
    }

    /// Synchronously write to the Python socket.
    pub fn write_all(&self, data: &[u8]) -> io::Result<()> {
        Python::with_gil(|py| {
            let bytes = PyBytes::new(py, data);
            self.write_fn
                .call1(py, (bytes,))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            Ok(())
        })
    }

    /// Synchronously read exactly n bytes.
    pub fn read_exact(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let data = self.read(buf.len() - filled)?;
            if data.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
            let to_copy = std::cmp::min(data.len(), buf.len() - filled);
            buf[filled..filled + to_copy].copy_from_slice(&data[..to_copy]);
            filled += to_copy;
        }
        Ok(())
    }
}

// SAFETY: The PyObject handles are thread-safe because:
// 1. We always acquire the GIL before accessing them
// 2. Python objects are reference-counted and can be shared across threads
unsafe impl Send for PySocketAdapter {}
