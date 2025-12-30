use pyo3::prelude::*;

mod error;
mod io_adapter;
mod types;
mod verify;

use error::register_exceptions;
use types::*;
use verify::*;

/// Python module for RATLS attestation verification.
///
/// This module provides bindings to verify TDX attestation over Python ssl.SSLSocket
/// connections. The verification is performed by Rust while Python retains ownership
/// of the socket.
///
/// Example:
///     import ssl
///     import socket
///     import ratls
///
///     # Establish TLS connection
///     context = ssl.create_default_context()
///     sock = socket.create_connection(("example.com", 443))
///     ssl_sock = context.wrap_socket(sock, server_hostname="example.com")
///
///     # Verify attestation
///     result = ratls.verify_attestation_over_socket(
///         ssl_sock,
///         policy=ratls.Policy.default(),
///     )
///
///     if result.trusted:
///         print(f"Verified! Measurement: {result.measurement}")
///
///     # Socket is still valid - use it for HTTP!
///     ssl_sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
#[pymodule]
fn _ratls(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register types
    m.add_class::<PyTeeType>()?;
    m.add_class::<PyPolicy>()?;
    m.add_class::<PyTdxTcbPolicy>()?;
    m.add_class::<PyAttestationResult>()?;

    // Register exceptions
    register_exceptions(m)?;

    // Register functions
    m.add_function(wrap_pyfunction!(verify_attestation_over_socket, m)?)?;
    m.add_function(wrap_pyfunction!(verify_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(verify_quote_freshness, m)?)?;
    m.add_function(wrap_pyfunction!(verify_event_log_integrity, m)?)?;
    m.add_function(wrap_pyfunction!(verify_tls_certificate_in_log, m)?)?;

    Ok(())
}
