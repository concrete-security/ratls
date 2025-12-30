"""RATLS - Remote Attestation TLS verification for Python.

This module provides Python bindings to verify TDX attestation over Python
ssl.SSLSocket connections. The verification is performed by Rust while Python
retains ownership of the socket.

Example:
    import ssl
    import socket
    import ratls

    # Establish TLS connection
    context = ssl.create_default_context()
    sock = socket.create_connection(("example.com", 443))
    ssl_sock = context.wrap_socket(sock, server_hostname="example.com")

    # Verify attestation
    result = ratls.verify_attestation_over_socket(
        ssl_sock,
        policy=ratls.Policy.default(),
    )

    if result.trusted:
        print(f"Verified! Measurement: {result.measurement}")

    # Socket is still valid - use it for HTTP!
    ssl_sock.sendall(b"GET / HTTP/1.1\\r\\n\\r\\n")
"""

from ._ratls import (
    # Types
    TeeType,
    Policy,
    TdxTcbPolicy,
    AttestationResult,
    # Exceptions
    RatlsException,
    PolicyViolationError,
    VendorVerificationError,
    IoError,
    X509Error,
    TeeUnsupportedError,
    # Functions
    verify_attestation_over_socket,
    verify_attestation,
    verify_quote_freshness,
    verify_event_log_integrity,
    verify_tls_certificate_in_log,
)

__all__ = [
    # Types
    "TeeType",
    "Policy",
    "TdxTcbPolicy",
    "AttestationResult",
    # Exceptions
    "RatlsException",
    "PolicyViolationError",
    "VendorVerificationError",
    "IoError",
    "X509Error",
    "TeeUnsupportedError",
    # Functions
    "verify_attestation_over_socket",
    "verify_attestation",
    "verify_quote_freshness",
    "verify_event_log_integrity",
    "verify_tls_certificate_in_log",
]

__version__ = "0.1.0"
