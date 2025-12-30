use crate::error::{ratls_error_to_py, to_py_error};
use crate::io_adapter::PySocketAdapter;
use crate::types::{PyAttestationResult, PyPolicy};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ratls_core::tdx;
use ratls_core::Policy;
use serde::Deserialize;
use serde_json::Value;
use tokio::runtime::Runtime;

/// Response structure from the attestation endpoint.
#[derive(Deserialize)]
#[serde(untagged)]
enum AttestationResponse {
    Success {
        quote: DstackQuote,
        #[serde(default)]
        collateral: Option<dcap_qvl::QuoteCollateralV3>,
    },
    Error {
        error: String,
    },
}

#[derive(Deserialize)]
struct DstackQuote {
    quote: String,
    #[serde(default)]
    event_log: Value,
}

/// Verify attestation over an existing Python ssl.SSLSocket.
///
/// This function:
/// 1. Extracts the peer certificate from the socket
/// 2. Sends an attestation request with a fresh nonce
/// 3. Parses the response and verifies the attestation
///
/// The socket remains valid after this call and can be used for further I/O.
///
/// Args:
///     sock: An established ssl.SSLSocket connection
///     policy: Attestation policy (defaults to Policy.default())
///     endpoint: HTTP path for attestation endpoint (default: "/tdx_quote")
///     host: Host header value for HTTP request (default: "localhost")
///
/// Returns:
///     AttestationResult with verification details
///
/// Raises:
///     PolicyViolationError: If policy requirements are not met
///     VendorVerificationError: If quote verification fails
///     IoError: If I/O fails during attestation
#[pyfunction]
#[pyo3(signature = (sock, policy=None, endpoint="/tdx_quote", host="localhost"))]
pub fn verify_attestation_over_socket(
    py: Python<'_>,
    sock: &Bound<'_, PyAny>,
    policy: Option<PyPolicy>,
    endpoint: &str,
    host: &str,
) -> PyResult<PyAttestationResult> {
    // Extract the peer certificate from the Python socket
    let peer_cert = extract_peer_cert(sock)?;

    // Create the I/O adapter
    let adapter = PySocketAdapter::new(py, sock)?;

    // Get the policy
    let core_policy: Policy = policy.unwrap_or_else(PyPolicy::py_default).into();

    // Clone values for the closure
    let endpoint = endpoint.to_string();
    let host = host.to_string();

    // Run the verification (releases GIL during blocking operations)
    py.allow_threads(|| {
        verify_attestation_impl(adapter, &peer_cert, &core_policy, &endpoint, &host)
    })
}

/// Internal synchronous implementation of attestation verification.
fn verify_attestation_impl(
    adapter: PySocketAdapter,
    server_cert: &[u8],
    policy: &Policy,
    endpoint: &str,
    host: &str,
) -> PyResult<PyAttestationResult> {
    // Generate a random nonce
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| to_py_error(format!("Failed to generate nonce: {e}")))?;
    let nonce_hex = hex::encode(nonce);

    // Build the HTTP request
    let body_json = format!(r#"{{"report_data":"{}"}}"#, nonce_hex);
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        endpoint,
        host,
        body_json.len(),
        body_json
    );

    // Send the request
    adapter
        .write_all(request.as_bytes())
        .map_err(|e| to_py_error(format!("Failed to send request: {e}")))?;

    // Read HTTP headers byte by byte
    let mut header_buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        adapter
            .read_exact(&mut byte)
            .map_err(|e| to_py_error(format!("Failed to read headers: {e}")))?;
        header_buffer.push(byte[0]);
        if header_buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buffer.len() > 8192 {
            return Err(to_py_error("HTTP header too large"));
        }
    }

    // Parse headers
    let headers_str = String::from_utf8_lossy(&header_buffer);
    if !headers_str.starts_with("HTTP/1.1 200") {
        let status_line = headers_str.lines().next().unwrap_or_default();
        return Err(to_py_error(format!("Server returned error: {status_line}")));
    }

    // Extract Content-Length
    let len_prefix = "content-length: ";
    let content_len = headers_str
        .to_lowercase()
        .lines()
        .find(|line| line.starts_with(len_prefix))
        .ok_or_else(|| to_py_error("Missing Content-Length"))
        .and_then(|line| {
            line[len_prefix.len()..]
                .trim()
                .parse::<usize>()
                .map_err(|_| to_py_error("Invalid Content-Length"))
        })?;

    // Read body
    let mut body = vec![0u8; content_len];
    adapter
        .read_exact(&mut body)
        .map_err(|e| to_py_error(format!("Failed to read body: {e}")))?;

    // Parse response
    let response: AttestationResponse = serde_json::from_slice(&body)
        .map_err(|e| to_py_error(format!("Invalid server response: {e}")))?;

    let (dstack_quote, response_collateral) = match response {
        AttestationResponse::Success { quote, collateral } => (quote, collateral),
        AttestationResponse::Error { error } => {
            return Err(to_py_error(format!("Server error: {error}")))
        }
    };

    // Decode quote
    let quote_bytes = hex::decode(&dstack_quote.quote)
        .map_err(|e| to_py_error(format!("Invalid quote hex: {e}")))?;

    // Parse event log
    let event_log = tdx::parse_event_log(dstack_quote.event_log)
        .map_err(|e| to_py_error(format!("Failed to parse event log: {e}")))?;

    // Get collateral (from response or fetch from PCCS)
    let collateral = if let Some(collateral) = response_collateral {
        collateral
    } else if let Some(pccs) = policy.pccs_url.as_deref() {
        // Need to fetch collateral async
        let rt = Runtime::new()
            .map_err(|e| to_py_error(format!("Failed to create runtime: {e}")))?;
        rt.block_on(async {
            dcap_qvl::collateral::get_collateral(pccs, &quote_bytes).await
        })
        .map_err(|e| to_py_error(format!("Failed to fetch collateral: {e}")))?
    } else {
        return Err(to_py_error(
            "Server did not provide collateral and no PCCS configured",
        ));
    };

    // Verify attestation (needs async runtime for dcap_qvl)
    let rt =
        Runtime::new().map_err(|e| to_py_error(format!("Failed to create runtime: {e}")))?;
    let attestation = rt
        .block_on(async { tdx::verify_attestation(&quote_bytes, &collateral, policy).await })
        .map_err(ratls_error_to_py)?;

    // Verify nonce freshness
    tdx::verify_quote_freshness(&quote_bytes, nonce_hex.as_bytes()).map_err(ratls_error_to_py)?;

    // Verify event log integrity
    tdx::verify_event_log_integrity(&quote_bytes, &event_log).map_err(ratls_error_to_py)?;

    // Verify TLS certificate binding
    tdx::verify_tls_certificate_in_log(&event_log, server_cert).map_err(ratls_error_to_py)?;

    Ok(attestation.into())
}

/// Extract the peer certificate from a Python ssl.SSLSocket.
fn extract_peer_cert(sock: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    // Call getpeercert(binary_form=True) to get DER-encoded certificate
    let cert = sock.call_method1("getpeercert", (true,))?;

    if cert.is_none() {
        return Err(to_py_error("No peer certificate available"));
    }

    let bytes = cert
        .downcast::<PyBytes>()
        .map_err(|_| to_py_error("Expected bytes from getpeercert"))?;

    Ok(bytes.as_bytes().to_vec())
}

/// Low-level verification: verify attestation given certificate, quote, and event log.
///
/// This is useful if you want to handle the attestation protocol yourself
/// and just call Rust for the cryptographic verification.
///
/// Args:
///     peer_cert_der: DER-encoded peer certificate
///     quote_hex: Hex-encoded TDX quote
///     event_log: Event log as a list of dicts (optional)
///     collateral: Quote collateral as dict (optional, fetched from PCCS if not provided)
///     policy: Attestation policy
///     nonce: The nonce used in the attestation request (for freshness verification)
///
/// Returns:
///     AttestationResult with verification details
#[pyfunction]
#[pyo3(signature = (peer_cert_der, quote_hex, event_log=None, collateral=None, policy=None, nonce=None))]
pub fn verify_attestation(
    py: Python<'_>,
    peer_cert_der: Vec<u8>,
    quote_hex: String,
    event_log: Option<&Bound<'_, PyAny>>,
    collateral: Option<&Bound<'_, PyAny>>,
    policy: Option<PyPolicy>,
    nonce: Option<String>,
) -> PyResult<PyAttestationResult> {
    let core_policy: Policy = policy.unwrap_or_else(PyPolicy::py_default).into();

    // Parse quote
    let quote_bytes =
        hex::decode(&quote_hex).map_err(|e| to_py_error(format!("Invalid quote hex: {e}")))?;

    // Parse event log
    let event_log_value: Value = if let Some(el) = event_log {
        pythonize::depythonize(el).map_err(|e| to_py_error(format!("Invalid event log: {e}")))?
    } else {
        Value::Null
    };
    let events = tdx::parse_event_log(event_log_value)
        .map_err(|e| to_py_error(format!("Failed to parse event log: {e}")))?;

    // Parse or fetch collateral
    let coll: dcap_qvl::QuoteCollateralV3 = if let Some(c) = collateral {
        pythonize::depythonize(c).map_err(|e| to_py_error(format!("Invalid collateral: {e}")))?
    } else {
        // Fetch from PCCS synchronously
        py.allow_threads(|| {
            let rt = Runtime::new()
                .map_err(|e| to_py_error(format!("Failed to create runtime: {e}")))?;
            rt.block_on(async {
                let pccs_url = core_policy
                    .pccs_url
                    .as_deref()
                    .ok_or_else(|| to_py_error("No PCCS URL and no collateral provided"))?;
                dcap_qvl::collateral::get_collateral(pccs_url, &quote_bytes)
                    .await
                    .map_err(|e| to_py_error(format!("Failed to fetch collateral: {e}")))
            })
        })?
    };

    // Run verification
    let result = py.allow_threads(|| {
        let rt =
            Runtime::new().map_err(|e| to_py_error(format!("Runtime error: {e}")))?;
        rt.block_on(async { tdx::verify_attestation(&quote_bytes, &coll, &core_policy).await })
            .map_err(ratls_error_to_py)
    })?;

    // Verify freshness if nonce provided
    if let Some(n) = nonce {
        tdx::verify_quote_freshness(&quote_bytes, n.as_bytes()).map_err(ratls_error_to_py)?;
    }

    // Verify event log integrity
    tdx::verify_event_log_integrity(&quote_bytes, &events).map_err(ratls_error_to_py)?;

    // Verify certificate binding
    tdx::verify_tls_certificate_in_log(&events, &peer_cert_der).map_err(ratls_error_to_py)?;

    Ok(result.into())
}

/// Verify that the quote contains the expected nonce.
#[pyfunction]
pub fn verify_quote_freshness(quote_hex: String, nonce: String) -> PyResult<()> {
    let quote_bytes =
        hex::decode(&quote_hex).map_err(|e| to_py_error(format!("Invalid quote hex: {e}")))?;
    tdx::verify_quote_freshness(&quote_bytes, nonce.as_bytes()).map_err(ratls_error_to_py)
}

/// Verify event log integrity against quote RTMRs.
#[pyfunction]
pub fn verify_event_log_integrity(quote_hex: String, event_log: &Bound<'_, PyAny>) -> PyResult<()> {
    let quote_bytes =
        hex::decode(&quote_hex).map_err(|e| to_py_error(format!("Invalid quote hex: {e}")))?;
    let event_log_value: Value = pythonize::depythonize(event_log)
        .map_err(|e| to_py_error(format!("Invalid event log: {e}")))?;
    let events = tdx::parse_event_log(event_log_value)
        .map_err(|e| to_py_error(format!("Failed to parse event log: {e}")))?;
    tdx::verify_event_log_integrity(&quote_bytes, &events).map_err(ratls_error_to_py)
}

/// Verify that the TLS certificate is recorded in the event log.
#[pyfunction]
pub fn verify_tls_certificate_in_log(
    event_log: &Bound<'_, PyAny>,
    cert_der: Vec<u8>,
) -> PyResult<()> {
    let event_log_value: Value = pythonize::depythonize(event_log)
        .map_err(|e| to_py_error(format!("Invalid event log: {e}")))?;
    let events = tdx::parse_event_log(event_log_value)
        .map_err(|e| to_py_error(format!("Failed to parse event log: {e}")))?;
    tdx::verify_tls_certificate_in_log(&events, &cert_der).map_err(ratls_error_to_py)
}
