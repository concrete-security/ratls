use crate::platform::{AsyncReadExt, AsyncWriteExt, TlsStream};
use crate::tdx;
use crate::{AsyncByteStream, AttestationEndpoint, AttestationResult, Policy, RatlsError};
use dcap_qvl::QuoteCollateralV3;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
struct AttestationRequest {
    report_data: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AttestationResponse {
    Success {
        quote: DstackQuote,
        #[serde(default)]
        collateral: Option<QuoteCollateralV3>,
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

/// Validates that the attestation endpoint path is safe to use in HTTP requests.
fn validate_endpoint_path(path: &str) -> Result<(), RatlsError> {
    // Prevent CRLF injection
    if path.contains('\r') || path.contains('\n') || path.contains('\0') {
        return Err(RatlsError::Policy(
            "Endpoint path contains invalid control characters".into(),
        ));
    }

    // Ensure path starts with /
    if !path.starts_with('/') {
        return Err(RatlsError::Policy(
            "Endpoint path must start with /".into(),
        ));
    }

    // Prevent path traversal
    if path.contains("../") || path.contains("/..") {
        return Err(RatlsError::Policy(
            "Path traversal sequences not allowed in endpoint path".into(),
        ));
    }

    // Reject paths that are suspiciously long
    if path.len() > 1024 {
        return Err(RatlsError::Policy(
            "Endpoint path is too long".into(),
        ));
    }

    Ok(())
}

pub async fn verify_attestation_stream<S>(
    stream: &mut TlsStream<S>,
    server_cert: &[u8],
    policy: &Policy,
    endpoint: &AttestationEndpoint,
) -> Result<AttestationResult, RatlsError>
where
    S: AsyncByteStream,
{
    validate_endpoint_path(&endpoint.path)?;

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);

    let body_json = serde_json::to_string(&AttestationRequest {
        report_data: nonce_hex.clone(),
    })
    .map_err(|e| RatlsError::Io(e.to_string()))?;
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        endpoint.path,
        body_json.len(),
        body_json
    );

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let mut header_buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| RatlsError::Io(e.to_string()))?;
        header_buffer.push(byte[0]);
        if header_buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buffer.len() > 8192 {
            return Err(RatlsError::Io("HTTP header too large".into()));
        }
    }

    let headers_str = String::from_utf8_lossy(&header_buffer);
    if !headers_str.starts_with("HTTP/1.1 200 OK") {
        let status_line = headers_str.lines().next().unwrap_or_default();
        return Err(RatlsError::Vendor(format!(
            "Server returned error: {status_line}"
        )));
    }

    let len_prefix = "content-length: ";
    let content_len = headers_str
        .to_lowercase()
        .lines()
        .find(|line| line.starts_with(len_prefix))
        .ok_or_else(|| RatlsError::Io("Missing Content-Length".into()))
        .and_then(|line| {
            line[len_prefix.len()..]
                .trim()
                .parse::<usize>()
                .map_err(|_| RatlsError::Io("Invalid Content-Length".into()))
        })?;

    let mut body = vec![0u8; content_len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let response: AttestationResponse = serde_json::from_slice(&body)
        .map_err(|e| RatlsError::Vendor(format!("Invalid server response: {e}")))?;

    let (dstack_quote, response_collateral) = match response {
        AttestationResponse::Success { quote, collateral } => (quote, collateral),
        AttestationResponse::Error { error } => return Err(RatlsError::Vendor(error)),
    };

    let quote_bytes = hex::decode(&dstack_quote.quote)
        .map_err(|e| RatlsError::Vendor(format!("Invalid quote hex: {e}")))?;
    let event_log = tdx::parse_event_log(dstack_quote.event_log)?;

    let collateral = if let Some(collateral) = response_collateral {
        collateral
    } else if let Some(pccs) = policy.pccs_url.as_deref() {
        dcap_qvl::collateral::get_collateral(pccs, &quote_bytes)
            .await
            .map_err(|e| RatlsError::Vendor(format!("Failed to fetch collateral: {e}")))?
    } else {
        return Err(RatlsError::Policy(
            "Server did not provide collateral and no PCCS configured".into(),
        ));
    };

    let attestation = tdx::verify_attestation(&quote_bytes, &collateral, policy).await?;

    tdx::verify_quote_freshness(&quote_bytes, nonce_hex.as_bytes())?;
    tdx::verify_event_log_integrity(&quote_bytes, &event_log)?;

    tdx::verify_tls_certificate_in_log(&event_log, server_cert)?;

    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_endpoint_path_valid() {
        // Valid paths should pass
        assert!(validate_endpoint_path("/tdx_quote").is_ok());
        assert!(validate_endpoint_path("/api/v1/attestation").is_ok());
        assert!(validate_endpoint_path("/path-with_underscores.json").is_ok());
    }

    #[test]
    fn test_validate_endpoint_path_crlf_injection() {
        // CRLF injection attempts should be rejected
        assert!(validate_endpoint_path("/tdx_quote\r\n").is_err());
        assert!(validate_endpoint_path("/tdx_quote\r\nX-Evil: header").is_err());
        assert!(validate_endpoint_path("/path\nwith\nnewlines").is_err());
        assert!(validate_endpoint_path("/path\0null").is_err());
    }

    #[test]
    fn test_validate_endpoint_path_traversal() {
        // Path traversal attempts should be rejected
        assert!(validate_endpoint_path("/../etc/passwd").is_err());
        assert!(validate_endpoint_path("/api/../admin").is_err());
        assert!(validate_endpoint_path("/path/../../sensitive").is_err());
    }

    #[test]
    fn test_validate_endpoint_path_missing_slash() {
        // Paths must start with /
        assert!(validate_endpoint_path("tdx_quote").is_err());
        assert!(validate_endpoint_path("api/v1").is_err());
    }

    #[test]
    fn test_validate_endpoint_path_too_long() {
        // Very long paths should be rejected
        let long_path = format!("/{}", "a".repeat(1024));
        assert!(validate_endpoint_path(&long_path).is_err());
    }
}
