//! WASM bindings for RA-TLS attested connections.
//!
//! This module provides a minimal API for establishing attested TLS connections
//! from browsers. It exposes native Web Streams (ReadableStream) for response reading.

#![cfg(target_arch = "wasm32")]

use async_io_stream::IoStream;
use futures::io::{ReadHalf, WriteHalf};
use futures::AsyncReadExt;
use ratls_core::{
    platform::{AsyncWriteExt, TlsStream},
    ratls_connect, Policy,
};
use serde::Serialize;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use web_sys::js_sys::{Object, Promise, Reflect, Uint8Array};
use web_sys::ReadableStreamDefaultController;
use ws_stream_wasm::{WsMeta, WsStreamIo};

type WsIo = IoStream<WsStreamIo, Vec<u8>>;

fn create_readable_stream(reader: ReadHalf<TlsStream<WsIo>>) -> web_sys::ReadableStream {
    let reader = Rc::new(RefCell::new(reader));
    let underlying_source = Object::new();

    let reader_clone = reader.clone();
    let pull = Closure::wrap(Box::new(move |controller: ReadableStreamDefaultController| {
        let reader = reader_clone.clone();
        let promise = wasm_bindgen_futures::future_to_promise(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut reader_ref = reader.borrow_mut();
            match reader_ref.read(&mut buf).await {
                Ok(0) => {
                    controller.close().ok();
                }
                Ok(n) => {
                    let chunk = Uint8Array::from(&buf[..n]);
                    controller.enqueue_with_chunk(&chunk.into()).ok();
                }
                Err(e) => {
                    let error = JsValue::from_str(&e.to_string());
                    controller.error_with_e(&error);
                }
            }
            Ok(JsValue::UNDEFINED)
        });
        promise
    }) as Box<dyn FnMut(ReadableStreamDefaultController) -> Promise>);

    Reflect::set(&underlying_source, &"pull".into(), pull.as_ref()).unwrap();
    pull.forget();

    web_sys::ReadableStream::new_with_underlying_source(&underlying_source).unwrap()
}

/// Attestation result summary exposed to JavaScript.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSummary {
    pub trusted: bool,
    pub tee_type: String,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

/// An attested TLS stream over a WebSocket connection.
///
/// Provides a native `ReadableStream` for response data and a `send` method
/// for writing requests. This design allows zero-copy response streaming
/// while keeping the write path simple.
#[wasm_bindgen]
pub struct AttestedStream {
    writer: Rc<RefCell<Option<WriteHalf<TlsStream<WsIo>>>>>,
    attestation: AttestationSummary,
    readable: web_sys::ReadableStream,
}

#[wasm_bindgen]
impl AttestedStream {
    /// Connect to a TEE server via WebSocket proxy and perform RA-TLS handshake.
    ///
    /// Returns an AttestedStream with:
    /// - `readable`: Native ReadableStream for response data
    /// - `send(data)`: Method to write request data
    /// - `attestation()`: Attestation verification result
    ///
    /// # Arguments
    /// * `ws_url` - WebSocket URL (e.g., "ws://proxy:9000?target=host:443")
    /// * `server_name` - TLS server name for SNI
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(ws_url: &str, server_name: &str) -> Result<AttestedStream, JsValue> {
        // 1. Establish WebSocket tunnel
        let (_meta, ws_stream) = WsMeta::connect(ws_url, None)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // 2. Perform RA-TLS handshake
        let (tls, att) = ratls_connect(
            ws_stream.into_io(),
            server_name,
            Policy::default(),
            Some(vec!["http/1.1".into()]),
        )
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let (reader, writer) = tls.split();

        let readable = create_readable_stream(reader);

        Ok(AttestedStream {
            writer: Rc::new(RefCell::new(Some(writer))),
            attestation: AttestationSummary {
                trusted: att.trusted,
                tee_type: format!("{:?}", att.tee_type),
                tcb_status: att.tcb_status,
                advisory_ids: att.advisory_ids,
            },
            readable,
        })
    }

    /// Get the native ReadableStream for response data.
    ///
    /// This stream can be passed directly to `new Response(readable)`.
    #[wasm_bindgen(getter)]
    pub fn readable(&self) -> web_sys::ReadableStream {
        self.readable.clone()
    }

    /// Get the attestation result from the RA-TLS handshake.
    #[wasm_bindgen(js_name = attestation)]
    pub fn attestation(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.attestation)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Send data to the TEE over the attested TLS connection.
    #[wasm_bindgen(js_name = send)]
    pub async fn send(&self, data: &[u8]) -> Result<(), JsValue> {
        let mut writer_opt = self.writer.borrow_mut();
        let writer = writer_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("stream is closed"))?;

        writer
            .write_all(data)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        writer
            .flush()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Close the write side of the stream.
    #[wasm_bindgen(js_name = closeWrite)]
    pub async fn close_write(&self) -> Result<(), JsValue> {
        let mut writer_opt = self.writer.borrow_mut();
        if let Some(mut writer) = writer_opt.take() {
            writer
                .close()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        Ok(())
    }
}

// ============================================================================
// HTTP Client with Chunked Transfer Decoding
// ============================================================================

/// Body encoding for HTTP responses.
enum BodyEncoding {
    /// Fixed content length.
    ContentLength(usize),
    /// Chunked transfer encoding.
    Chunked,
    /// No body (e.g., for 204, 304 responses).
    None,
}

/// State machine for chunked transfer decoding.
enum ChunkedState {
    /// Reading the hex size line.
    ReadingSize,
    /// Reading chunk data of known size.
    ReadingData { remaining: usize },
    /// Reading the CRLF after chunk data.
    ReadingTrailer,
    /// Final chunk received (size 0).
    Done,
}

/// HTTP response parsed from headers.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpResponse {
    status: u16,
    status_text: String,
    headers: Vec<(String, String)>,
}

/// High-level HTTP client over attested TLS.
///
/// Provides a fetch-like API that handles HTTP/1.1 protocol details
/// including chunked transfer encoding for streaming responses.
#[wasm_bindgen]
pub struct RatlsHttp {
    reader: Rc<RefCell<Option<ReadHalf<TlsStream<WsIo>>>>>,
    writer: Rc<RefCell<Option<WriteHalf<TlsStream<WsIo>>>>>,
    attestation: AttestationSummary,
    /// Buffer for partial reads during header parsing.
    buffer: Rc<RefCell<Vec<u8>>>,
}

#[wasm_bindgen]
impl RatlsHttp {
    /// Connect to a TEE server and perform RA-TLS handshake.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(ws_url: &str, server_name: &str) -> Result<RatlsHttp, JsValue> {
        let (_meta, ws_stream) = WsMeta::connect(ws_url, None)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let (tls, att) = ratls_connect(
            ws_stream.into_io(),
            server_name,
            Policy::default(),
            Some(vec!["http/1.1".into()]),
        )
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let (reader, writer) = tls.split();

        Ok(RatlsHttp {
            reader: Rc::new(RefCell::new(Some(reader))),
            writer: Rc::new(RefCell::new(Some(writer))),
            attestation: AttestationSummary {
                trusted: att.trusted,
                tee_type: format!("{:?}", att.tee_type),
                tcb_status: att.tcb_status,
                advisory_ids: att.advisory_ids,
            },
            buffer: Rc::new(RefCell::new(Vec::new())),
        })
    }

    /// Get attestation result.
    #[wasm_bindgen(js_name = attestation)]
    pub fn attestation(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.attestation)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Perform an HTTP request and return response with streaming body.
    ///
    /// Returns a JS object: { status, statusText, headers, body }
    /// where body is a native ReadableStream.
    #[wasm_bindgen(js_name = fetch)]
    pub async fn fetch(
        &self,
        method: &str,
        path: &str,
        host: &str,
        headers_js: JsValue,
        body: Option<Vec<u8>>,
    ) -> Result<JsValue, JsValue> {
        // Parse headers from JS
        let headers: Vec<(String, String)> = if headers_js.is_null() || headers_js.is_undefined() {
            vec![]
        } else {
            serde_wasm_bindgen::from_value(headers_js)
                .map_err(|e| JsValue::from_str(&format!("Invalid headers: {e}")))?
        };

        // Build HTTP request
        let request = build_http_request(method, path, host, &headers, body.as_deref());

        // Send request
        {
            let mut writer_opt = self.writer.borrow_mut();
            let writer = writer_opt
                .as_mut()
                .ok_or_else(|| JsValue::from_str("connection closed"))?;

            writer
                .write_all(request.as_bytes())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            if let Some(ref body_data) = body {
                writer
                    .write_all(body_data)
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }

            writer
                .flush()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        // Read and parse headers
        let (response, encoding, leftover) = self.read_response_headers().await?;

        // Store leftover data in buffer
        *self.buffer.borrow_mut() = leftover;

        // Create body ReadableStream based on encoding
        let body_stream = self.create_body_stream(encoding);

        // Build JS response object
        let result = Object::new();
        Reflect::set(&result, &"status".into(), &JsValue::from(response.status))?;
        Reflect::set(
            &result,
            &"statusText".into(),
            &JsValue::from_str(&response.status_text),
        )?;

        // Convert headers to JS object
        let headers_obj = Object::new();
        for (name, value) in &response.headers {
            Reflect::set(&headers_obj, &name.into(), &JsValue::from_str(value))?;
        }
        Reflect::set(&result, &"headers".into(), &headers_obj)?;

        Reflect::set(&result, &"body".into(), &body_stream)?;

        Ok(result.into())
    }

    /// Read from TLS stream until headers are complete.
    async fn read_response_headers(
        &self,
    ) -> Result<(HttpResponse, BodyEncoding, Vec<u8>), JsValue> {
        let mut header_buf = Vec::new();
        let mut temp = [0u8; 4096];

        loop {
            // Check if we have complete headers
            if let Some(end_pos) = find_header_end(&header_buf) {
                // Parse headers with httparse (include the \r\n\r\n terminator)
                let (response, encoding) = parse_headers(&header_buf[..end_pos + 4])?;

                // Return leftover data after headers
                let leftover = header_buf[end_pos + 4..].to_vec();
                return Ok((response, encoding, leftover));
            }

            // Read more data
            let n = {
                let mut reader_opt = self.reader.borrow_mut();
                let reader = reader_opt
                    .as_mut()
                    .ok_or_else(|| JsValue::from_str("connection closed"))?;

                reader
                    .read(&mut temp)
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            };

            if n == 0 {
                return Err(JsValue::from_str("connection closed before headers complete"));
            }

            header_buf.extend_from_slice(&temp[..n]);

            if header_buf.len() > 64 * 1024 {
                return Err(JsValue::from_str("HTTP headers too large"));
            }
        }
    }

    /// Create a ReadableStream for the response body.
    fn create_body_stream(&self, encoding: BodyEncoding) -> web_sys::ReadableStream {
        let reader = self.reader.clone();
        let buffer = self.buffer.clone();

        match encoding {
            BodyEncoding::None => {
                // Return empty stream
                let underlying_source = Object::new();
                let start = Closure::wrap(Box::new(
                    move |controller: ReadableStreamDefaultController| {
                        controller.close().ok();
                    },
                )
                    as Box<dyn FnMut(ReadableStreamDefaultController)>);
                Reflect::set(&underlying_source, &"start".into(), start.as_ref()).unwrap();
                start.forget();
                web_sys::ReadableStream::new_with_underlying_source(&underlying_source).unwrap()
            }

            BodyEncoding::ContentLength(len) => {
                create_content_length_stream(reader, buffer, len)
            }

            BodyEncoding::Chunked => create_chunked_stream(reader, buffer),
        }
    }
}

/// Build an HTTP/1.1 request string.
fn build_http_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> String {
    let mut request = format!("{} {} HTTP/1.1\r\n", method, if path.is_empty() { "/" } else { path });
    request.push_str(&format!("Host: {}\r\n", host));
    request.push_str("Connection: close\r\n");

    for (name, value) in headers {
        if name.to_lowercase() != "host" && name.to_lowercase() != "connection" {
            request.push_str(&format!("{}: {}\r\n", name, value));
        }
    }

    if let Some(b) = body {
        request.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }

    request.push_str("\r\n");
    request
}

/// Find the end of HTTP headers (CRLFCRLF).
fn find_header_end(data: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = b"\r\n\r\n";
    data.windows(4).position(|w| w == MARKER)
}

/// Parse HTTP response headers using httparse.
fn parse_headers(data: &[u8]) -> Result<(HttpResponse, BodyEncoding), JsValue> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers_buf);

    match response.parse(data) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(JsValue::from_str("incomplete HTTP headers"));
        }
        Err(e) => {
            return Err(JsValue::from_str(&format!("HTTP parse error: {e}")));
        }
    }

    let status = response.code.unwrap_or(0);
    let status_text = response.reason.unwrap_or("").to_string();

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;

    for header in response.headers.iter() {
        let name = header.name.to_string();
        let value = String::from_utf8_lossy(header.value).to_string();

        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            is_chunked = value.to_lowercase().contains("chunked");
        }

        headers.push((name, value));
    }

    // Determine body encoding
    let encoding = if status == 204 || status == 304 || (100..200).contains(&status) {
        BodyEncoding::None
    } else if is_chunked {
        BodyEncoding::Chunked
    } else if let Some(len) = content_length {
        BodyEncoding::ContentLength(len)
    } else {
        // No content-length and not chunked - read until close
        BodyEncoding::ContentLength(usize::MAX)
    };

    Ok((
        HttpResponse {
            status,
            status_text,
            headers,
        },
        encoding,
    ))
}

/// Create a ReadableStream that reads exactly `len` bytes.
fn create_content_length_stream(
    reader: Rc<RefCell<Option<ReadHalf<TlsStream<WsIo>>>>>,
    buffer: Rc<RefCell<Vec<u8>>>,
    total_len: usize,
) -> web_sys::ReadableStream {
    let remaining = Rc::new(RefCell::new(total_len));
    let underlying_source = Object::new();

    let pull = Closure::wrap(Box::new(move |controller: ReadableStreamDefaultController| {
        let reader = reader.clone();
        let buffer = buffer.clone();
        let remaining = remaining.clone();

        wasm_bindgen_futures::future_to_promise(async move {
            let mut rem = remaining.borrow_mut();

            if *rem == 0 {
                controller.close().ok();
                return Ok(JsValue::UNDEFINED);
            }

            // First, drain any buffered data
            {
                let mut buf = buffer.borrow_mut();
                if !buf.is_empty() {
                    let take = buf.len().min(*rem);
                    let chunk: Vec<u8> = buf.drain(..take).collect();
                    *rem = rem.saturating_sub(chunk.len());

                    let arr = Uint8Array::from(&chunk[..]);
                    controller.enqueue_with_chunk(&arr.into()).ok();

                    if *rem == 0 {
                        controller.close().ok();
                    }
                    return Ok(JsValue::UNDEFINED);
                }
            }

            // Read from stream
            let mut temp = vec![0u8; 16 * 1024];
            let read_len = temp.len().min(*rem);

            let n = {
                let mut reader_opt = reader.borrow_mut();
                match reader_opt.as_mut() {
                    Some(r) => r.read(&mut temp[..read_len]).await.unwrap_or(0),
                    None => 0,
                }
            };

            if n == 0 {
                controller.close().ok();
            } else {
                *rem = rem.saturating_sub(n);
                let arr = Uint8Array::from(&temp[..n]);
                controller.enqueue_with_chunk(&arr.into()).ok();

                if *rem == 0 {
                    controller.close().ok();
                }
            }

            Ok(JsValue::UNDEFINED)
        })
    }) as Box<dyn FnMut(ReadableStreamDefaultController) -> Promise>);

    Reflect::set(&underlying_source, &"pull".into(), pull.as_ref()).unwrap();
    pull.forget();

    web_sys::ReadableStream::new_with_underlying_source(&underlying_source).unwrap()
}

/// Create a ReadableStream that decodes chunked transfer encoding.
fn create_chunked_stream(
    reader: Rc<RefCell<Option<ReadHalf<TlsStream<WsIo>>>>>,
    buffer: Rc<RefCell<Vec<u8>>>,
) -> web_sys::ReadableStream {
    let state = Rc::new(RefCell::new(ChunkedState::ReadingSize));
    let underlying_source = Object::new();

    let pull = Closure::wrap(Box::new(move |controller: ReadableStreamDefaultController| {
        let reader = reader.clone();
        let buffer = buffer.clone();
        let state = state.clone();

        wasm_bindgen_futures::future_to_promise(async move {
            loop {
                let current_state = state.borrow().clone();

                match current_state {
                    ChunkedState::Done => {
                        controller.close().ok();
                        return Ok(JsValue::UNDEFINED);
                    }

                    ChunkedState::ReadingSize => {
                        // Look for chunk size line ending with CRLF
                        let line_end = {
                            let buf = buffer.borrow();
                            buf.windows(2).position(|w| w == b"\r\n")
                        };

                        if let Some(pos) = line_end {
                            let mut buf = buffer.borrow_mut();
                            let line: Vec<u8> = buf.drain(..pos).collect();
                            buf.drain(..2); // Remove CRLF

                            // Parse hex size (ignore chunk extensions after ';')
                            let size_str = String::from_utf8_lossy(&line);
                            let size_part = size_str.split(';').next().unwrap_or("").trim();
                            let chunk_size = usize::from_str_radix(size_part, 16).unwrap_or(0);

                            if chunk_size == 0 {
                                *state.borrow_mut() = ChunkedState::Done;
                            } else {
                                *state.borrow_mut() = ChunkedState::ReadingData {
                                    remaining: chunk_size,
                                };
                            }
                        } else {
                            // Need more data
                            if !read_more(&reader, &buffer).await {
                                controller.close().ok();
                                return Ok(JsValue::UNDEFINED);
                            }
                        }
                    }

                    ChunkedState::ReadingData { remaining } => {
                        let buf_len = buffer.borrow().len();

                        if buf_len > 0 {
                            let take = buf_len.min(remaining);
                            let chunk: Vec<u8> = buffer.borrow_mut().drain(..take).collect();
                            let new_remaining = remaining - chunk.len();

                            let arr = Uint8Array::from(&chunk[..]);
                            controller.enqueue_with_chunk(&arr.into()).ok();

                            if new_remaining == 0 {
                                *state.borrow_mut() = ChunkedState::ReadingTrailer;
                            } else {
                                *state.borrow_mut() = ChunkedState::ReadingData {
                                    remaining: new_remaining,
                                };
                            }
                            return Ok(JsValue::UNDEFINED);
                        } else {
                            // Need more data
                            if !read_more(&reader, &buffer).await {
                                controller.close().ok();
                                return Ok(JsValue::UNDEFINED);
                            }
                        }
                    }

                    ChunkedState::ReadingTrailer => {
                        // Skip the CRLF after chunk data
                        let buf_len = buffer.borrow().len();
                        if buf_len >= 2 {
                            buffer.borrow_mut().drain(..2);
                            *state.borrow_mut() = ChunkedState::ReadingSize;
                        } else {
                            // Need more data
                            if !read_more(&reader, &buffer).await {
                                controller.close().ok();
                                return Ok(JsValue::UNDEFINED);
                            }
                        }
                    }
                }
            }
        })
    }) as Box<dyn FnMut(ReadableStreamDefaultController) -> Promise>);

    Reflect::set(&underlying_source, &"pull".into(), pull.as_ref()).unwrap();
    pull.forget();

    web_sys::ReadableStream::new_with_underlying_source(&underlying_source).unwrap()
}

/// Read more data from the TLS stream into the buffer.
async fn read_more(
    reader: &Rc<RefCell<Option<ReadHalf<TlsStream<WsIo>>>>>,
    buffer: &Rc<RefCell<Vec<u8>>>,
) -> bool {
    let mut temp = [0u8; 8192];
    let n = {
        let mut reader_opt = reader.borrow_mut();
        match reader_opt.as_mut() {
            Some(r) => r.read(&mut temp).await.unwrap_or(0),
            None => 0,
        }
    };

    if n == 0 {
        return false;
    }

    buffer.borrow_mut().extend_from_slice(&temp[..n]);
    true
}

// Need Clone for ChunkedState to work with state machine
impl Clone for ChunkedState {
    fn clone(&self) -> Self {
        match self {
            ChunkedState::ReadingSize => ChunkedState::ReadingSize,
            ChunkedState::ReadingData { remaining } => ChunkedState::ReadingData {
                remaining: *remaining,
            },
            ChunkedState::ReadingTrailer => ChunkedState::ReadingTrailer,
            ChunkedState::Done => ChunkedState::Done,
        }
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // Tests can run in both browser and Node.js
    // Remove run_in_browser to allow Node.js execution

    #[wasm_bindgen_test]
    fn test_attestation_summary_serialization() {
        let summary = AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec!["INTEL-SA-00001".to_string()],
        };

        // Test that it can be serialized to JSON
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"trusted\":true"));
        assert!(json.contains("\"teeType\":\"Tdx\""));
        assert!(json.contains("\"tcbStatus\":\"UpToDate\""));
        assert!(json.contains("INTEL-SA-00001"));
    }

    #[wasm_bindgen_test]
    fn test_attestation_summary_camel_case() {
        let summary = AttestationSummary {
            trusted: false,
            tee_type: "Snp".to_string(),
            tcb_status: "SWHardeningNeeded".to_string(),
            advisory_ids: vec![],
        };

        let json = serde_json::to_string(&summary).unwrap();
        // Verify camelCase renaming is applied
        assert!(json.contains("teeType"));
        assert!(json.contains("tcbStatus"));
        assert!(json.contains("advisoryIds"));
        // Verify snake_case is NOT present
        assert!(!json.contains("tee_type"));
        assert!(!json.contains("tcb_status"));
        assert!(!json.contains("advisory_ids"));
    }

    #[wasm_bindgen_test]
    fn test_attestation_summary_to_js_value() {
        let summary = AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec!["ADV1".to_string(), "ADV2".to_string()],
        };

        // Test conversion to JsValue via serde-wasm-bindgen
        let js_value = serde_wasm_bindgen::to_value(&summary).unwrap();
        assert!(!js_value.is_undefined());
        assert!(!js_value.is_null());
    }

    #[wasm_bindgen_test]
    fn test_attestation_summary_empty_advisories() {
        let summary = AttestationSummary {
            trusted: true,
            tee_type: "Tdx".to_string(),
            tcb_status: "UpToDate".to_string(),
            advisory_ids: vec![],
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"advisoryIds\":[]"));
    }
}
