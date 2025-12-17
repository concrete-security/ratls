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
