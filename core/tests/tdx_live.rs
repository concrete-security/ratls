use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratls_core::{ratls_connect, Policy};
use tokio::net::TcpStream;

fn install_crypto_provider() {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());
}

#[tokio::test]
async fn verify_live_tdx_quote() {
    install_crypto_provider();

    let client = reqwest::Client::new();
    let resp = match client
        .post("https://vllm.concrete-security.com/tdx_quote")
        .json(&serde_json::json!({ "report_data": "deadbeefcafebabe" }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            eprintln!("quote fetch failed: {err}");
            return;
        }
    };
    if !resp.status().is_success() {
        eprintln!("quote endpoint returned {}", resp.status());
        return;
    }
    let body: serde_json::Value = resp.json().await.expect("decode json");
    let quote_hex = match body["quote"]["quote"].as_str() {
        Some(v) => v,
        None => {
            eprintln!("missing quote field");
            return;
        }
    };
    let quote = match hex::decode(quote_hex) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("invalid quote hex: {err}");
            return;
        }
    };

    let collateral = match dcap_qvl::collateral::get_collateral_from_pcs(&quote).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("failed to fetch collateral: {err}");
            return;
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let res = dcap_qvl::verify::verify(&quote, &collateral, now);
    assert!(res.is_ok(), "live quote verification failed: {res:?}");
}

#[tokio::test]
async fn connect_to_vllm_with_ratls() {
    install_crypto_provider();

    const HOST: &str = "vllm.concrete-security.com";
    let stream = TcpStream::connect((HOST, 443))
        .await
        .unwrap_or_else(|err| panic!("tcp connect to {HOST} failed: {err}"));

    let policy = Policy {
        allowed_tdx_status: vec![
            "UpToDate".into(),
            "UpToDateWithWarnings".into(),
            "ConfigurationNeeded".into(),
            "SWHardeningNeeded".into(),
            "ConfigurationAndSWHardeningNeeded".into(),
            "OutOfDate".into(),
            "OutOfDateConfigurationNeeded".into(),
        ],
        ..Policy::default()
    };

    let result = ratls_connect(stream, HOST, policy, None).await;
    assert!(
        result.is_ok(),
        "connection to {HOST} failed: {:?}",
        result
    );
    let (_, attestation) = result.unwrap();
    assert!(
        attestation.trusted,
        "attestation should be trusted, got: {:?}",
        attestation
    );
    assert_eq!(
        attestation.tee_type,
        ratls_core::TeeType::Tdx,
        "expected TDX tee type, got: {:?}",
        attestation.tee_type
    );
}
