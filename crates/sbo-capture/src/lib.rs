//! Client-side **capture** of SBO attribution material.
//!
//! This is the online, once-per-cert counterpart to `sbo-core`'s deterministic
//! attribution *verifier*. It mints the two values an email-rooted SBO write
//! carries:
//!
//! - **`Auth-Cert`** — a browserid certificate binding the SBO `Public-Key`
//!   (ephemeral) ↔ the user's email, obtained from a broker's `/wsapi/cert_key`
//!   endpoint after authenticating.
//! - **`Auth-Evidence`** — an RFC 9102 DNSSEC proof of the broker's
//!   `_browserid.<issuer>` TXT record, gathered live via `dnssec-prover`'s
//!   query feature and serialized as `inline:<base64url>`.
//!
//! The capture path is inherently online (HTTP to the broker, DNS to a
//! resolver). Offline unit tests cover the request/response shapes and the
//! evidence encoding; the network round-trips are exercised by `#[ignore]`d
//! live tests against the real broker (`id.sandmill.org`) — mirroring the
//! verifier's split in `sbo-core::attribution`.

use std::net::SocketAddr;

use browserid_core::discovery::SupportDocument;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use dnssec_prover::query::build_txt_proof_async;
use dnssec_prover::rr::Name;

/// The default DNS resolver to gather DNSSEC evidence from (Cloudflare, TCP).
pub const DEFAULT_RESOLVER: &str = "1.1.1.1:53";

/// Failure modes of the capture flow.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// An HTTP request to the broker failed at the transport level.
    #[error("broker request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The broker authenticated request was rejected.
    #[error("authentication failed{0}")]
    AuthRejected(String),
    /// The broker declined to issue a certificate.
    #[error("certificate provisioning failed{0}")]
    ProvisionRejected(String),
    /// The issued certificate could not be parsed.
    #[error("issued certificate could not be parsed: {0}")]
    BadCertificate(String),
    /// The DNSSEC evidence query failed.
    #[error("DNSSEC evidence capture failed: {0}")]
    Evidence(String),
    /// A domain/name was malformed.
    #[error("invalid name '{0}'")]
    BadName(String),
}

// ---------------------------------------------------------------------------
// Broker wire types (mirror browserid-broker's wsapi shapes).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuthenticateRequest<'a> {
    email: &'a str,
    pass: &'a str,
}

#[derive(Deserialize)]
struct AuthenticateResponse {
    success: bool,
    #[serde(default)]
    reason: Option<String>,
}

/// A thin client for a browserid broker. Carries a cookie store so the session
/// established by [`BrokerClient::authenticate`] is reused by
/// [`BrokerClient::provision`].
pub struct BrokerClient {
    base_url: String,
    http: reqwest::Client,
}

impl BrokerClient {
    /// Construct a client for a broker base URL (e.g. `https://id.sandmill.org`).
    pub fn new(base_url: impl Into<String>) -> Result<Self, CaptureError> {
        let http = reqwest::Client::builder().cookie_store(true).build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Fetch the broker's support document (`GET /.well-known/browserid`).
    pub async fn discover(&self) -> Result<SupportDocument, CaptureError> {
        let url = format!("{}/.well-known/browserid", self.base_url);
        let doc = self.http.get(&url).send().await?.error_for_status()?.json().await?;
        Ok(doc)
    }

    /// Authenticate to the broker (`POST /wsapi/authenticate_user`), establishing
    /// a session cookie used by the subsequent provisioning call.
    pub async fn authenticate(&self, email: &str, pass: &str) -> Result<(), CaptureError> {
        let url = format!("{}/wsapi/authenticate_user", self.base_url);
        let resp: AuthenticateResponse = self
            .http
            .post(&url)
            .json(&AuthenticateRequest { email, pass })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(CaptureError::AuthRejected(reason_suffix(resp.reason)));
        }
        Ok(())
    }

}

fn reason_suffix(reason: Option<String>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!(": {r}"),
        _ => String::new(),
    }
}

/// The FQDN whose TXT record carries a provider's browserid key:
/// `_browserid.<domain>.` (note the trailing dot required by `dnssec-prover`).
pub fn provider_record_name(domain: &str) -> Result<Name, CaptureError> {
    let fqdn = format!("_browserid.{}.", domain.trim_end_matches('.'));
    Name::try_from(fqdn.as_str()).map_err(|_| CaptureError::BadName(fqdn))
}

/// Capture an RFC 9102 DNSSEC proof of `_browserid.<domain>` from `resolver`,
/// returning the raw proof bytes (consumed by `sbo-core`'s verifier).
pub async fn capture_evidence(resolver: SocketAddr, domain: &str) -> Result<Vec<u8>, CaptureError> {
    let name = provider_record_name(domain)?;
    let (proof, _ttl) = build_txt_proof_async(resolver, &name)
        .await
        .map_err(|e| CaptureError::Evidence(e.to_string()))?;
    Ok(proof)
}

// ===========================================================================
// Device-cert capture path (browserid-ng v0.5).
//
// Flow: authenticate (session) → GET csrf → POST /device/issue (device + config
// certs) → build a fresh access key + POST /access/mint (access cert) → assemble
// the client-signed warrant + assertion into the RP-facing 4-object bundle
// `access_cert~assertion~warrant~config_cert`. The bundle is verified by
// `sbo_core::device_attribution::verify_device_attribution`.
// ===========================================================================

use browserid_core::device::{
    AccessCert, AccessPresentation, AccessRequest, DeviceCert, Subject, Warrant,
};
use browserid_core::{Assertion, KeyPair};
use chrono::Duration;

/// A captured device-model presentation, ready to attach to SBO writes. The
/// `access_key` is the fresh SBO signing key — it signs both the embedded
/// assertion and (the caller uses it for) the SBO envelope; its public half is
/// the `Public-Key` the verifier binds.
pub struct CapturedDevicePresentation {
    /// The `access_cert~assertion~warrant~config_cert` bundle.
    pub presentation: String,
    /// The `Auth-Evidence` value (`inline:<base64url>` DNSSEC proof for the IdP).
    pub auth_evidence: String,
    /// The issuing IdP domain (the DNSSEC-proven provider).
    pub issuer: String,
    /// The fresh access/SBO signing key (public half is bound by the verifier).
    pub access_key: KeyPair,
}

#[derive(Serialize)]
struct DeviceIssueRequest<'a> {
    csrf: &'a str,
    email: &'a str,
    device_pubkey: String,
    config_pubkey: String,
}

#[derive(Deserialize)]
struct DeviceIssueResponse {
    success: bool,
    #[serde(default)]
    device_cert: Option<String>,
    #[serde(default)]
    config_cert: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct AccessMintRequest<'a> {
    device_cert: &'a str,
    access_request: &'a str,
}

#[derive(Deserialize)]
struct AccessMintResponse {
    success: bool,
    #[serde(default)]
    access_cert: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct SessionContext {
    #[serde(default)]
    csrf_token: Option<String>,
}

impl BrokerClient {
    /// Fetch the session CSRF token (`GET /wsapi/session_context`). Requires a
    /// prior [`authenticate`](Self::authenticate).
    pub async fn csrf_token(&self) -> Result<String, CaptureError> {
        let url = format!("{}/wsapi/session_context", self.base_url);
        let ctx: SessionContext = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ctx.csrf_token
            .ok_or_else(|| CaptureError::AuthRejected(": no CSRF token (not authenticated)".into()))
    }

    /// Issue a device (authentication) + config (authorization) cert pair for
    /// `email` (`POST /device/issue`). Requires a prior authenticate + csrf.
    pub async fn device_issue(
        &self,
        csrf: &str,
        email: &str,
        device_pub: &browserid_core::PublicKey,
        config_pub: &browserid_core::PublicKey,
    ) -> Result<(DeviceCert, DeviceCert), CaptureError> {
        let url = format!("{}/device/issue", self.base_url);
        let resp: DeviceIssueResponse = self
            .http
            .post(&url)
            .json(&DeviceIssueRequest {
                csrf,
                email,
                device_pubkey: device_pub.to_base64(),
                config_pubkey: config_pub.to_base64(),
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(CaptureError::ProvisionRejected(reason_suffix(resp.reason)));
        }
        let device = DeviceCert::parse(
            &resp
                .device_cert
                .ok_or_else(|| CaptureError::ProvisionRejected(": no device cert".into()))?,
        )
        .map_err(|e| CaptureError::BadCertificate(e.to_string()))?;
        let config = DeviceCert::parse(
            &resp
                .config_cert
                .ok_or_else(|| CaptureError::ProvisionRejected(": no config cert".into()))?,
        )
        .map_err(|e| CaptureError::BadCertificate(e.to_string()))?;
        Ok((device, config))
    }

    /// Mint a fresh-key access cert (`POST /access/mint`). The `device_cert` is
    /// the credential (no session needed); `access_request` is signed by the
    /// device key over the fresh `access_pub`.
    pub async fn access_mint(
        &self,
        device_cert: &DeviceCert,
        access_request: &AccessRequest,
    ) -> Result<AccessCert, CaptureError> {
        let url = format!("{}/access/mint", self.base_url);
        let resp: AccessMintResponse = self
            .http
            .post(&url)
            .json(&AccessMintRequest {
                device_cert: device_cert.encoded(),
                access_request: access_request.encoded(),
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(CaptureError::ProvisionRejected(reason_suffix(resp.reason)));
        }
        let cert = resp
            .access_cert
            .ok_or_else(|| CaptureError::ProvisionRejected(": no access cert".into()))?;
        AccessCert::parse(&cert).map_err(|e| CaptureError::BadCertificate(e.to_string()))
    }
}

/// Run the full device-model capture against a broker for `email`, producing an
/// RP-ready `access_cert~assertion~warrant~config_cert` bundle for `audience`
/// (an `sbo+raw://…` reference) with `scopes`.
///
/// Device, config, and access keys are all generated fresh here. The device key
/// authenticates the mint; the config key signs the warrant; the access key is
/// the SBO signing key (returned so the caller can sign the SBO envelope with
/// the same key the verifier binds). DNSSEC evidence for the IdP issuer is
/// gathered so the verifier can root the provider key.
#[allow(clippy::too_many_arguments)]
pub async fn capture_device_attribution(
    broker_base_url: &str,
    email: &str,
    password: &str,
    audience: &str,
    scopes: Vec<String>,
    resolver: SocketAddr,
) -> Result<CapturedDevicePresentation, CaptureError> {
    let broker = BrokerClient::new(broker_base_url)?;
    broker.authenticate(email, password).await?;
    let csrf = broker.csrf_token().await?;

    // Fresh keys: device (authentication), config (authorization), access (SBO).
    let device_key = KeyPair::generate();
    let config_key = KeyPair::generate();
    let access_key = KeyPair::generate();

    let (device_cert, config_cert) = broker
        .device_issue(&csrf, email, &device_key.public_key(), &config_key.public_key())
        .await?;
    let issuer = device_cert.iss().to_string();

    // Device-signed request to mint a cert for the fresh access key.
    let jti = format!("{:016x}", rand_u64());
    let access_request = AccessRequest::create(
        &issuer,
        email,
        Subject::User,
        &access_key.public_key(),
        &jti,
        &device_key,
    )
    .map_err(|e| CaptureError::BadCertificate(e.to_string()))?;
    let access_cert = broker.access_mint(&device_cert, &access_request).await?;

    // Client-signed warrant (config cert) + assertion (access key) → bundle.
    let warrant = Warrant::create(
        email,
        Subject::User,
        audience,
        scopes,
        Duration::days(90),
        &config_key,
        None,
    )
    .map_err(|e| CaptureError::BadCertificate(e.to_string()))?;
    let assertion = Assertion::create(audience, Duration::minutes(10), &access_key)
        .map_err(|e| CaptureError::BadCertificate(e.to_string()))?;
    let presentation = AccessPresentation {
        access_cert,
        assertion,
        warrant,
        config_cert,
    }
    .encode();

    // DNSSEC evidence for _browserid.<issuer> (the provider key that signed the
    // access + config certs).
    let proof = capture_evidence(resolver, &issuer).await?;
    let auth_evidence = sbo_core::authorize::encode_auth_evidence_inline(&proof);

    Ok(CapturedDevicePresentation { presentation, auth_evidence, issuer, access_key })
}

/// A small non-crypto random u64 for the access-request `jti` (single-use nonce
/// checked at the mint; uniqueness, not unpredictability, is what matters here).
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix in the address of a stack local for a little extra entropy.
    let mix = &nanos as *const u64 as u64;
    nanos ^ mix.rotate_left(17)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_record_name_is_fqdn() {
        let n = provider_record_name("id.sandmill.org").unwrap();
        assert_eq!(n.as_str(), "_browserid.id.sandmill.org.");
        // A trailing dot on input is tolerated.
        let n2 = provider_record_name("sandmill.org.").unwrap();
        assert_eq!(n2.as_str(), "_browserid.sandmill.org.");
    }

    #[test]
    fn authenticate_request_shape() {
        let body = serde_json::to_value(AuthenticateRequest { email: "a@b.com", pass: "pw" }).unwrap();
        assert_eq!(body, serde_json::json!({"email": "a@b.com", "pass": "pw"}));
    }

    #[test]
    fn support_document_deserializes() {
        let doc: SupportDocument = serde_json::from_value(serde_json::json!({
            "public-key": {"algorithm": "Ed25519", "publicKey": "5w9yzPdFp5kjZZLbYl4jaR6EeS9VYGDEakzAf-a8Q9E"},
            "authentication": "/auth",
            "provisioning": "/provision"
        }))
        .unwrap();
        assert_eq!(doc.authentication.as_deref(), Some("/auth"));
        assert_eq!(doc.provisioning.as_deref(), Some("/provision"));
    }

    #[test]
    fn evidence_inline_roundtrips_with_verifier_parser() {
        let proof = b"\x00\x01rfc9102-proof\xfe\xff";
        let encoded = sbo_core::authorize::encode_auth_evidence_inline(proof);
        assert!(encoded.starts_with("inline:"));
        let decoded = sbo_core::authorize::parse_auth_evidence(&encoded).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn device_issue_request_shape() {
        let dev = KeyPair::generate();
        let cfg = KeyPair::generate();
        let body = serde_json::to_value(DeviceIssueRequest {
            csrf: "tok",
            email: "a@b.com",
            device_pubkey: dev.public_key().to_base64(),
            config_pubkey: cfg.public_key().to_base64(),
        })
        .unwrap();
        assert_eq!(body["csrf"], "tok");
        assert_eq!(body["email"], "a@b.com");
        assert_eq!(body["device_pubkey"], dev.public_key().to_base64());
        assert_eq!(body["config_pubkey"], cfg.public_key().to_base64());
    }

    #[test]
    fn device_issue_response_parses() {
        let ok: DeviceIssueResponse = serde_json::from_value(serde_json::json!({
            "success": true, "device_cert": "DC", "config_cert": "CC"
        }))
        .unwrap();
        assert!(ok.success);
        assert_eq!(ok.device_cert.as_deref(), Some("DC"));
        assert_eq!(ok.config_cert.as_deref(), Some("CC"));
    }

    #[test]
    fn access_mint_response_parses() {
        let ok: AccessMintResponse =
            serde_json::from_value(serde_json::json!({"success": true, "access_cert": "AC"}))
                .unwrap();
        assert!(ok.success);
        assert_eq!(ok.access_cert.as_deref(), Some("AC"));
        let err: AccessMintResponse =
            serde_json::from_value(serde_json::json!({"success": false, "reason": "nope"}))
                .unwrap();
        assert!(!err.success);
    }

    /// jti nonces are unique across calls (single-use replay protection).
    #[test]
    fn rand_u64_varies() {
        assert_ne!(rand_u64(), rand_u64());
    }

    /// Live test: capture real DNSSEC evidence for `_browserid.sandmill.org`
    /// from a validating resolver. Requires network; run with
    /// `cargo test -p sbo-capture -- --ignored`.
    #[tokio::test]
    #[ignore = "requires live DNS"]
    async fn live_capture_evidence_sandmill() {
        let resolver: SocketAddr = DEFAULT_RESOLVER.parse().unwrap();
        let proof = capture_evidence(resolver, "sandmill.org").await.unwrap();
        assert!(!proof.is_empty());
        // The proof must validate offline against the pinned IANA root.
        let rrs = dnssec_prover::ser::parse_rr_stream(&proof).unwrap();
        dnssec_prover::validation::verify_rr_stream(&rrs).unwrap();
    }

    /// Full live device-model capture against the real broker, then verify the
    /// captured presentation through `sbo-core`'s deterministic device verifier
    /// — the complete email-attribution loop.
    ///
    /// Requires a real broker account. Run with:
    /// ```text
    /// SBO_TEST_EMAIL=you@sandmill.org SBO_TEST_PASSWORD=... \
    ///   cargo test -p sbo-capture -- --ignored live_capture_device_e2e
    /// ```
    /// Optional overrides: `SBO_BROKER_URL` (default `https://id.sandmill.org`),
    /// `SBO_DNS_RESOLVER` (default `1.1.1.1:53`).
    #[tokio::test]
    #[ignore = "requires live broker account (SBO_TEST_EMAIL / SBO_TEST_PASSWORD)"]
    async fn live_capture_device_e2e() {
        let email = std::env::var("SBO_TEST_EMAIL").expect("set SBO_TEST_EMAIL");
        let password = std::env::var("SBO_TEST_PASSWORD").expect("set SBO_TEST_PASSWORD");
        let broker = std::env::var("SBO_BROKER_URL")
            .unwrap_or_else(|_| "https://id.sandmill.org".to_string());
        let resolver: SocketAddr = std::env::var("SBO_DNS_RESOLVER")
            .unwrap_or_else(|_| DEFAULT_RESOLVER.to_string())
            .parse()
            .unwrap();

        let audience = "sbo+raw://avail:turing:506/".to_string();
        let captured = capture_device_attribution(
            &broker, &email, &password, &audience, vec![], resolver,
        )
        .await
        .expect("device capture should succeed");

        // Verify it the way every replayer will: deterministic offline check.
        let evidence = sbo_core::authorize::parse_auth_evidence(&captured.auth_evidence).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Email domain != issuer (broker), so the issuer must be a pinned broker.
        let anchors =
            sbo_core::attribution::TrustAnchors::with_brokers(vec![captured.issuer.clone()]);

        let attribution = sbo_core::device_attribution::verify_device_attribution(
            &captured.access_key.public_key().to_base64(),
            &captured.presentation,
            &evidence,
            &audience,
            now,
            &anchors,
        )
        .expect("captured device attribution should verify");
        assert_eq!(attribution.email, email);
    }
}
