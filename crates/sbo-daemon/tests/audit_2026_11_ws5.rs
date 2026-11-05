//! AUDIT-2026-11 WS5 — HTTP / IPC / outbound-fetch findings for the daemon.
//!
//! Each test encodes one verdict from `docs/security-audit-2026-11-ws5-http-surface.md`.
//! Tests that FAIL today are `#[ignore]`d with an `AUDIT-2026-11 W5-n` comment
//! and are the acceptance test for the fix; the rest pass today and pin what
//! was re-verified. Everything runs in-process or against loopback listeners
//! this file opens itself; no production host, no real keys, no live DNS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;

use sbo_daemon::http::{
    create_router, ApiError, ListSelector, ObjectView, RepoApi, StateRootView, SubmitResultView,
};
use sbo_daemon::status::StatusChecker;
use sbo_core::browserid_core::{KeyPair, StatusRef};

// ---------------------------------------------------------------------------
// Peak-allocation meter (for the gzip-bomb test)
// ---------------------------------------------------------------------------

struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl std::alloc::GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        let p = std::alloc::System.alloc(l);
        if !p.is_null() {
            let live = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        std::alloc::System.dealloc(p, l)
    }
}

#[global_allocator]
static GLOBAL: Meter = Meter;

fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Loopback helpers
// ---------------------------------------------------------------------------

/// Bind a loopback TCP listener and report whether ANY connection arrives
/// within `wait`. Used to observe whether an outbound fetcher even tries to
/// reach a non-public address.
async fn connection_observer(wait: Duration) -> (SocketAddr, tokio::task::JoinHandle<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        tokio::time::timeout(wait, listener.accept()).await.is_ok()
    });
    (addr, h)
}

fn authority_keys(authority: &str) -> HashMap<String, sbo_daemon::status::AuthorityKey> {
    let kp = KeyPair::generate();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    HashMap::from([(authority.to_string(), (kp.public_key(), now - 3600, now + 3600))])
}

// ---------------------------------------------------------------------------
// W5-4 (WS1 D18): submit-gate status fetch reaches non-public hosts (SSRF)
// ---------------------------------------------------------------------------

/// Passes today: a non-`https` status URI is refused before any connection.
#[tokio::test]
async fn status_fetch_refuses_plain_http_without_connecting() {
    let (addr, observed) = connection_observer(Duration::from_millis(500)).await;
    let checker = StatusChecker::new();
    let refs = vec![("warrant", StatusRef { uri: format!("http://{addr}/list"), idx: 1 }, "idp.test".to_string())];
    let err = checker.check_all(&refs, &authority_keys("idp.test")).await.unwrap_err();
    assert!(err.contains("not https"), "{err}");
    assert!(!observed.await.unwrap(), "a plain-http URI must never be dialled");
}

/// AUDIT-2026-11 W5-4: a status URI naming a loopback / private address is
/// refused before any connection (the host must resolve to globally routable
/// addresses only), so the submit gate is no longer a blind SSRF probe
/// steered by the presentation's `status.uri` (I31; browserid-ng H1 class).
#[tokio::test]
async fn status_fetch_never_dials_a_non_public_address() {
    let (addr, observed) = connection_observer(Duration::from_secs(3)).await;
    let checker = StatusChecker::new();
    let refs = vec![("warrant", StatusRef { uri: format!("https://{addr}/list"), idx: 1 }, "idp.test".to_string())];
    let _ = checker.check_all(&refs, &authority_keys("idp.test")).await;
    assert!(!observed.await.unwrap(), "status fetch dialled a loopback address");
}

/// AUDIT-2026-11 W5-4 / D52: for the IdP-issued certs the status URI host
/// must equal the credential's authority (`iss`), so an access/config cert
/// cannot point the gate at an arbitrary https host (browserid-ng W6-4
/// class, I31). Warrants stay signer-chosen (their authority IS the host).
#[tokio::test]
async fn status_fetch_requires_uri_host_to_equal_the_authority() {
    let (addr, observed) = connection_observer(Duration::from_secs(3)).await;
    let checker = StatusChecker::new();
    // Authority is `idp.test`; the URI host is something else entirely.
    let refs = vec![("access cert", StatusRef { uri: format!("https://{addr}/list"), idx: 1 }, "idp.test".to_string())];
    let err = checker.check_all(&refs, &authority_keys("idp.test")).await.unwrap_err();
    assert!(err.contains("authority") || err.contains("host"), "{err}");
    assert!(!observed.await.unwrap(), "fetched a list from a host that is not the authority");
}

/// Passes today: the authority must hold DNSSEC-proven evidence before any
/// fetch; an unknown authority fails closed with no connection.
#[tokio::test]
async fn status_fetch_without_authority_evidence_never_connects() {
    let (addr, observed) = connection_observer(Duration::from_millis(500)).await;
    let checker = StatusChecker::new();
    let refs = vec![("warrant", StatusRef { uri: format!("https://{addr}/list"), idx: 1 }, "idp.test".to_string())];
    let err = checker.check_all(&refs, &HashMap::new()).await.unwrap_err();
    assert!(err.contains("no on-chain DNSSEC evidence"), "{err}");
    assert!(!observed.await.unwrap());
}

// ---------------------------------------------------------------------------
// W5-5 (WS1 D50): snapshot fetch follows redirects; gzip inflates uncapped
// ---------------------------------------------------------------------------

async fn serve(router: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// AUDIT-2026-11 W5-5: `bootstrap::fetch_snapshot` uses a no-redirect client
/// (plus an address guard and a body cap): a serving node cannot bounce the
/// bootstrapper to another host. Operator-chosen `node_url`, so Medium not
/// High (I31).
#[tokio::test]
async fn snapshot_fetch_refuses_redirects() {
    use axum::routing::get;
    let empty = gzip(br#"{"objects":[],"policy_versions":[]}"#);
    let target = serve(axum::Router::new().route(
        "/v1/snapshot",
        get(move || {
            let b = empty.clone();
            async move { b }
        }),
    ))
    .await;
    let bouncer = serve(axum::Router::new().route(
        "/v1/snapshot",
        get(move || async move {
            axum::response::Redirect::temporary(&format!("http://{target}/v1/snapshot?block=1"))
        }),
    ))
    .await;
    let res = sbo_daemon::bootstrap::fetch_snapshot(&format!("http://{bouncer}"), 1).await;
    assert!(res.is_err(), "fetch_snapshot followed a redirect to another host");
}

/// Passes today: a well-formed snapshot round-trips (the control for the
/// bomb test below).
#[tokio::test]
async fn snapshot_decode_accepts_a_small_payload() {
    let gz = gzip(br#"{"objects":[],"policy_versions":[]}"#);
    let p = sbo_daemon::snapshot::decode_snapshot_payload(&gz).unwrap();
    assert!(p.objects.is_empty());
}

/// AUDIT-2026-11 W5-5: `decode_snapshot_payload` inflates through a capped
/// reader (`MAX_SNAPSHOT_BYTES`, buffer sized once): a ~260 KiB body that
/// claims 256 MiB is refused without being materialized. Reachable from any
/// serving node during bootstrap and from local snapshot files (I36).
#[test]
fn snapshot_decode_rejects_a_gzip_bomb_without_inflating_it() {
    const BOMB: usize = 256 * 1024 * 1024;
    let gz = gzip(&vec![0u8; BOMB]);
    assert!(gz.len() < 1024 * 1024, "bomb compressed to {} bytes", gz.len());
    reset_peak();
    let before = PEAK.load(Ordering::Relaxed);
    let res = sbo_daemon::snapshot::decode_snapshot_payload(&gz);
    let peak = PEAK.load(Ordering::Relaxed) - before;
    assert!(res.is_err());
    assert!(peak < 64 * 1024 * 1024, "decoder allocated {} MiB for a {} KiB body", peak >> 20, gz.len() >> 10);
}

// ---------------------------------------------------------------------------
// W5-8 (WS1 D20): IPC socket permissions
// ---------------------------------------------------------------------------

/// AUDIT-2026-11 W5-8 (Q22 a): the IPC socket is `0600` right after the bind
/// (it used to inherit the process umask, typically `0755`, letting any local
/// user issue every command: `RepoAdd` to any directory, `RepoRemove` of the
/// repo state, `SubmitIdentity`; I34).
#[tokio::test]
async fn ipc_socket_is_created_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let server = sbo_daemon::ipc::IpcServer::new(sock.clone());
    let h = tokio::spawn(async move {
        let _ = server
            .run(|_req| async { sbo_daemon::ipc::Response::error("unused") })
            .await;
    });
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    h.abort();
    assert_eq!(mode, 0o600, "socket mode is {mode:o}");
}

/// Passes today: the IPC framing is one JSON object per line; a line that is
/// not a request gets an error reply and the connection stays usable, so a
/// malformed first line cannot wedge the server.
#[tokio::test]
async fn ipc_malformed_line_is_answered_and_the_connection_survives() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let server = sbo_daemon::ipc::IpcServer::new(sock.clone());
    let h = tokio::spawn(async move {
        let _ = server
            .run(|_req| async { sbo_daemon::ipc::Response::ok(serde_json::json!({"ok": true})) })
            .await;
    });
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    w.write_all(b"not json\n").await.unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    assert!(line.contains("Invalid request"), "{line}");
    line.clear();
    w.write_all(b"{\"cmd\":\"Status\"}\n").await.unwrap();
    r.read_line(&mut line).await.unwrap();
    assert!(line.contains("\"ok\":true"), "{line}");
    h.abort();
}

// ---------------------------------------------------------------------------
// W5-9: `/v1/submit` captures evidence for issuers named by UNVERIFIED claims
// ---------------------------------------------------------------------------

/// Passes today and pins the shape of W5-9: `evidence::required_issuers` is
/// computed from the presentation's bare claims, before any signature in the
/// bundle is checked (`main.rs::submit` calls `build_refreshes` BEFORE
/// `validate_message`). A presentation whose signatures are garbage still
/// names issuers, so an unauthenticated POST drives one live DNSSEC capture
/// per invented issuer through the node's resolver (I2 / I31 class).
#[test]
fn required_issuers_are_read_from_unverified_presentation_claims() {
    use sbo_core::browserid_core::device::{AccessCert, DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
    use sbo_core::browserid_core::Assertion;
    use chrono::Duration as CDur;

    let idp_a = KeyPair::generate();
    let idp_b = KeyPair::generate();
    let access_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let access = AccessCert::create(
        "attacker-named-a.test", "agent@a.test", Holder::new("ag.k1").unwrap(), &access_kp.public_key(),
        CDur::hours(1), &idp_a, None,
    )
    .unwrap();
    let config = DeviceCert::create(
        "attacker-named-b.test", &config_kp.public_key(), Purpose::Authorization, Holder::new("br.1").unwrap(),
        vec!["user@b.test".to_string()], CDur::days(90), &idp_b, None,
    )
    .unwrap();
    let warrant = Warrant::create(
        "user@b.test", "agent@a.test", HolderMatcher::new("ag.k1").unwrap(),
        "sbo+raw://avail:turing:1/", vec!["action:post".into()], CDur::days(30), &config_kp, None,
    )
    .unwrap();
    let assertion = Assertion::create("sbo+raw://avail:turing:1/", CDur::minutes(5), &access_kp).unwrap();
    let pres = format!("{}~{}~{}~{}", access.encoded(), assertion.encoded(), warrant.encoded(), config.encoded());

    // Envelope signed by an unrelated key: the attribution would FAIL
    // validation (envelope key != access-key), yet the issuers are produced.
    let key = sbo_core::crypto::SigningKey::generate();
    let mut msg = sbo_core::message::Message {
        action: sbo_core::message::Action::Post,
        path: sbo_core::message::Path::parse("/x/").unwrap(),
        id: sbo_core::message::Id::new("y").unwrap(),
        object_type: sbo_core::message::ObjectType::Object,
        signing_key: key.public_key(),
        signature: sbo_core::crypto::Signature([0u8; 64]),
        content_type: None,
        content_hash: None,
        payload: None,
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: Some(pres),
        auth_evidence: None,
        auth_warrant: None, extra_headers: Vec::new(),
    };
    msg.sign(&key);
    let issuers = sbo_daemon::evidence::required_issuers(&msg);
    assert_eq!(issuers, vec!["attacker-named-a.test", "attacker-named-b.test"]);
}

/// AUDIT-2026-11 W5-9: the submit path now takes its issuers from
/// `evidence::capture_issuers`, which refuses the same bundle (the envelope
/// key is not the access-key) before any capture could run. A
/// self-consistent bundle (envelope signed by the access key, assertion over
/// the warrant's audience, warrant signed by the config key, grantee ==
/// access identity) yields exactly its two issuers, never more than
/// `MAX_ISSUERS_PER_SUBMIT`.
#[test]
fn w5_9_inconsistent_presentation_names_no_issuers_for_capture() {
    use sbo_core::browserid_core::device::{AccessCert, DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
    use sbo_core::browserid_core::Assertion;
    use chrono::Duration as CDur;

    let idp_a = KeyPair::generate();
    let idp_b = KeyPair::generate();
    let access_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let access = AccessCert::create(
        "a.test", "agent@a.test", Holder::new("ag.k1").unwrap(), &access_kp.public_key(),
        CDur::hours(1), &idp_a, None,
    )
    .unwrap();
    let config = DeviceCert::create(
        "b.test", &config_kp.public_key(), Purpose::Authorization, Holder::new("br.1").unwrap(),
        vec!["user@b.test".to_string()], CDur::days(90), &idp_b, None,
    )
    .unwrap();
    let warrant = Warrant::create(
        "user@b.test", "agent@a.test", HolderMatcher::new("ag.k1").unwrap(),
        "sbo+raw://avail:turing:1/", vec!["action:post".into()], CDur::days(30), &config_kp, None,
    )
    .unwrap();
    let assertion = Assertion::create("sbo+raw://avail:turing:1/", CDur::minutes(5), &access_kp).unwrap();
    let pres = format!("{}~{}~{}~{}", access.encoded(), assertion.encoded(), warrant.encoded(), config.encoded());

    let mk = |signer: &sbo_core::crypto::SigningKey, cert: Option<String>| {
        let mut msg = sbo_core::message::Message {
            action: sbo_core::message::Action::Post,
            path: sbo_core::message::Path::parse("/x/").unwrap(),
            id: sbo_core::message::Id::new("y").unwrap(),
            object_type: sbo_core::message::ObjectType::Object,
            signing_key: signer.public_key(),
            signature: sbo_core::crypto::Signature([0u8; 64]),
            content_type: None,
            content_hash: None,
            payload: None,
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: None,
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: cert,
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(signer);
        msg
    };

    // Envelope signed by an unrelated key: refused, no issuers to capture.
    let unrelated = sbo_core::crypto::SigningKey::generate();
    let err = sbo_daemon::evidence::capture_issuers(&mk(&unrelated, Some(pres.clone()))).unwrap_err();
    assert!(err.contains("access-key"), "{err}");

    // Envelope signed by the access key, but the assertion names another
    // audience than the warrant: refused.
    let access_sk = sbo_core::crypto::SigningKey::from_bytes(access_kp.secret_bytes());
    let other_assertion = Assertion::create("sbo+raw://avail:turing:2/", CDur::minutes(5), &access_kp).unwrap();
    let bad_aud = format!("{}~{}~{}~{}", access.encoded(), other_assertion.encoded(), warrant.encoded(), config.encoded());
    let err = sbo_daemon::evidence::capture_issuers(&mk(&access_sk, Some(bad_aud))).unwrap_err();
    assert!(err.contains("audience"), "{err}");

    // Self-consistent: exactly the two issuers, within the cap.
    let issuers = sbo_daemon::evidence::capture_issuers(&mk(&access_sk, Some(pres))).unwrap();
    assert_eq!(issuers, vec!["a.test", "b.test"]);
    assert!(issuers.len() <= sbo_daemon::evidence::MAX_ISSUERS_PER_SUBMIT);

    // A key-rooted write (no presentation) needs no capture at all.
    assert!(sbo_daemon::evidence::capture_issuers(&mk(&unrelated, None)).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// W5-10 (WS1 D37): the auth popup — removed (Q31)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PopupState;
#[async_trait::async_trait]
impl RepoApi for PopupState {
    fn get_object(&self, _: Option<&str>, _: &str, _: &str, _: bool) -> Result<ObjectView, ApiError> {
        Err(ApiError::not_found("n/a"))
    }
    fn get_object_raw(&self, _: Option<&str>, _: &str, _: &str) -> Result<Option<Vec<u8>>, ApiError> {
        Ok(None)
    }
    fn list_objects(&self, _: Option<&str>, _: &ListSelector) -> Result<Vec<ObjectView>, ApiError> {
        Ok(vec![])
    }
    fn state_root(&self, _: Option<&str>) -> Result<StateRootView, ApiError> {
        Err(ApiError::not_found("n/a"))
    }
    async fn submit(&self, _: Option<&str>, _: Vec<u8>) -> Result<SubmitResultView, ApiError> {
        Err(ApiError::bad_request("n/a"))
    }
}

async fn popup(state: Arc<RwLock<PopupState>>, origin: &str) -> (StatusCode, String) {
    let uri = format!("/auth?origin={}&challenge=c", urlencoding(origin));
    let resp = create_router(state)
        .oneshot(Request::builder().method(Method::GET).uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// AUDIT-2026-11 W5-10, decided Q31 (a): the popup flow is removed, so an
/// unauthenticated `GET /auth` creates nothing — it is a 404 and the daemon
/// holds no sign-request table at all (`SignRequest` storage is gone from
/// `DaemonState`). Retargeted from "pending requests are bounded" to "the
/// route does not exist".
#[tokio::test]
async fn auth_popup_pending_requests_are_bounded() {
    let state = Arc::new(RwLock::new(PopupState));
    for _ in 0..1000 {
        let (status, body) = popup(state.clone(), "https://a.test").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("REQUEST_ID"), "popup page was served");
    }
    // The companion routes are gone too.
    for (m, uri) in [(Method::POST, "/auth/request"), (Method::GET, "/auth/status/deadbeefdeadbeef")] {
        let resp = create_router(state.clone())
            .oneshot(Request::builder().method(m.clone()).uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{m} {uri}");
    }
}
