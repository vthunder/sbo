//! AUDIT-2026-11 WS5 — durable authorization matrix for the daemon's HTTP
//! surface: route × principal → expected status / headers.
//!
//! Expectations are written against the **public exposure mode** decided in
//! `docs/security-audit-2026-11-decisions.md` Q15 (the deployed daemon at
//! da.sandmill.org binds `0.0.0.0:5000` behind dokku nginx):
//!
//! - reads (`/v1/object`, `/v1/list`, `/v1/state-root`, `/v1/sync-points`,
//!   `/v1/snapshot`, `/health`) stay open to every principal;
//! - `/v1/submit` and `/v1/dnssec` spend the node's TurboDA credit / resolver
//!   budget and are admitted only for an operator-allowlisted browser origin or
//!   bearer;
//! - CORS reflects only allowlisted origins (never `*`), and the
//!   `Access-Control-Allow-Private-Network` header is not set in public mode;
//! - every route answers 429 under a per-source flood.
//!
//! Cells that FAIL today are `#[ignore]`d with an `AUDIT-2026-11 W5-n` comment;
//! un-ignoring a cell is the acceptance test for its fix. Everything else
//! passes today and pins what the audit re-verified. The router is exercised
//! in-process through `tower::ServiceExt::oneshot` against a mock `RepoApi`;
//! no network, no production host, no real keys.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;

use sbo_daemon::http::{
    create_router, ApiError, ListSelector, ObjectView, RepoApi, SignRequestStore, StateRootView,
    SubmitResultView, SyncPointsView,
};
use sbo_daemon::ipc::SignRequest;

// ---------------------------------------------------------------------------
// Mock state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    requests: HashMap<String, SignRequest>,
    gated: bool,
    submits: std::sync::Mutex<usize>,
}

impl SignRequestStore for MockState {
    fn create_sign_request(&mut self, request: SignRequest) -> String {
        let id = request.request_id.clone();
        self.requests.insert(id.clone(), request);
        id
    }
    fn get_sign_request(&self, request_id: &str) -> Option<&SignRequest> {
        self.requests.get(request_id)
    }
}

fn sample_view() -> ObjectView {
    ObjectView {
        path: "/x/".to_string(),
        id: "y".to_string(),
        creator: "sys".to_string(),
        owner_ref: None,
        content_type: "application/json".to_string(),
        content_schema: None,
        block: 1,
        hlc: None,
        prev: None,
        related: None,
        object_hash: "00".repeat(32),
        value: Some(serde_json::json!({})),
        payload_text: "{}".to_string(),
        sboq: None,
        confirmed: true,
    }
}

#[async_trait::async_trait]
impl RepoApi for MockState {
    fn read_gate_reason(&self) -> Option<String> {
        self.gated.then(|| "gated".to_string())
    }
    fn get_object(
        &self,
        _repo: Option<&str>,
        _path: &str,
        _id: &str,
        _with_proof: bool,
    ) -> Result<ObjectView, ApiError> {
        Ok(sample_view())
    }
    fn get_object_raw(
        &self,
        _repo: Option<&str>,
        _path: &str,
        _id: &str,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        // No on-chain proof → `/v1/dnssec` would go to live DNS. The mock keeps
        // the handler from reaching the network by making the capture fail
        // fast: `sbo_capture::DEFAULT_RESOLVER` is only consulted when
        // `needs_refresh` is true, and we never assert on that path's body.
        Ok(None)
    }
    fn list_objects(
        &self,
        _repo: Option<&str>,
        _selector: &ListSelector,
    ) -> Result<Vec<ObjectView>, ApiError> {
        Ok(vec![sample_view()])
    }
    fn state_root(&self, _repo: Option<&str>) -> Result<StateRootView, ApiError> {
        Ok(StateRootView { block: 1, state_root: "ab".repeat(32) })
    }
    fn sync_points(&self, _repo: Option<&str>) -> Result<SyncPointsView, ApiError> {
        Ok(SyncPointsView {
            format: "sync-points/1".into(),
            genesis: sbo_daemon::http::GenesisView { first_block: Some(1), genesis_hash: None },
            head: 1,
            latest_state_root: StateRootView { block: 1, state_root: "ab".repeat(32) },
            snapshots: vec![],
            checkpoints: vec![],
            attestations: vec![],
        })
    }
    async fn submit(&self, _repo: Option<&str>, _data: Vec<u8>) -> Result<SubmitResultView, ApiError> {
        *self.submits.lock().unwrap() += 1;
        Ok(SubmitResultView {
            submission_id: String::new(),
            accepted: true,
            pending: true,
            hash: "ab".repeat(16),
            evidence_refreshed: vec![],
        })
    }
}

fn router_with(state: MockState) -> axum::Router {
    create_router(Arc::new(RwLock::new(state)))
}

fn router() -> axum::Router {
    router_with(MockState::default())
}

/// Principals of the matrix. The daemon has no sessions or cookies; a caller
/// is distinguished only by the browser `Origin` it carries (or none).
#[derive(Clone, Copy, Debug)]
enum Principal {
    /// Non-browser client, no `Origin` header (curl, the CLI, a proxy).
    Anonymous,
    /// A web page on an origin the operator did NOT allowlist.
    ForeignOrigin,
    /// A web page on the operator's allowlisted origin (Q15: e.g. mingo.place).
    AllowedOrigin,
}

const ALLOWED: &str = "https://mingo.place";
const FOREIGN: &str = "https://evil.example";

fn req(method: Method, uri: &str, who: Principal, body: Body) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    match who {
        Principal::Anonymous => {}
        Principal::ForeignOrigin => b = b.header(header::ORIGIN, FOREIGN),
        Principal::AllowedOrigin => b = b.header(header::ORIGIN, ALLOWED),
    }
    b.body(body).unwrap()
}

async fn send(router: axum::Router, r: Request<Body>) -> axum::response::Response {
    router.oneshot(r).await.unwrap()
}

const SUBMIT_BODY: &[u8] = b"SBO-Version: 0.5\nAction: post\n\n";

// ---------------------------------------------------------------------------
// Matrix: reads are open to everyone (passes today)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reads_are_open_to_every_principal() {
    for who in [Principal::Anonymous, Principal::ForeignOrigin, Principal::AllowedOrigin] {
        for uri in [
            "/health",
            "/v1/object?path=/x/&id=y",
            "/v1/list?prefix=/",
            "/v1/state-root",
            "/v1/sync-points",
        ] {
            let resp = send(router(), req(Method::GET, uri, who, Body::empty())).await;
            assert_eq!(resp.status(), StatusCode::OK, "{who:?} GET {uri}");
        }
        // No snapshot on the mock → 404, not 401/403.
        let resp = send(router(), req(Method::GET, "/v1/snapshot", who, Body::empty())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{who:?} GET /v1/snapshot");
    }
}

#[tokio::test]
async fn unknown_route_and_wrong_method_are_404_and_405() {
    let resp = send(router(), req(Method::GET, "/v1/nope", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = send(router(), req(Method::POST, "/v1/object?path=/x/&id=y", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let resp = send(router(), req(Method::GET, "/v1/submit", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn historical_as_of_is_refused_not_served_stale() {
    let resp = send(router(), req(Method::GET, "/v1/object?path=/x/&id=y&as_of=5", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let resp = send(router(), req(Method::GET, "/v1/list?prefix=/&as_of=5", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn unknown_sign_request_is_404_with_no_assertion() {
    let resp = send(router(), req(Method::GET, "/auth/status/0000000000000000", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json.get("assertion_jwt").is_none());
}

// ---------------------------------------------------------------------------
// Matrix: the fast-sync read gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gated_reads_answer_503_on_object_list_state_root_and_dnssec() {
    for uri in ["/v1/object?path=/x/&id=y", "/v1/list?prefix=/", "/v1/state-root", "/v1/dnssec?domain=a.test"] {
        let resp = send(
            router_with(MockState { gated: true, ..Default::default() }),
            req(Method::GET, uri, Principal::Anonymous, Body::empty()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "GET {uri}");
    }
}

/// AUDIT-2026-11 W5-6: fails today. `/v1/sync-points` and `/v1/snapshot` skip
/// `check_read_gate`, so a node whose fast-sync anchor is still unverified
/// serves a manifest and snapshots derived from that unverified state.
#[tokio::test]
#[ignore]
async fn gated_sync_points_and_snapshot_answer_503() {
    for uri in ["/v1/sync-points", "/v1/snapshot"] {
        let resp = send(
            router_with(MockState { gated: true, ..Default::default() }),
            req(Method::GET, uri, Principal::Anonymous, Body::empty()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "GET {uri}");
    }
}

/// AUDIT-2026-11 W5-7: fails today. `/v1/submit` does not consult the read
/// gate: while the anchor is unverified the node validates the write against
/// a provisional (serving-node-asserted) state, stages it in the overlay and
/// pays TurboDA for it.
#[tokio::test]
#[ignore]
async fn gated_submit_is_refused() {
    let resp = send(
        router_with(MockState { gated: true, ..Default::default() }),
        req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Matrix: spend endpoints (`/v1/submit`, `/v1/dnssec`) — Q15 public mode
// ---------------------------------------------------------------------------

/// Pins today's behaviour so the W5-1 cells below are read against it: every
/// principal, including a foreign web origin and an anonymous proxy, is
/// admitted to `/v1/submit`.
#[tokio::test]
async fn today_every_principal_is_admitted_to_submit() {
    for who in [Principal::Anonymous, Principal::ForeignOrigin, Principal::AllowedOrigin] {
        let resp = send(router(), req(Method::POST, "/v1/submit", who, Body::from(SUBMIT_BODY))).await;
        assert_eq!(resp.status(), StatusCode::OK, "{who:?}");
    }
}

/// AUDIT-2026-11 W5-1: fails today. In public mode a page on a non-allowlisted
/// origin must not be able to spend the node's TurboDA credit (D38, Q15).
#[tokio::test]
#[ignore]
async fn public_mode_submit_refuses_a_foreign_origin() {
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::ForeignOrigin, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// AUDIT-2026-11 W5-1: fails today. An anonymous caller with no allowlisted
/// origin and no bearer is refused in public mode (Q15: "origin or bearer").
#[tokio::test]
#[ignore]
async fn public_mode_submit_refuses_an_anonymous_caller_without_bearer() {
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::Anonymous, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The allowlisted origin keeps working in public mode (passes today because
/// nothing is restricted yet; stays the acceptance pin after the fix).
#[tokio::test]
async fn public_mode_submit_admits_the_allowlisted_origin() {
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// AUDIT-2026-11 W5-2: fails today. `/v1/dnssec?domain=<any>` performs a live
/// DNSSEC capture through the node's resolver for any caller and any domain
/// (D19); in public mode it is admitted like `/v1/submit`.
#[tokio::test]
#[ignore]
async fn public_mode_dnssec_capture_refuses_a_foreign_origin() {
    // `needed_by` far in the past so the on-chain window (absent on the mock)
    // is "stale" and the handler would go to the resolver — the point is that
    // it must refuse BEFORE that.
    let resp = send(
        router(),
        req(Method::GET, "/v1/dnssec?domain=a.test&needed_by=1", Principal::ForeignOrigin, Body::empty()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Matrix: CORS and Private Network Access headers
// ---------------------------------------------------------------------------

/// Pins today's behaviour: `*` is reflected to every origin on every route,
/// and the PNA header is on every response.
#[tokio::test]
async fn today_cors_is_star_and_private_network_header_is_always_set() {
    let resp = send(router(), req(Method::GET, "/v1/state-root", Principal::ForeignOrigin, Body::empty())).await;
    assert_eq!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
    assert_eq!(resp.headers().get("access-control-allow-private-network").unwrap(), "true");
    // Preflight for a cross-origin POST succeeds for the foreign origin.
    let pre = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/submit")
        .header(header::ORIGIN, FOREIGN)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .body(Body::empty())
        .unwrap();
    let resp = send(router(), pre).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
}

/// AUDIT-2026-11 W5-1: fails today. Public mode reflects only the configured
/// allowlist; a foreign origin gets no `Access-Control-Allow-Origin` at all.
#[tokio::test]
#[ignore]
async fn public_mode_cors_does_not_reflect_a_foreign_origin() {
    let resp = send(router(), req(Method::GET, "/v1/state-root", Principal::ForeignOrigin, Body::empty())).await;
    assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    let resp = send(router(), req(Method::GET, "/v1/state-root", Principal::AllowedOrigin, Body::empty())).await;
    assert_eq!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), ALLOWED);
}

/// AUDIT-2026-11 W5-1: fails today. `Access-Control-Allow-Private-Network`
/// exists so a public page may reach a *loopback* daemon; a publicly bound
/// daemon must not send it.
#[tokio::test]
#[ignore]
async fn public_mode_does_not_set_private_network_header() {
    let resp = send(router(), req(Method::GET, "/health", Principal::AllowedOrigin, Body::empty())).await;
    assert!(resp.headers().get("access-control-allow-private-network").is_none());
}

// ---------------------------------------------------------------------------
// Matrix: rate limiting
// ---------------------------------------------------------------------------

/// Pins today's behaviour: no route ever answers 429.
#[tokio::test]
async fn today_no_route_answers_429_under_a_flood() {
    let r = router();
    for _ in 0..500 {
        let resp = send(r.clone(), req(Method::POST, "/v1/submit", Principal::Anonymous, Body::from(SUBMIT_BODY))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

/// AUDIT-2026-11 W5-3: fails today. Public mode rate-limits per source; a
/// flood of 500 submits from one source must hit 429 (D19, Q15).
#[tokio::test]
#[ignore]
async fn public_mode_flood_on_submit_hits_429() {
    let r = router();
    let mut saw_429 = false;
    for _ in 0..500 {
        let resp = send(r.clone(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "no 429 after 500 submits from one source");
}

/// AUDIT-2026-11 W5-3: fails today. The live-DNS route is the cheapest
/// amplifier on the surface and must be limited independently of submit.
#[tokio::test]
#[ignore]
async fn public_mode_flood_on_dnssec_hits_429() {
    let r = router();
    let mut saw_429 = false;
    for _ in 0..200 {
        // The mock has no on-chain proof, so an un-limited handler would go to
        // the resolver; the limiter must answer before any capture (the fixed
        // test may stub the capture, the verdict is what matters).
        let resp = send(r.clone(), req(Method::GET, "/v1/dnssec?domain=a.test", Principal::AllowedOrigin, Body::empty())).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "no 429 after 200 dnssec requests from one source");
}

// ---------------------------------------------------------------------------
// Body and input caps (pass today)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_body_over_two_mib_is_413() {
    // axum's default `DefaultBodyLimit` (2 MiB) applies to the `Bytes` extractor.
    let big = vec![b'x'; 3 * 1024 * 1024];
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::Anonymous, Body::from(big))).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn empty_submit_is_400_and_never_reaches_the_repo() {
    let state = Arc::new(RwLock::new(MockState::default()));
    let r = create_router(state.clone());
    let resp = send(r, req(Method::POST, "/v1/submit", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(*state.read().await.submits.lock().unwrap(), 0);
}

#[tokio::test]
async fn snapshot_block_must_be_an_integer_or_latest() {
    let resp = send(router(), req(Method::GET, "/v1/snapshot?block=abc", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = send(router(), req(Method::GET, "/v1/snapshot?block=-1", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
