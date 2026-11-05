//! AUDIT-2026-11 WS5 — durable authorization matrix for the daemon's HTTP
//! surface: route × principal → expected status / headers.
//!
//! Expectations are written against the **public exposure mode** decided in
//! `docs/security-audit-2026-11-decisions.md` Q15 (the deployed daemon at
//! da.sandmill.org binds `0.0.0.0:5000` behind dokku nginx):
//!
//! - reads (`/v1/object`, `/v1/list`, `/v1/state-root`, `/v1/sync-points`,
//!   `/v1/snapshot`, `/health`) stay open to every principal;
//! - `/v1/submit` spends the node's TurboDA credit / resolver budget and is
//!   admitted only for an operator-allowlisted browser origin or bearer;
//! - `/v1/dnssec` and the `/auth*` popup routes no longer exist (Q30, Q31);
//! - CORS reflects only allowlisted origins (never `*`), and the
//!   `Access-Control-Allow-Private-Network` header is not set in public mode;
//! - every route answers 429 under a per-source flood.
//!
//! Loopback mode (the localhost convenience server) keeps the pre-audit
//! behaviour; the `loopback_mode_*` cells pin it. The router is exercised
//! in-process through `tower::ServiceExt::oneshot` against a mock `RepoApi`;
//! no network, no production host, no real keys.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tokio::sync::RwLock;
use tower::ServiceExt;

use sbo_daemon::http::{
    create_router, create_router_with, ApiError, HttpOptions, ListSelector, ObjectView, RepoApi,
    StateRootView, SubmitResultView, SyncPointsView,
};

// ---------------------------------------------------------------------------
// Mock state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    gated: bool,
    submits: std::sync::Mutex<usize>,
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

const ALLOWED: &str = "https://mingo.place";
const FOREIGN: &str = "https://evil.example";
const BEARER: &str = "operator-token";

/// Public mode as the deployed daemon would configure it: one allowlisted
/// origin and one bearer.
fn public_options() -> HttpOptions {
    HttpOptions::public(vec![ALLOWED.to_string()], vec![BEARER.to_string()])
}

fn router_with(state: MockState) -> axum::Router {
    create_router_with(Arc::new(RwLock::new(state)), public_options())
}

/// Public-mode router (the matrix default).
fn router() -> axum::Router {
    router_with(MockState::default())
}

/// Loopback-mode router (pre-audit behaviour, pinned).
fn loopback_router() -> axum::Router {
    create_router(Arc::new(RwLock::new(MockState::default())))
}

/// Principals of the matrix. The daemon has no sessions or cookies; a caller
/// is distinguished only by the browser `Origin` it carries (or none) and by
/// an `Authorization: Bearer` it presents.
#[derive(Clone, Copy, Debug)]
enum Principal {
    /// Non-browser client, no `Origin` header (curl, the CLI, a proxy).
    Anonymous,
    /// A web page on an origin the operator did NOT allowlist.
    ForeignOrigin,
    /// A web page on the operator's allowlisted origin (Q15: e.g. mingo.place).
    AllowedOrigin,
    /// Non-browser client presenting the operator's bearer token.
    Bearer,
}

fn req(method: Method, uri: &str, who: Principal, body: Body) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    match who {
        Principal::Anonymous => {}
        Principal::ForeignOrigin => b = b.header(header::ORIGIN, FOREIGN),
        Principal::AllowedOrigin => b = b.header(header::ORIGIN, ALLOWED),
        Principal::Bearer => b = b.header(header::AUTHORIZATION, format!("Bearer {BEARER}")),
    }
    b.body(body).unwrap()
}

async fn send(router: axum::Router, r: Request<Body>) -> axum::response::Response {
    router.oneshot(r).await.unwrap()
}

const SUBMIT_BODY: &[u8] = b"SBO-Version: 0.5\nAction: post\n\n";

// ---------------------------------------------------------------------------
// Matrix: reads are open to everyone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reads_are_open_to_every_principal() {
    for who in [Principal::Anonymous, Principal::ForeignOrigin, Principal::AllowedOrigin, Principal::Bearer] {
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

/// Q31 (W5-10 / D37): the `/auth` popup flow is gone in both modes.
#[tokio::test]
async fn auth_popup_routes_are_gone() {
    for r in [router(), loopback_router()] {
        for (m, uri) in [
            (Method::GET, "/auth?origin=https://a.test&challenge=c"),
            (Method::POST, "/auth/request"),
            (Method::GET, "/auth/status/0000000000000000"),
        ] {
            let resp = send(r.clone(), req(m.clone(), uri, Principal::Anonymous, Body::empty())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{m} {uri}");
        }
    }
}

/// Q30 (W5-2 / D19): `/v1/dnssec` is gone in both modes; submit refreshes
/// issuer evidence itself.
#[tokio::test]
async fn dnssec_route_is_gone() {
    for r in [router(), loopback_router()] {
        let resp = send(r, req(Method::GET, "/v1/dnssec?domain=a.test&needed_by=1", Principal::AllowedOrigin, Body::empty())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

// ---------------------------------------------------------------------------
// Matrix: the fast-sync read gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gated_reads_answer_503_on_object_list_and_state_root() {
    for uri in ["/v1/object?path=/x/&id=y", "/v1/list?prefix=/", "/v1/state-root"] {
        let resp = send(
            router_with(MockState { gated: true, ..Default::default() }),
            req(Method::GET, uri, Principal::Anonymous, Body::empty()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "GET {uri}");
    }
}

/// AUDIT-2026-11 W5-6: `/v1/sync-points` and `/v1/snapshot` consult
/// `check_read_gate`, so a node whose fast-sync anchor is still unverified
/// never serves a manifest or snapshots derived from that unverified state.
#[tokio::test]
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

/// AUDIT-2026-11 W5-7: `/v1/submit` consults the read gate: while the anchor
/// is unverified the node must not validate a write against a provisional
/// state, stage it and pay TurboDA for it. Checked in both modes, and it
/// never reaches `submit()`.
#[tokio::test]
async fn gated_submit_is_refused() {
    for public in [true, false] {
        let state = Arc::new(RwLock::new(MockState { gated: true, ..Default::default() }));
        let r = if public {
            create_router_with(state.clone(), public_options())
        } else {
            create_router(state.clone())
        };
        let resp = send(r, req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "public={public}");
        assert_eq!(*state.read().await.submits.lock().unwrap(), 0, "public={public}");
    }
}

// ---------------------------------------------------------------------------
// Matrix: the spend endpoint (`/v1/submit`) — Q15 public mode
// ---------------------------------------------------------------------------

/// Loopback mode keeps the localhost convenience behaviour: every principal
/// is admitted to `/v1/submit`.
#[tokio::test]
async fn loopback_mode_every_principal_is_admitted_to_submit() {
    for who in [Principal::Anonymous, Principal::ForeignOrigin, Principal::AllowedOrigin, Principal::Bearer] {
        let resp = send(loopback_router(), req(Method::POST, "/v1/submit", who, Body::from(SUBMIT_BODY))).await;
        assert_eq!(resp.status(), StatusCode::OK, "{who:?}");
    }
}

/// AUDIT-2026-11 W5-1: in public mode a page on a non-allowlisted origin
/// cannot spend the node's TurboDA credit (D38, Q15), and `submit()` is
/// never reached.
#[tokio::test]
async fn public_mode_submit_refuses_a_foreign_origin() {
    let state = Arc::new(RwLock::new(MockState::default()));
    let r = create_router_with(state.clone(), public_options());
    let resp = send(r, req(Method::POST, "/v1/submit", Principal::ForeignOrigin, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(*state.read().await.submits.lock().unwrap(), 0);
}

/// AUDIT-2026-11 W5-1: an anonymous caller with no allowlisted origin and no
/// bearer is refused in public mode (Q15: "origin or bearer").
#[tokio::test]
async fn public_mode_submit_refuses_an_anonymous_caller_without_bearer() {
    let state = Arc::new(RwLock::new(MockState::default()));
    let r = create_router_with(state.clone(), public_options());
    let resp = send(r, req(Method::POST, "/v1/submit", Principal::Anonymous, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(*state.read().await.submits.lock().unwrap(), 0);
}

/// The allowlisted origin keeps working in public mode.
#[tokio::test]
async fn public_mode_submit_admits_the_allowlisted_origin() {
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Q15: the bearer is the knob for trusted non-browser clients; a wrong
/// bearer is 401 and never falls through to the origin check.
#[tokio::test]
async fn public_mode_submit_admits_the_bearer_and_refuses_a_wrong_one() {
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::Bearer, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bad = Request::builder()
        .method(Method::POST)
        .uri("/v1/submit")
        .header(header::ORIGIN, ALLOWED)
        .header(header::AUTHORIZATION, "Bearer not-the-token")
        .body(Body::from(SUBMIT_BODY))
        .unwrap();
    let resp = send(router(), bad).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Public mode with an empty allowlist and no bearer refuses everyone — the
/// operator must opt a client in; nothing is admitted by default.
#[tokio::test]
async fn public_mode_with_no_allowlist_refuses_every_submit() {
    let r = create_router_with(
        Arc::new(RwLock::new(MockState::default())),
        HttpOptions::public(vec![], vec![]),
    );
    for who in [Principal::Anonymous, Principal::ForeignOrigin, Principal::AllowedOrigin, Principal::Bearer] {
        let resp = send(r.clone(), req(Method::POST, "/v1/submit", who, Body::from(SUBMIT_BODY))).await;
        assert!(
            matches!(resp.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "{who:?}: {}",
            resp.status()
        );
    }
}

// ---------------------------------------------------------------------------
// Matrix: CORS and Private Network Access headers
// ---------------------------------------------------------------------------

/// Loopback mode: `*` is reflected to every origin on every route, and the
/// PNA header is on every response (the localhost convenience server).
#[tokio::test]
async fn loopback_mode_cors_is_star_and_private_network_header_is_always_set() {
    let resp = send(loopback_router(), req(Method::GET, "/v1/state-root", Principal::ForeignOrigin, Body::empty())).await;
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
    let resp = send(loopback_router(), pre).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
}

/// AUDIT-2026-11 W5-1: public mode reflects only the configured allowlist; a
/// foreign origin gets no `Access-Control-Allow-Origin` at all.
#[tokio::test]
async fn public_mode_cors_does_not_reflect_a_foreign_origin() {
    let resp = send(router(), req(Method::GET, "/v1/state-root", Principal::ForeignOrigin, Body::empty())).await;
    assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    let resp = send(router(), req(Method::GET, "/v1/state-root", Principal::AllowedOrigin, Body::empty())).await;
    assert_eq!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), ALLOWED);
}

/// Public mode: the preflight for a cross-origin POST names only the
/// allowlisted origin and never advertises the private-network header.
#[tokio::test]
async fn public_mode_preflight_reflects_only_the_allowlist() {
    let pre = |origin: &str| {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/v1/submit")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .header("access-control-request-private-network", "true")
            .body(Body::empty())
            .unwrap()
    };
    let resp = send(router(), pre(ALLOWED)).await;
    assert_eq!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), ALLOWED);
    assert!(resp.headers().get("access-control-allow-private-network").is_none());
    let resp = send(router(), pre(FOREIGN)).await;
    assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert!(resp.headers().get("access-control-allow-private-network").is_none());
}

/// AUDIT-2026-11 W5-1: `Access-Control-Allow-Private-Network` exists so a
/// public page may reach a *loopback* daemon; a publicly bound daemon does
/// not send it.
#[tokio::test]
async fn public_mode_does_not_set_private_network_header() {
    for uri in ["/health", "/v1/state-root"] {
        let resp = send(router(), req(Method::GET, uri, Principal::AllowedOrigin, Body::empty())).await;
        assert!(resp.headers().get("access-control-allow-private-network").is_none(), "{uri}");
    }
}

// ---------------------------------------------------------------------------
// Matrix: rate limiting
// ---------------------------------------------------------------------------

/// Loopback mode: no route answers 429 (the localhost convenience server).
#[tokio::test]
async fn loopback_mode_no_route_answers_429_under_a_flood() {
    let r = loopback_router();
    for _ in 0..500 {
        let resp = send(r.clone(), req(Method::POST, "/v1/submit", Principal::Anonymous, Body::from(SUBMIT_BODY))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

/// AUDIT-2026-11 W5-3: public mode rate-limits per source; a flood of 500
/// submits from one source hits 429 (D19, Q15), and the limiter answers
/// BEFORE the origin gate so a refused principal cannot probe for free either.
#[tokio::test]
async fn public_mode_flood_on_submit_hits_429() {
    let state = Arc::new(RwLock::new(MockState::default()));
    let r = create_router_with(state.clone(), public_options());
    let mut saw_429 = false;
    for _ in 0..500 {
        let resp = send(r.clone(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "no 429 after 500 submits from one source");
    let served = *state.read().await.submits.lock().unwrap();
    assert!(served <= 60, "{served} submits reached submit() before the limiter fired");
    // Once the spend bucket is empty, a foreign origin sees 429 too (the
    // limiter is in front of the gate).
    let resp = send(r.clone(), req(Method::POST, "/v1/submit", Principal::ForeignOrigin, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// AUDIT-2026-11 W5-3: reads are limited per source as well (a looser
/// budget than spends); a flood of 2000 state-root reads hits 429, while
/// `/health` is exempt so the platform healthcheck never flaps.
#[tokio::test]
async fn public_mode_flood_on_reads_hits_429_but_health_is_exempt() {
    let r = router();
    let mut saw_429 = false;
    for _ in 0..2000 {
        let resp = send(r.clone(), req(Method::GET, "/v1/state-root", Principal::AllowedOrigin, Body::empty())).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "no 429 after 2000 reads from one source");
    let resp = send(r.clone(), req(Method::GET, "/health", Principal::Anonymous, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Spend and read budgets are independent: exhausting the submit bucket
/// leaves reads from the same source untouched.
#[tokio::test]
async fn public_mode_spend_and_read_budgets_are_independent() {
    let r = router();
    for _ in 0..100 {
        let _ = send(r.clone(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
    }
    let resp = send(r.clone(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(SUBMIT_BODY))).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let resp = send(r.clone(), req(Method::GET, "/v1/state-root", Principal::AllowedOrigin, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Body and input caps
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_body_over_two_mib_is_413() {
    // axum's default `DefaultBodyLimit` (2 MiB) applies to the `Bytes` extractor.
    let big = vec![b'x'; 3 * 1024 * 1024];
    let resp = send(router(), req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::from(big))).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn empty_submit_is_400_and_never_reaches_the_repo() {
    let state = Arc::new(RwLock::new(MockState::default()));
    let r = create_router_with(state.clone(), public_options());
    let resp = send(r, req(Method::POST, "/v1/submit", Principal::AllowedOrigin, Body::empty())).await;
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
