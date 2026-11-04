//! Security audit 2026-11, WS8 — PoC for W5-1 (D38, High): a page on a foreign
//! web origin can `POST /v1/submit` to a daemon bound on `0.0.0.0`, and the
//! request reaches `submit()` and is answered. Combined with `*` CORS and the
//! Private-Network header, any site a user visits can spend the node's TurboDA
//! credit for a write the repo admits.
//!
//! In-process: axum router from `create_router`, a mock `RepoApi` that records
//! whether `submit()` ran and never touches the network, a counter instead of
//! a DA submitter. No production host, no Avail, fake bytes. `#[ignore]`d; run:
//! `cargo test -p sbo-daemon --test audit_2026_11_poc_http -- --ignored`.
//! Backs `docs/security-audit-2026-11-ws8-pocs.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
#[allow(unused_imports)]
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;

use sbo_daemon::http::{
    create_router, ApiError, ListSelector, ObjectView, RepoApi, SignRequestStore, StateRootView,
    SubmitResultView,
};
use sbo_daemon::ipc::SignRequest;

/// A mock node that counts how many times `submit()` is invoked and what bytes
/// it was handed — standing in for the TurboDA spend, which we never perform.
#[derive(Default)]
struct SpendCounter {
    submits: AtomicUsize,
    last_len: AtomicUsize,
    requests: HashMap<String, SignRequest>,
}

impl SignRequestStore for SpendCounter {
    fn create_sign_request(&mut self, request: SignRequest) -> String {
        let id = request.request_id.clone();
        self.requests.insert(id.clone(), request);
        id
    }
    fn get_sign_request(&self, request_id: &str) -> Option<&SignRequest> {
        self.requests.get(request_id)
    }
}

#[async_trait::async_trait]
impl RepoApi for SpendCounter {
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
    async fn submit(&self, _: Option<&str>, data: Vec<u8>) -> Result<SubmitResultView, ApiError> {
        // This is the point past which the node would validate, stage and pay
        // TurboDA. We only count it.
        self.submits.fetch_add(1, Ordering::SeqCst);
        self.last_len.store(data.len(), Ordering::SeqCst);
        Ok(SubmitResultView {
            submission_id: String::new(),
            accepted: true,
            pending: true,
            hash: "poc".into(),
            evidence_refreshed: vec![],
        })
    }
}

/// The CORS preflight for a cross-origin `POST /v1/submit` succeeds for an
/// arbitrary foreign origin, and the Private-Network header is present — the
/// browser will therefore allow the real POST from a public page to this
/// loopback/0.0.0.0 node.
#[tokio::test]
#[ignore] // AUDIT-2026-11 W5-1 PoC: cross-origin preflight is allowed today
async fn poc_w5_1_cross_origin_preflight_is_allowed() {
    let state = Arc::new(RwLock::new(SpendCounter::default()));
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/v1/submit")
                .header("origin", "https://evil.example")
                .header("access-control-request-method", "POST")
                .header("access-control-request-private-network", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT,
        "PoC FAILED TO REPRODUCE — preflight was not allowed: {}",
        resp.status(),
    );
    let acao = resp.headers().get("access-control-allow-origin");
    assert!(acao.is_some(), "no Access-Control-Allow-Origin on the preflight");
    assert!(
        resp.headers().get("access-control-allow-private-network").is_some(),
        "PoC: the Private-Network header is what lets a public page reach a loopback node",
    );
}

/// The real cross-origin POST reaches `submit()`: the request a foreign page
/// makes is served, so the node would spend its TurboDA credit on it.
#[tokio::test]
#[ignore] // AUDIT-2026-11 W5-1 PoC: a foreign-origin submit reaches the spend path today
async fn poc_w5_1_foreign_origin_submit_reaches_the_spend_path() {
    let state = Arc::new(RwLock::new(SpendCounter::default()));
    let router = create_router(state.clone());

    let body = b"SBO-Version: 0.5\n".to_vec();
    let resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/submit")
                .header("origin", "https://evil.example")
                .header("content-type", "application/octet-stream")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    // The handler ran (our mock returns 200 from submit()).
    assert_eq!(resp.status(), StatusCode::OK, "cross-origin POST was not served");
    let count = state.read().await.submits.load(Ordering::SeqCst);
    assert_eq!(
        count, 1,
        "PoC FAILED TO REPRODUCE — submit() was not reached by the foreign-origin POST",
    );
    assert_eq!(state.read().await.last_len.load(Ordering::SeqCst), body.len());
}
