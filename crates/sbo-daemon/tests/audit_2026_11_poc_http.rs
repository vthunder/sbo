//! Security audit 2026-11, WS8 — PoC for W5-1 (D38, High), INVERTED after the
//! fix (sbo-b4cx, Q15): a page on a foreign web origin could `POST /v1/submit`
//! to a daemon bound on `0.0.0.0`, and the request reached `submit()`.
//! Combined with `*` CORS and the Private-Network header, any site a user
//! visited could spend the node's TurboDA credit for a write the repo admits.
//! In public mode the preflight no longer names the foreign origin, the
//! private-network header is never sent, and the POST is refused before
//! `submit()`.
//!
//! In-process: axum router from `create_router_with` in public mode, a mock
//! `RepoApi` that records whether `submit()` ran and never touches the
//! network, a counter instead of a DA submitter. No production host, no
//! Avail, fake bytes. Backs `docs/security-audit-2026-11-ws8-pocs.md`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
#[allow(unused_imports)]
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;

use sbo_daemon::http::{
    create_router_with, ApiError, HttpOptions, ListSelector, ObjectView, RepoApi, StateRootView,
    SubmitResultView,
};

/// A mock node that counts how many times `submit()` is invoked and what bytes
/// it was handed — standing in for the TurboDA spend, which we never perform.
#[derive(Default)]
struct SpendCounter {
    submits: AtomicUsize,
    last_len: AtomicUsize,
}

/// The deployed shape: public mode, mingo.place allowlisted, no bearer.
fn public_router(state: Arc<RwLock<SpendCounter>>) -> axum::Router {
    create_router_with(state, HttpOptions::public(vec!["https://mingo.place".into()], vec![]))
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

/// The CORS preflight for a cross-origin `POST /v1/submit` from a foreign
/// origin is not granted in public mode: no `Access-Control-Allow-Origin`
/// and no Private-Network header, so the browser never sends the real POST.
#[tokio::test]
async fn poc_w5_1_cross_origin_preflight_is_refused() {
    let state = Arc::new(RwLock::new(SpendCounter::default()));
    let resp = public_router(state)
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
        resp.headers().get("access-control-allow-origin").is_none(),
        "the preflight named the foreign origin: {:?}",
        resp.headers().get("access-control-allow-origin")
    );
    assert!(
        resp.headers().get("access-control-allow-private-network").is_none(),
        "the Private-Network header is what let a public page reach a loopback node",
    );
}

/// A cross-origin POST from a foreign origin never reaches `submit()`: the
/// node spends nothing on it.
#[tokio::test]
async fn poc_w5_1_foreign_origin_submit_never_reaches_the_spend_path() {
    let state = Arc::new(RwLock::new(SpendCounter::default()));
    let router = public_router(state.clone());

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

    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cross-origin POST was served");
    let count = state.read().await.submits.load(Ordering::SeqCst);
    assert_eq!(count, 0, "submit() was reached by the foreign-origin POST");
    assert_eq!(state.read().await.last_len.load(Ordering::SeqCst), 0);
}
