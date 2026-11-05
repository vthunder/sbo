//! HTTP server: the daemon's browser-facing read + submit API (`/v1/*`).
//!
//! Two exposure modes (security audit 2026-11, Q15):
//!
//! - **loopback** — the localhost convenience server: CORS reflects any
//!   origin and the `Access-Control-Allow-Private-Network` header is set so a
//!   public page may reach a daemon on `127.0.0.1`. No limits.
//! - **public** — for a daemon bound on a routable address (da.sandmill.org
//!   binds `0.0.0.0:5000`): CORS reflects only the configured origin
//!   allowlist, the private-network header is never sent, every source is
//!   rate-limited, and the spend route (`/v1/submit`) is admitted only for an
//!   allowlisted browser `Origin` or an operator-configured bearer token.
//!
//! The mode is chosen from `[http]` in config (or derived from the bind
//! address); binding a routable address in loopback mode is refused.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::RwLock;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use serde::{Deserialize, Serialize};

/// Shared state for HTTP handlers
pub type HttpState<S> = Arc<RwLock<S>>;

// ===========================================================================
// Phase 7.3 — browser read + submit API (`/v1/*`)
//
// A thin HTTP surface over the daemon's confirmed state and DA submit path, so
// a browser client can read objects/lists, fetch SBOQ proofs, submit signed
// wire bytes, and check freshness — without the Unix-socket IPC. The data
// operations are abstracted behind [`RepoApi`], implemented by the daemon's
// concrete state in `main.rs` (it owns the repo set + the DA client).
// ===========================================================================

/// An error from a `/v1/*` data operation, carrying the HTTP status to return.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::NOT_FOUND, message: msg.into() }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: msg.into() }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message: msg.into() }
    }
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::NOT_IMPLEMENTED, message: msg.into() }
    }
    /// 503 — reads refused while the fast-sync trust anchor is unverified.
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::SERVICE_UNAVAILABLE, message: msg.into() }
    }
    /// 401 — public-mode spend route with no admissible origin or bearer.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::UNAUTHORIZED, message: msg.into() }
    }
    /// 403 — public-mode spend route from a non-allowlisted origin.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::FORBIDDEN, message: msg.into() }
    }
    /// 429 — the per-source limiter refused the request.
    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::TOO_MANY_REQUESTS, message: msg.into() }
    }
}

/// Refuse a state read while the fast-sync trust gate is active.
fn check_read_gate<S: RepoApi>(state: &S) -> Result<(), ApiError> {
    match state.read_gate_reason() {
        Some(reason) => Err(ApiError::unavailable(reason)),
        None => Ok(()),
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

/// A confirmed object rendered for the browser. `value` is the parsed JSON
/// payload when the content is `application/json`; `payload_text` is the raw
/// (lossy-UTF-8) payload, useful for JWT identities/domains. `sboq` is present
/// only when a proof was requested.
#[derive(Debug, Serialize)]
pub struct ObjectView {
    pub path: String,
    pub id: String,
    pub creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_schema: Option<String>,
    pub block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// The object's `Related` header (Wire Format Spec §Related Objects), if it
    /// carried one. Descriptive: `ref` is not resolved and nothing authorizes
    /// on it — it is what the writer declared, signed along with the rest of
    /// the headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<sbo_core::message::Related>>,
    pub object_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    pub payload_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sboq: Option<String>,
    /// `true` for objects served from confirmed (proof-backed) state; `false`
    /// for objects served from the unconfirmed mempool overlay. The UI renders
    /// `false` as a pending affordance that clears on confirmation.
    pub confirmed: bool,
}

/// What a list query selects: objects under a path prefix, or by content schema.
pub enum ListSelector {
    Prefix(String),
    Schema(String),
}

/// Latest `(block, state_root)` for freshness checks.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct StateRootView {
    pub block: u64,
    pub state_root: String,
}

/// Sync-point manifest — what a client needs to pick a fast bootstrap path
/// (State Commitment §Sync-Point Discovery). Every entry is verified, not trusted.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct SyncPointsView {
    pub format: String,
    pub genesis: GenesisView,
    /// Latest confirmed block the serving node has synced.
    pub head: u64,
    /// Latest recorded `(block, state_root)`.
    pub latest_state_root: StateRootView,
    /// Snapshots this node serves (newest first), each verifiable against a checkpoint.
    pub snapshots: Vec<crate::snapshot::SnapshotMeta>,
    /// On-chain checkpoint objects observed under `/sys/checkpoints/`.
    pub checkpoints: Vec<CheckpointView>,
    /// Checkpoint attestations observed under `/u/<attestor>/attestations/checkpoints/`
    /// (State Commitment §Checkpoint Attestations). Advisory discovery only — a
    /// client re-reads/verifies these from attestors it trusts. Absent in older
    /// nodes, so default to empty when deserializing.
    #[serde(default)]
    pub attestations: Vec<AttestationView>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct AttestationView {
    pub block: u64,
    /// Resolved controller of the attestor (the identity a client decides to trust).
    pub attestor: String,
    pub state_root: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct GenesisView {
    pub first_block: Option<u64>,
    pub genesis_hash: Option<String>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct CheckpointView {
    pub id: String,
    pub block: u64,
    pub state_root: String,
    /// The on-chain `checkpoint.v1` object's signed wire bytes (base64), when
    /// the node retained them. A bootstrapping client re-verifies the signature
    /// against its pinned keys; without it this entry is a bare hint and backs
    /// nothing (audit 2026-11 D26).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<String>,
}

/// Result of a successful DA submission. The write was validated against
/// confirmed state, staged in the mempool overlay (so it is visible to all
/// clients within ~1s), and forwarded to the DA layer.
#[derive(Debug, Serialize)]
pub struct SubmitResultView {
    pub submission_id: String,
    /// Always `true` on success — the write was accepted (validated).
    pub accepted: bool,
    /// `true` while the write lives in the overlay (not yet confirmed on-chain).
    pub pending: bool,
    /// Hex `object_hash` of the accepted write; clients can poll for it to flip
    /// to `confirmed: true`.
    pub hash: String,
    /// Issuer domains whose `/sys/dnssec/<domain>` evidence this node refreshed
    /// (and enqueued ahead of the write) because the on-chain copy would not
    /// have covered the write's inclusion. Empty when nothing was needed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refreshed: Vec<String>,
}

/// Data operations the `/v1/*` routes need from the daemon's state. `repo` (the
/// repo's URI or local path) selects which followed repo to serve; when `None`
/// the daemon uses its sole repo (an error if it follows several).
#[async_trait::async_trait]
pub trait RepoApi: Send + Sync + 'static {
    /// Fast-sync trust gate: while a provisional anchor is unverified, state reads
    /// must be refused (the loaded snapshot root is not yet backed by enough
    /// on-chain attestors). Returns a human-readable reason when gated, else
    /// `None`. Default: never gated.
    fn read_gate_reason(&self) -> Option<String> {
        None
    }

    fn get_object(
        &self,
        repo: Option<&str>,
        path: &str,
        id: &str,
        with_proof: bool,
    ) -> Result<ObjectView, ApiError>;

    /// Raw confirmed payload bytes for an object, or `None` if it does not exist.
    /// Unlike [`ObjectView::payload_text`] (lossy UTF-8), this preserves binary
    /// content — required for the DNSSEC proof (`application/octet-stream`).
    fn get_object_raw(
        &self,
        repo: Option<&str>,
        path: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, ApiError>;

    fn list_objects(
        &self,
        repo: Option<&str>,
        selector: &ListSelector,
    ) -> Result<Vec<ObjectView>, ApiError>;

    fn state_root(&self, repo: Option<&str>) -> Result<StateRootView, ApiError>;

    /// Fast-sync manifest (§Sync-Point Discovery). Default: unsupported.
    fn sync_points(&self, _repo: Option<&str>) -> Result<SyncPointsView, ApiError> {
        Err(ApiError::internal("sync-points not supported"))
    }

    /// Metadata for a snapshot at `block` (or the latest if `None`).
    fn snapshot_meta(
        &self,
        _repo: Option<&str>,
        _block: Option<u64>,
    ) -> Result<Option<crate::snapshot::SnapshotMeta>, ApiError> {
        Ok(None)
    }

    /// Compressed snapshot bytes for `block`, or `None` if absent.
    fn snapshot_bytes(
        &self,
        _repo: Option<&str>,
        _block: u64,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        Ok(None)
    }

    /// Validate, stage and enqueue a write for `repo` (`None` = the sole
    /// followed repo). Ensures issuer DNSSEC evidence first (`evidence.rs`).
    async fn submit(&self, repo: Option<&str>, data: Vec<u8>) -> Result<SubmitResultView, ApiError>;
}


// ===========================================================================
// Exposure mode, origin/bearer admission and the per-source limiter (Q15)
// ===========================================================================

/// How the HTTP surface is exposed (`[http] mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpMode {
    /// Localhost convenience server: open CORS, private-network header, no limits.
    Loopback,
    /// Routable bind: origin allowlist, no private-network header, per-source
    /// limits, submit gated on origin or bearer.
    Public,
}

/// Per-source request budgets for public mode (requests per minute, which is
/// also the burst size; refilled continuously).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Reads: `/v1/object`, `/v1/list`, `/v1/state-root`, `/v1/sync-points`, `/v1/snapshot`.
    pub reads_per_minute: u32,
    /// Spends: `/v1/submit` (TurboDA credit + resolver budget).
    pub spends_per_minute: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self { reads_per_minute: 600, spends_per_minute: 60 }
    }
}

/// Everything the router needs to know about its exposure.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub mode: HttpMode,
    /// Browser origins (scheme://host[:port]) that CORS reflects and that
    /// may `POST /v1/submit`. Public mode only.
    pub allowed_origins: Vec<String>,
    /// Bearer tokens that admit a non-browser client to `/v1/submit`
    /// (`Authorization: Bearer <token>`). Public mode only.
    pub bearer_tokens: Vec<String>,
    pub limits: RateLimits,
}

impl HttpOptions {
    pub fn loopback() -> Self {
        Self {
            mode: HttpMode::Loopback,
            allowed_origins: Vec::new(),
            bearer_tokens: Vec::new(),
            limits: RateLimits::default(),
        }
    }

    pub fn public(allowed_origins: Vec<String>, bearer_tokens: Vec<String>) -> Self {
        Self {
            mode: HttpMode::Public,
            allowed_origins,
            bearer_tokens,
            limits: RateLimits::default(),
        }
    }

    /// `true` when `origin` (a request's `Origin` header value) is allowlisted.
    /// Exact, case-insensitive match on the serialized origin.
    fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o.eq_ignore_ascii_case(origin))
    }

    /// `true` when `token` equals a configured bearer (constant-time per candidate).
    fn bearer_allowed(&self, token: &str) -> bool {
        self.bearer_tokens.iter().any(|t| ct_eq(t.as_bytes(), token.as_bytes()))
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Token-bucket limiter keyed on the source address. The key is the
/// **connection** address (`ConnectInfo`), never `X-Forwarded-For`: dokku's
/// nginx overwrites that header with the connection address, so it carries
/// nothing the connection does not, and a direct caller could forge it. A
/// request with no connection info (in-process tests) shares one bucket.
struct Limiter {
    limits: RateLimits,
    buckets: Mutex<HashMap<(IpAddr, bool), Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Idle-bucket sweep threshold: above this many entries, buckets that have
/// been full for a minute are dropped before inserting.
const LIMITER_SWEEP_AT: usize = 10_000;

impl Limiter {
    fn new(limits: RateLimits) -> Self {
        Self { limits, buckets: Mutex::new(HashMap::new()) }
    }

    /// Take one token from `ip`'s bucket for the class; `false` ⇒ 429.
    fn admit(&self, ip: IpAddr, spend: bool) -> bool {
        let per_minute = if spend { self.limits.spends_per_minute } else { self.limits.reads_per_minute };
        if per_minute == 0 {
            return true;
        }
        let capacity = per_minute as f64;
        let rate_per_sec = capacity / 60.0;
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= LIMITER_SWEEP_AT && !buckets.contains_key(&(ip, spend)) {
            buckets.retain(|_, b| now.duration_since(b.last).as_secs() < 60);
        }
        let b = buckets.entry((ip, spend)).or_insert(Bucket { tokens: capacity, last: now });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate_per_sec).min(capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Router-wide context shared by the admission middleware.
struct Guard {
    options: HttpOptions,
    limiter: Limiter,
}

fn source_ip(req: &axum::extract::Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

fn is_spend_route(method: &Method, path: &str) -> bool {
    method == Method::POST && path == "/v1/submit"
}

/// Public-mode admission, in order: per-source limit (429), then for the
/// spend route the origin/bearer gate (403 / 401). Reads are open to every
/// principal but still limited. `/health` is exempt from the limiter so a
/// platform healthcheck never flaps under load.
async fn public_admission(
    State(guard): State<Arc<Guard>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    if path == "/health" || req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let spend = is_spend_route(req.method(), &path);
    if !guard.limiter.admit(source_ip(&req), spend) {
        return ApiError::too_many_requests("rate limit exceeded for this source").into_response();
    }
    if spend {
        if let Err(e) = admit_spend(&guard.options, req.headers()) {
            return e.into_response();
        }
    }
    next.run(req).await
}

/// The Q15 spend gate: a configured bearer admits any client; otherwise a
/// browser `Origin` must be allowlisted (403 when it is not), and a request
/// with no `Origin` at all needs the bearer (401).
fn admit_spend(options: &HttpOptions, headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    if let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if options.bearer_allowed(token.trim()) {
            return Ok(());
        }
        return Err(ApiError::unauthorized("bearer token not recognized"));
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(origin) if options.origin_allowed(origin) => Ok(()),
        Some(_) => Err(ApiError::forbidden("origin is not allowlisted for /v1/submit")),
        None => Err(ApiError::unauthorized(
            "/v1/submit needs an allowlisted Origin or `Authorization: Bearer <token>`",
        )),
    }
}

/// Create the HTTP router in loopback mode (today's localhost behaviour).
pub fn create_router<S: RepoApi>(state: HttpState<S>) -> Router {
    create_router_with(state, HttpOptions::loopback())
}

/// Create the HTTP router for the given exposure options.
pub fn create_router_with<S: RepoApi>(state: HttpState<S>, options: HttpOptions) -> Router {
    let routes = Router::new()
        .route("/health", get(health_check))
        .route("/v1/object", get(get_object_v1::<S>))
        .route("/v1/list", get(list_objects_v1::<S>))
        .route("/v1/submit", post(submit_v1::<S>))
        .route("/v1/state-root", get(state_root_v1::<S>))
        .route("/v1/sync-points", get(sync_points_v1::<S>))
        .route("/v1/snapshot", get(snapshot_v1::<S>))
        .with_state(state);

    match options.mode {
        HttpMode::Loopback => {
            // CORS: a localhost convenience server with no credentialed
            // requests, so reflect any origin — the browser client may be
            // served from any dev origin or the Mingo site.
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::CONTENT_TYPE,
                    HeaderName::from_static("access-control-request-private-network"),
                ])
                .expose_headers([HeaderName::from_static("access-control-allow-private-network")]);

            // Private Network Access header — lets a public page reach a
            // LOOPBACK daemon. Never sent in public mode.
            let private_network = SetResponseHeaderLayer::overriding(
                HeaderName::from_static("access-control-allow-private-network"),
                HeaderValue::from_static("true"),
            );
            // Layer order matters: cors handles OPTIONS, then private_network
            // adds the header to all responses including preflight.
            routes.layer(cors).layer(private_network)
        }
        HttpMode::Public => {
            let origins: Vec<HeaderValue> = options
                .allowed_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok())
                .collect();
            let cors = CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);
            let guard = Arc::new(Guard { limiter: Limiter::new(options.limits), options });
            routes
                .layer(axum::middleware::from_fn_with_state(guard, public_admission))
                .layer(cors)
        }
    }
}
/// Query params for `GET /v1/object`.
#[derive(Debug, Deserialize)]
pub struct ObjectQuery {
    /// The object's prefix path (with trailing slash), e.g. `/communities/cooks/`.
    pub path: String,
    /// The object id, e.g. `community`.
    pub id: String,
    /// Optional repo selector (URI or local path); defaults to the sole repo.
    pub repo: Option<String>,
    /// `1`/`true` to include the SBOQ proof.
    pub proof: Option<String>,
    /// Optional historical-snapshot block (`?as_of=`). Recognized but not yet served —
    /// see [`reject_as_of`].
    pub as_of: Option<String>,
}

/// Historical `as_of` reads need a versioned / retained-trie backend (the state DB
/// currently stores only latest LWW values + state roots for proof freshness, not
/// historical object values). We **recognize** `as_of` and refuse rather than silently
/// returning the latest value (which would be a wrong-but-plausible result). Tracked
/// follow-up: versioned object state. Returns `Ok(())` when no `as_of` is requested.
fn reject_as_of(as_of: Option<&str>) -> Result<(), ApiError> {
    match as_of {
        None => Ok(()),
        Some(_) => Err(ApiError::not_implemented(
            "historical `as_of` reads are not yet supported (requires versioned state); \
             omit `as_of` to read the latest value",
        )),
    }
}

/// `GET /v1/object?path=&id=&repo=&proof=&as_of=` — read one confirmed object.
async fn get_object_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<ObjectQuery>,
) -> Result<Json<ObjectView>, ApiError> {
    reject_as_of(q.as_of.as_deref())?;
    let with_proof = matches!(q.proof.as_deref(), Some("1") | Some("true"));
    let state = state.read().await;
    check_read_gate(&*state)?;
    let view = state.get_object(q.repo.as_deref(), &q.path, &q.id, with_proof)?;
    Ok(Json(view))
}

/// Query params for `GET /v1/list` (exactly one of `prefix`/`schema`).
#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub prefix: Option<String>,
    pub schema: Option<String>,
    pub repo: Option<String>,
    /// Optional historical-snapshot block (`?as_of=`) — recognized but not yet served.
    pub as_of: Option<String>,
}

/// `GET /v1/list?prefix=` or `?schema=` — enumerate confirmed objects.
async fn list_objects_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<ListParams>,
) -> Result<Json<Vec<ObjectView>>, ApiError> {
    reject_as_of(q.as_of.as_deref())?;
    let selector = match (q.prefix, q.schema) {
        (Some(p), None) => ListSelector::Prefix(p),
        (None, Some(s)) => ListSelector::Schema(s),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request("provide exactly one of `prefix` or `schema`"))
        }
        (None, None) => {
            return Err(ApiError::bad_request("`prefix` or `schema` query is required"))
        }
    };
    let state = state.read().await;
    check_read_gate(&*state)?;
    let views = state.list_objects(q.repo.as_deref(), &selector)?;
    Ok(Json(views))
}


/// `POST /v1/submit` — submit raw signed wire bytes to the DA layer. The body
/// is the wire-format envelope(s); the daemon forwards it unchanged. Refused
/// while the fast-sync read gate is active: the write would be validated
/// against a provisional, unverified state (W5-7).
async fn submit_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<StateRootParams>,
    body: Bytes,
) -> Result<Json<SubmitResultView>, ApiError> {
    if body.is_empty() {
        return Err(ApiError::bad_request("empty submit body"));
    }
    let state = state.read().await;
    check_read_gate(&*state)?;
    let result = state.submit(q.repo.as_deref(), body.to_vec()).await?;
    Ok(Json(result))
}
/// Query params for `GET /v1/state-root`.
#[derive(Debug, Deserialize)]
pub struct StateRootParams {
    pub repo: Option<String>,
}

/// `GET /v1/state-root?repo=` — latest `(block, state_root)` for freshness.
async fn state_root_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<StateRootParams>,
) -> Result<Json<StateRootView>, ApiError> {
    let state = state.read().await;
    check_read_gate(&*state)?;
    let view = state.state_root(q.repo.as_deref())?;
    Ok(Json(view))
}

/// `GET /v1/sync-points?repo=` — the fast-sync manifest (§Sync-Point Discovery).
/// Gated like every other state read (W5-6): an unverified anchor must not be
/// advertised as a sync point.
async fn sync_points_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<StateRootParams>,
) -> Result<Json<SyncPointsView>, ApiError> {
    let state = state.read().await;
    check_read_gate(&*state)?;
    Ok(Json(state.sync_points(q.repo.as_deref())?))
}
#[derive(Debug, Deserialize)]
pub struct SnapshotParams {
    /// Block height, or `latest`/absent for the newest snapshot.
    #[serde(default)]
    pub block: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
}


/// `GET /v1/snapshot?block=<n|latest>&repo=` — stream the compressed snapshot at a
/// checkpoint height (the newest if unspecified). Self-verifying: the client
/// rebuilds the trie and matches the root against the checkpoint (§Snapshots).
/// Gated like every other state read (W5-6).
async fn snapshot_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<SnapshotParams>,
) -> axum::response::Response {
    let state = state.read().await;
    if let Err(e) = check_read_gate(&*state) {
        return e.into_response();
    }
    let repo = q.repo.as_deref();
    let block_opt = match q.block.as_deref() {
        None | Some("") | Some("latest") => None,
        Some(s) => match s.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid block").into_response(),
        },
    };
    let meta = match state.snapshot_meta(repo, block_opt) {
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::NOT_FOUND, "no snapshot available").into_response(),
        Err(e) => return e.into_response(),
    };
    let bytes = match state.snapshot_bytes(repo, meta.block) {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::NOT_FOUND, "snapshot file missing").into_response(),
        Err(e) => return e.into_response(),
    };
    let mut resp = axum::response::Response::new(axum::body::Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    let set = |h: &mut axum::http::HeaderMap, name: &'static str, v: &str| {
        if let Ok(val) = HeaderValue::from_str(v) {
            h.insert(HeaderName::from_static(name), val);
        }
    };
    set(h, "x-snapshot-block", &meta.block.to_string());
    set(h, "x-snapshot-state-root", &meta.state_root);
    set(h, "x-snapshot-content-sha256", &meta.content_sha256);
    set(h, "x-snapshot-format", &meta.format);
    resp
}

/// GET /health - Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Start the HTTP server on `bind` with the given exposure options. The
/// listener is served with connection info so the public-mode limiter keys
/// on the peer address.
pub async fn run_server<S: RepoApi>(
    state: HttpState<S>,
    bind: &str,
    options: HttpOptions,
) -> anyhow::Result<()> {
    tracing::info!("HTTP server listening on http://{} ({:?} mode)", bind, options.mode);
    if options.mode == HttpMode::Public {
        if options.allowed_origins.is_empty() && options.bearer_tokens.is_empty() {
            tracing::warn!(
                "HTTP public mode with no allowed_origins and no bearer_tokens: /v1/submit is refused for every caller"
            );
        } else {
            tracing::info!(
                "HTTP public mode: {} allowed origin(s), {} bearer token(s)",
                options.allowed_origins.len(),
                options.bearer_tokens.len()
            );
        }
    }
    let router = create_router_with(state, options);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn reject_as_of_passes_when_absent_refuses_when_present() {
        assert!(reject_as_of(None).is_ok());
        let err = reject_as_of(Some("12345")).unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_IMPLEMENTED);
    }
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `oneshot`

    /// A mock state implementing the trait the router requires, so we can
    /// exercise routing + (de)serialization of the `/v1/*` surface in isolation.
    #[derive(Default)]
    struct MockState;
    fn sample_view() -> ObjectView {
        ObjectView {
            path: "/communities/cooks/".to_string(),
            id: "community".to_string(),
            creator: "sys".to_string(),
            owner_ref: None,
            content_type: "application/json".to_string(),
            content_schema: Some("community.v1".to_string()),
            block: 7,
            hlc: None,
            prev: None,
            related: None,
            object_hash: "00".repeat(32),
            value: Some(serde_json::json!({ "name": "Cooks" })),
            payload_text: "{\"name\":\"Cooks\"}".to_string(),
            sboq: None,
            confirmed: true,
        }
    }

    #[async_trait::async_trait]
    impl RepoApi for MockState {
        fn get_object(
            &self,
            _repo: Option<&str>,
            path: &str,
            id: &str,
            with_proof: bool,
        ) -> Result<ObjectView, ApiError> {
            if id == "missing" {
                return Err(ApiError::not_found("object not found"));
            }
            let mut v = sample_view();
            v.path = path.to_string();
            v.id = id.to_string();
            if with_proof {
                v.sboq = Some("SBOQ/0.2".to_string());
            }
            Ok(v)
        }
        fn get_object_raw(
            &self,
            _repo: Option<&str>,
            _path: &str,
            id: &str,
        ) -> Result<Option<Vec<u8>>, ApiError> {
            if id == "missing" {
                return Ok(None);
            }
            Ok(Some(b"raw-bytes".to_vec()))
        }
        fn list_objects(
            &self,
            _repo: Option<&str>,
            selector: &ListSelector,
        ) -> Result<Vec<ObjectView>, ApiError> {
            match selector {
                ListSelector::Prefix(_) | ListSelector::Schema(_) => Ok(vec![sample_view()]),
            }
        }
        fn state_root(&self, _repo: Option<&str>) -> Result<StateRootView, ApiError> {
            Ok(StateRootView { block: 7, state_root: "ab".repeat(32) })
        }
        async fn submit(&self, _repo: Option<&str>, _data: Vec<u8>) -> Result<SubmitResultView, ApiError> {
            Ok(SubmitResultView {
                submission_id: "sub-123".to_string(),
                accepted: true,
                pending: true,
                evidence_refreshed: Vec::new(),
                hash: "ab".repeat(16),
            })
        }
    }

    fn router() -> Router {
        create_router(Arc::new(RwLock::new(MockState::default())))
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn get_object_returns_view() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/object?path=/communities/cooks/&id=community")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["id"], "community");
        assert_eq!(json["content_schema"], "community.v1");
        assert!(json.get("sboq").is_none(), "no proof unless requested");
    }

    #[tokio::test]
    async fn get_object_with_proof_includes_sboq() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/object?path=/x/&id=y&proof=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["sboq"], "SBOQ/0.2");
    }

    #[tokio::test]
    async fn get_missing_object_is_404() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/object?path=/x/&id=missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_requires_exactly_one_selector() {
        // neither
        let resp = router()
            .oneshot(Request::builder().uri("/v1/list").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // both
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/list?prefix=/communities/&schema=community.v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_by_prefix_returns_array() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/list?prefix=/communities/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn submit_returns_submission_id() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/submit")
                    .body(Body::from(vec![1u8, 2, 3]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["submission_id"], "sub-123");
    }

    #[tokio::test]
    async fn empty_submit_is_400() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/submit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn state_root_returns_block_and_root() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/state-root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["block"], 7);
        assert_eq!(json["state_root"].as_str().unwrap().len(), 64);
    }
}
