//! SBO Daemon Binary
//!
//! Manages local SBO repository replicas with data availability verification.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use sbo_daemon::config::Config;
use sbo_daemon::http::{self, SignRequestStore};
use sbo_daemon::ipc::{IpcServer, Request, Response, SignRequestStatus, SignRequest as IpcSignRequest};
use sbo_daemon::lc::LcManager;
use sbo_daemon::prover::Prover;
use sbo_daemon::repo::{RepoManager, SboRawUri};
use sbo_daemon::rpc::RpcClient;
use sbo_daemon::sync::SyncEngine;
use sbo_daemon::turbo::TurboDaClient;

#[derive(Parser)]
#[command(name = "sbo-daemon")]
#[command(about = "SBO daemon for repository sync and data availability verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,

        /// Verbose output for specific components (can be repeated)
        /// Options: rpc, rpc-decode, raw-incoming, blocks
        #[arg(long = "verbose", short = 'v', value_name = "COMPONENT")]
        verbose: Vec<String>,

        /// Debug options (can be repeated)
        /// Options: save-raw-block
        #[arg(long = "debug", short = 'd', value_name = "OPTION")]
        debug: Vec<String>,

        /// Enable prover mode (generate ZK proofs for processed blocks)
        #[arg(long)]
        prover: bool,

        /// Enable light mode (verify proofs instead of executing state transitions)
        #[arg(long)]
        light: bool,
    },
    /// Show daemon status
    Status,
    /// Initialize configuration
    Init,
    /// Fast-sync bootstrap: fetch + verify a snapshot from a serving node and load
    /// it into the repo's state DB, so `start` tails from there instead of replaying
    /// from genesis (State Commitment fast-sync).
    Bootstrap {
        /// Serving node base URL, e.g. https://da.sandmill.org
        #[arg(long)]
        node: String,
        /// State directory to load into (default: the configured repo's state dir).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

/// Verbose logging flags
#[derive(Clone, Default)]
pub struct VerboseFlags {
    /// Log RPC connection details
    pub rpc: bool,
    /// Log RPC decode details (block headers, matrix decoding)
    pub rpc_decode: bool,
    /// Log raw incoming data for repos
    pub raw_incoming: bool,
    /// Log every block processed (even empty ones)
    pub blocks: bool,
}

impl VerboseFlags {
    fn from_args(args: &[String]) -> Self {
        Self {
            rpc: args.iter().any(|s| s == "rpc"),
            rpc_decode: args.iter().any(|s| s == "rpc-decode"),
            raw_incoming: args.iter().any(|s| s == "raw-incoming"),
            blocks: args.iter().any(|s| s == "blocks"),
        }
    }
}

/// Debug flags for development/troubleshooting
#[derive(Clone, Default)]
pub struct DebugFlags {
    /// Save raw block data (header, matrix, lookup) to /tmp/sbo-debug/
    pub save_raw_block: bool,
}

impl DebugFlags {
    fn from_args(args: &[String]) -> Self {
        Self {
            save_raw_block: args.iter().any(|s| s == "save-raw-block"),
        }
    }
}

/// Shared daemon state
struct DaemonState {
    config: Config,
    repos: RepoManager,
    lc: LcManager,
    #[allow(dead_code)]
    rpc: RpcClient,
    turbo: TurboDaClient,
    /// Pending sign requests from apps (keyed by request_id)
    sign_requests: HashMap<String, IpcSignRequest>,
    /// Shared mempool overlay (validated-but-unconfirmed writes). Cloned into the
    /// sync task so confirmed writes reconcile (evict) their shadows.
    pending: SharedPending,
}

impl DaemonState {
    async fn new(config: Config) -> anyhow::Result<Self> {
        // Create directories
        std::fs::create_dir_all(&config.daemon.repos_dir)?;

        // Initialize components
        let repos = RepoManager::load(config.daemon.repos_index.clone())?;

        let lc = LcManager::new(config.light_client.clone());
        let rpc = RpcClient::new(config.rpc.clone(), false, false, false);
        let turbo = TurboDaClient::new(config.turbo_da.clone());

        Ok(Self {
            config,
            repos,
            lc,
            rpc,
            turbo,
            sign_requests: HashMap::new(),
            pending: std::sync::Arc::new(std::sync::RwLock::new(PendingPool::new())),
        })
    }
}

impl SignRequestStore for DaemonState {
    fn create_sign_request(&mut self, request: IpcSignRequest) -> String {
        let id = request.request_id.clone();
        self.sign_requests.insert(id.clone(), request);
        id
    }

    fn get_sign_request(&self, request_id: &str) -> Option<&IpcSignRequest> {
        self.sign_requests.get(request_id)
    }
}

// ===========================================================================
// Phase 7.3 — shared read helpers + the browser RepoApi implementation
// ===========================================================================

use sbo_core::state::{StateDb, StoredObject};
use sbo_daemon::pending::{PendingPool, SharedPending};
use sbo_daemon::http::{
    ApiError, ListSelector, ObjectView, RepoApi, StateRootView, SubmitResultView,
};
use sbo_daemon::repo::Repo;

/// Resolve which followed repo a request targets. `sel` may be a display/canonical
/// URI or the local path; `None` selects the sole repo (error if several).
fn resolve_repo<'a>(repos: &'a RepoManager, sel: Option<&str>) -> Result<&'a Repo, ApiError> {
    match sel {
        Some(s) => repos
            .list()
            .find(|r| {
                r.display_uri == s
                    || r.uri.to_string() == s
                    || r.uri.to_canonical_string() == s
                    || r.path.to_string_lossy() == s
            })
            .ok_or_else(|| ApiError::not_found(format!("no followed repo matching {s}"))),
        None => {
            let mut it = repos.list();
            let first = it
                .next()
                .ok_or_else(|| ApiError::not_found("no repos followed"))?;
            if it.next().is_some() {
                return Err(ApiError::bad_request(
                    "multiple repos followed; specify ?repo=",
                ));
            }
            Ok(first)
        }
    }
}

/// Render a stored object into the browser view, attaching `sboq` if supplied.
fn build_object_view(obj: &StoredObject, sboq: Option<String>, confirmed: bool) -> ObjectView {
    let payload_text = String::from_utf8_lossy(&obj.payload).to_string();
    let value = if obj.content_type == "application/json" {
        serde_json::from_slice::<serde_json::Value>(&obj.payload).ok()
    } else {
        None
    };
    ObjectView {
        path: obj.path.to_string(),
        id: obj.id.as_str().to_string(),
        creator: obj.creator.as_str().to_string(),
        owner_ref: obj.owner_ref.clone(),
        content_type: obj.content_type.clone(),
        content_schema: obj.content_schema.clone(),
        block: obj.block_number,
        hlc: obj.hlc.clone(),
        prev: obj.prev.clone(),
        object_hash: hex::encode(obj.object_hash),
        value,
        payload_text,
        sboq,
        confirmed,
    }
}

/// Build the SBOQ proof text for an object (creator auto-detected), mirroring
/// the IPC `ObjectProof` path. Returns `None` if the object has no trie proof.
fn generate_sboq_text(
    repo: &Repo,
    db: &StateDb,
    path: &sbo_core::message::Path,
    id: &sbo_core::message::Id,
    path_str: &str,
    id_str: &str,
) -> Result<Option<String>, String> {
    match db.generate_trie_proof_auto(path, id) {
        Ok(Some((creator, trie_proof))) => {
            let object_file_path = repo.path.join(path_str.trim_start_matches('/')).join(id_str);
            let object_bytes = std::fs::read(&object_file_path).ok();
            let sboq = sbo_core::proof::SboqMessage {
                version: "0.2".to_string(),
                path: path_str.to_string(),
                id: id_str.to_string(),
                creator: creator.to_string(),
                block: repo.head,
                state_root: trie_proof.state_root,
                object_hash: trie_proof.object_hash,
                trie_proof,
                object: object_bytes,
            };
            Ok(Some(
                String::from_utf8_lossy(&sbo_core::proof::serialize_sboq(&sboq)).to_string(),
            ))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(format!("Failed to generate proof: {e}")),
    }
}

/// Read one object's view from a repo's confirmed state (shared by IPC + HTTP).
fn read_object_view(
    repo: &Repo,
    path_str: &str,
    id_str: &str,
    with_proof: bool,
    pending: &SharedPending,
) -> Result<ObjectView, ApiError> {
    let db = repo
        .state_db()
        .map_err(|e| ApiError::internal(format!("Failed to open state db: {e}")))?;
    let path = sbo_core::message::Path::parse(path_str)
        .map_err(|e| ApiError::bad_request(format!("Invalid path: {e}")))?;
    let id = sbo_core::message::Id::new(id_str)
        .map_err(|e| ApiError::bad_request(format!("Invalid id: {e}")))?;

    let confirmed = db
        .get_first_object_at_path_id(&path, &id)
        .map_err(|e| ApiError::internal(format!("State DB error: {e}")))?;

    // Proof requests only ever serve confirmed objects — the overlay has no
    // proofs. Otherwise merge the mempool overlay over confirmed state (LWW).
    if !with_proof {
        let pool = pending.read().unwrap();
        if let Some(p) = pool.object_at(&path, &id) {
            let wins = match &confirmed {
                Some(c) => sbo_daemon::pending::overlay_wins(p, c),
                None => true,
            };
            if wins {
                return Ok(build_object_view(p, None, false));
            }
        }
    }

    let obj = confirmed
        .ok_or_else(|| ApiError::not_found(format!("object not found: {path_str}{id_str}")))?;

    let sboq = if with_proof {
        generate_sboq_text(repo, &db, &path, &id, path_str, id_str)
            .map_err(ApiError::internal)?
    } else {
        None
    };
    Ok(build_object_view(&obj, sboq, true))
}

/// Raw confirmed+overlay payload bytes for `(path, id)`, or `None` if absent.
/// Preserves binary content (the DNSSEC proof) that `read_object_view` would
/// mangle via lossy UTF-8. Mirrors the overlay-over-confirmed LWW of the
/// no-proof read path.
fn read_object_raw(
    repo: &Repo,
    path_str: &str,
    id_str: &str,
    pending: &SharedPending,
) -> Result<Option<Vec<u8>>, ApiError> {
    let db = repo
        .state_db()
        .map_err(|e| ApiError::internal(format!("Failed to open state db: {e}")))?;
    let path = sbo_core::message::Path::parse(path_str)
        .map_err(|e| ApiError::bad_request(format!("Invalid path: {e}")))?;
    let id = sbo_core::message::Id::new(id_str)
        .map_err(|e| ApiError::bad_request(format!("Invalid id: {e}")))?;

    let confirmed = db
        .get_first_object_at_path_id(&path, &id)
        .map_err(|e| ApiError::internal(format!("State DB error: {e}")))?;

    let pool = pending.read().unwrap();
    if let Some(p) = pool.object_at(&path, &id) {
        let wins = match &confirmed {
            Some(c) => sbo_daemon::pending::overlay_wins(p, c),
            None => true,
        };
        if wins {
            return Ok(Some(p.payload.clone()));
        }
    }
    Ok(confirmed.map(|o| o.payload))
}

/// List object views from a repo's confirmed state, merged with the mempool
/// overlay (shared by IPC + HTTP). Pending objects shadow confirmed ones at the
/// same `(path, id)` when they win LWW; pending-only objects are appended.
fn read_object_list(
    repo: &Repo,
    selector: &ListSelector,
    pending: &SharedPending,
) -> Result<Vec<ObjectView>, ApiError> {
    let db = repo
        .state_db()
        .map_err(|e| ApiError::internal(format!("Failed to open state db: {e}")))?;
    let confirmed = match selector {
        ListSelector::Prefix(p) => db.list_objects_by_path_prefix(p),
        ListSelector::Schema(s) => db.list_objects_by_schema(s),
    }
    .map_err(|e| ApiError::internal(format!("State DB error: {e}")))?;

    let pool = pending.read().unwrap();
    let pend: Vec<&StoredObject> = match selector {
        ListSelector::Prefix(p) => pool.objects_under_prefix(p),
        ListSelector::Schema(s) => pool.objects_by_schema(s),
    };

    // Index pending by (path, id) so confirmed entries can defer to a winning
    // shadow; remaining pending-only entries are appended afterward.
    use std::collections::HashMap;
    let mut pend_by_key: HashMap<(String, String), &StoredObject> = pend
        .into_iter()
        .map(|o| ((o.path.to_string(), o.id.as_str().to_string()), o))
        .collect();

    let mut views = Vec::with_capacity(confirmed.len() + pend_by_key.len());
    for c in &confirmed {
        let key = (c.path.to_string(), c.id.as_str().to_string());
        match pend_by_key.remove(&key) {
            Some(p) if sbo_daemon::pending::overlay_wins(p, c) => {
                views.push(build_object_view(p, None, false));
            }
            _ => views.push(build_object_view(c, None, true)),
        }
    }
    // Pending objects with no confirmed counterpart.
    for p in pend_by_key.values() {
        views.push(build_object_view(p, None, false));
    }
    Ok(views)
}

#[async_trait::async_trait]
impl RepoApi for DaemonState {
    fn get_object(
        &self,
        repo: Option<&str>,
        path: &str,
        id: &str,
        with_proof: bool,
    ) -> Result<ObjectView, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        read_object_view(repo, path, id, with_proof, &self.pending)
    }

    fn get_object_raw(
        &self,
        repo: Option<&str>,
        path: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        read_object_raw(repo, path, id, &self.pending)
    }

    fn list_objects(
        &self,
        repo: Option<&str>,
        selector: &ListSelector,
    ) -> Result<Vec<ObjectView>, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        read_object_list(repo, selector, &self.pending)
    }

    fn state_root(&self, repo: Option<&str>) -> Result<StateRootView, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        let db = repo
            .state_db()
            .map_err(|e| ApiError::internal(format!("Failed to open state db: {e}")))?;
        // State roots are recorded only at blocks where state changed, so report
        // the latest recorded (block, root) — not the latest synced block, which
        // may have had no writes (→ no root stored).
        let (block, root) = db
            .get_latest_state_root()
            .map_err(|e| ApiError::internal(format!("State DB error: {e}")))?
            .unwrap_or((repo.head, [0u8; 32]));
        Ok(StateRootView {
            block,
            state_root: hex::encode(root),
        })
    }

    fn sync_points(&self, repo: Option<&str>) -> Result<sbo_daemon::http::SyncPointsView, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        let dir = self
            .config
            .checkpoint
            .snapshots_dir
            .clone()
            .unwrap_or_else(|| sbo_daemon::repo_dir_for_uri(&repo.uri.to_string()).join("snapshots"));
        let snapshots = sbo_daemon::snapshot::list_snapshot_metas(&dir);
        let db = repo
            .state_db()
            .map_err(|e| ApiError::internal(format!("Failed to open state db: {e}")))?;
        let (block, root) = db
            .get_latest_state_root()
            .map_err(|e| ApiError::internal(format!("State DB error: {e}")))?
            .unwrap_or((repo.head, [0u8; 32]));
        // On-chain checkpoint objects (if any have been published).
        let checkpoints = db
            .list_objects_by_path_prefix("/sys/checkpoints/")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|o| {
                let v: serde_json::Value = serde_json::from_slice(&o.payload).ok()?;
                Some(sbo_daemon::http::CheckpointView {
                    id: o.id.as_str().to_string(),
                    block: v.get("block")?.as_u64()?,
                    state_root: v.get("state_root")?.as_str()?.to_string(),
                })
            })
            .collect();
        // Checkpoint attestations observed on chain (advisory discovery). Each is
        // attributed to its author's resolved controller — the identity a client
        // decides whether to trust.
        let attestations = db
            .list_objects_by_schema("checkpoint-attestation.v1")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|o| {
                let v: serde_json::Value = serde_json::from_slice(&o.payload).ok()?;
                Some(sbo_daemon::http::AttestationView {
                    block: v.get("block")?.as_u64()?,
                    attestor: o.owner.as_str().to_string(),
                    state_root: v.get("state_root")?.as_str()?.to_string(),
                })
            })
            .collect();
        Ok(sbo_daemon::http::SyncPointsView {
            format: "sbo-sync-points/1".to_string(),
            genesis: sbo_daemon::http::GenesisView {
                first_block: repo.uri.first_block,
                genesis_hash: repo.expected_genesis.clone(),
            },
            head: repo.head,
            latest_state_root: StateRootView { block, state_root: hex::encode(root) },
            snapshots,
            checkpoints,
            attestations,
        })
    }

    fn snapshot_meta(
        &self,
        repo: Option<&str>,
        block: Option<u64>,
    ) -> Result<Option<sbo_daemon::snapshot::SnapshotMeta>, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        let dir = self
            .config
            .checkpoint
            .snapshots_dir
            .clone()
            .unwrap_or_else(|| sbo_daemon::repo_dir_for_uri(&repo.uri.to_string()).join("snapshots"));
        let metas = sbo_daemon::snapshot::list_snapshot_metas(&dir);
        Ok(match block {
            Some(b) => metas.into_iter().find(|m| m.block == b),
            None => metas.into_iter().next(),
        })
    }

    fn snapshot_bytes(
        &self,
        repo: Option<&str>,
        block: u64,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let repo = resolve_repo(&self.repos, repo)?;
        let dir = self
            .config
            .checkpoint
            .snapshots_dir
            .clone()
            .unwrap_or_else(|| sbo_daemon::repo_dir_for_uri(&repo.uri.to_string()).join("snapshots"));
        let file = dir.join(sbo_daemon::snapshot::snapshot_file_name(block));
        Ok(std::fs::read(&file).ok())
    }

    async fn submit(&self, data: Vec<u8>) -> Result<SubmitResultView, ApiError> {
        use sbo_daemon::validate::{
            message_to_stored_object, validate_message, L2Context, ValidationResult,
        };

        // Parse the wire envelope(s). A malformed body is a hard 400 — far
        // better UX than today's silent DA-layer filtering.
        let messages = sbo_core::wire::parse_batch(&data)
            .map_err(|e| ApiError::bad_request(format!("wire parse failed: {e}")))?;
        if messages.is_empty() {
            return Err(ApiError::bad_request("no SBO messages in submit body"));
        }

        // Validate against the daemon's sole repo's confirmed state **plus** the
        // mempool's pending tip (Phase B: pending-aware validation via Overlay).
        // Validating against confirmed+pending lets chained optimistic writes
        // (e.g. join → post in one submit) succeed before the earlier write has
        // landed in a block.
        let repo = resolve_repo(&self.repos, None)?;
        let db = repo
            .state_db()
            .map_err(|e| ApiError::internal(format!("Failed to open state db: {e}")))?;
        let now = unix_now();

        // Seed an overlay from the current pending snapshot. As each message in
        // the batch validates, stage its object into the overlay so later
        // messages in the same submit observe it.
        let snapshot = self.pending.read().unwrap().snapshot();
        let mut overlay = sbo_daemon::state_view::Overlay::new(&db, snapshot);

        // Fully validate every message and pre-build its overlay object before
        // mutating the pool, so a rejected message leaves the pool untouched.
        let mut staged: Vec<(StoredObject, [u8; 32])> = Vec::with_capacity(messages.len());
        for msg in &messages {
            let l2 = L2Context::for_block(Some(now), &overlay);
            match validate_message(msg, &overlay, &repo.path, &l2) {
                ValidationResult::Valid { .. } => {}
                ValidationResult::Invalid { stage, reason } => {
                    return Err(ApiError::bad_request(format!("{stage:?}: {reason}")));
                }
            }
            let object_hash = sbo_core::sha256(&sbo_core::wire::serialize(msg));
            // Only content-bearing writes (Post) produce an overlay object;
            // Deletes have no stored object and simply wait for confirmation.
            if let Some(obj) = message_to_stored_object(
                msg,
                repo.head,
                Some(&overlay as &dyn sbo_daemon::state_view::StateView),
                object_hash,
                &l2,
            ) {
                // Make this write visible to the next message in the batch, then
                // record it for pool insertion once the whole batch is accepted.
                overlay.stage(obj.clone());
                staged.push((obj, object_hash));
            }
        }

        // All valid → stage in the overlay (visible to every client within ~1s),
        // then forward the unchanged bytes to the DA layer.
        let last_hash = staged
            .last()
            .map(|(_, h)| hex::encode(h))
            .unwrap_or_default();
        {
            let mut pool = self.pending.write().unwrap();
            for (obj, hash) in staged {
                pool.insert(obj, hash, now);
            }
        }

        let result = self
            .turbo
            .submit_raw(&data)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        Ok(SubmitResultView {
            submission_id: result.submission_id,
            accepted: true,
            pending: true,
            hash: last_hash,
        })
    }
}

/// How far the light client's DAS availability window may lag the finalized
/// head before we treat the LC as stalled and fall back to RPC-only tailing.
/// Healthy sampling lags finality by only a few blocks; a gap this large means
/// the LC has stopped sampling. At ~20s Avail blocks this is ~10 minutes.
const LC_STALL_LAG_BLOCKS: u64 = 30;

/// Current wall-clock time in Unix seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Generate a checkpoint + snapshot at the current confirmed head when the
/// configured dual trigger fires and sync is caught up to the finalized head.
/// Called from the sync task after block processing, so it observes a consistent
/// confirmed state with no concurrent writer (root + objects match exactly).
#[allow(clippy::too_many_arguments)]
async fn checkpoint_if_due(
    state: &Arc<RwLock<DaemonState>>,
    cfg: &sbo_daemon::config::CheckpointConfig,
    latest_block: u64,
    last_checkpoint_block: &mut u64,
    writes_since_checkpoint: &mut u64,
    turbo: &TurboDaClient,
    checkpoint_key: Option<&sbo_core::crypto::SigningKey>,
    prev_checkpoint: &mut Option<String>,
    now: i64,
) {
    if !cfg.enabled {
        return;
    }
    // Single-repo model: the daemon follows one repo.
    let (head, state_db, snap_dir) = {
        let st = state.read().await;
        let Some(repo) = st.repos.list().next() else {
            return;
        };
        let db = match repo.state_db() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("checkpoint: cannot open state db: {e}");
                return;
            }
        };
        let dir = cfg.snapshots_dir.clone().unwrap_or_else(|| {
            sbo_daemon::repo_dir_for_uri(&repo.uri.to_string()).join("snapshots")
        });
        (repo.head, db, dir)
    };

    // Only checkpoint confirmed, near-tip state — never mid-backfill.
    if head == 0 || head + 1 < latest_block {
        return;
    }
    if head <= *last_checkpoint_block {
        return;
    }
    let due = head - *last_checkpoint_block >= cfg.every_blocks
        || *writes_since_checkpoint >= cfg.every_writes;
    if !due {
        return;
    }

    let root = match state_db.compute_trie_state_root() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("checkpoint: state root failed: {e}");
            return;
        }
    };
    let objects = match state_db.list_objects_by_path_prefix("/") {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("checkpoint: list objects failed: {e}");
            return;
        }
    };

    match sbo_daemon::snapshot::write_snapshot(&snap_dir, head, &hex::encode(root), &objects, now) {
        Ok(meta) => {
            tracing::info!(
                "checkpoint @ block {}: snapshot {} objects, {} -> {} bytes (gz), root {}…",
                head,
                meta.object_count,
                meta.uncompressed_bytes,
                meta.compressed_bytes,
                &meta.state_root[..std::cmp::min(16, meta.state_root.len())]
            );
            prune_snapshots(&snap_dir, 3);
            *last_checkpoint_block = head;
            *writes_since_checkpoint = 0;

            // Publish the checkpoint.v1 object on-chain (State Commitment §Checkpoints)
            // so clients can verify snapshots against an authority-signed root, not
            // just the serving node. The committed root is `root` (as of `head`),
            // which excludes this checkpoint object itself (the exclude-self rule).
            if cfg.publish {
                match checkpoint_key {
                    Some(key) => {
                        let wire = build_checkpoint_wire(
                            key,
                            head,
                            &hex::encode(root),
                            prev_checkpoint.as_deref(),
                            now,
                        );
                        match turbo.submit_raw(&wire).await {
                            Ok(_) => {
                                tracing::info!("published checkpoint.v1 for block {head} on-chain");
                                *prev_checkpoint = Some(format!("/sys/checkpoints/block-{head}"));
                            }
                            Err(e) => tracing::error!("checkpoint publish submit failed: {e}"),
                        }
                    }
                    None => tracing::warn!(
                        "checkpoint publish=true but no authority key loaded; on-chain publish skipped"
                    ),
                }
            }
        }
        Err(e) => {
            tracing::error!("checkpoint: snapshot generation failed at block {}: {}", head, e)
        }
    }
}

/// Post `checkpoint-attestation.v1` for any on-chain checkpoint this node has
/// INDEPENDENTLY reached and reproduced (State Commitment §Checkpoint
/// Attestations). Attestations lag the checkpoint: we attest a past height `h`
/// from our own recorded state root at `h`, never a root we did not compute.
async fn attest_if_due(
    state: &Arc<RwLock<DaemonState>>,
    cfg: &sbo_daemon::config::AttestConfig,
    turbo: &TurboDaClient,
    attest_key: Option<&sbo_core::crypto::SigningKey>,
    attested: &mut std::collections::HashSet<u64>,
    now: i64,
) {
    if !cfg.enabled {
        return;
    }
    let (Some(key), Some(attestor)) = (attest_key, cfg.attestor.as_deref()) else {
        return;
    };

    // Snapshot what we need under a short read lock: our head and the state db.
    let (head, state_db) = {
        let st = state.read().await;
        let Some(repo) = st.repos.list().next() else {
            return;
        };
        match repo.state_db() {
            Ok(db) => (repo.head, db),
            Err(e) => {
                tracing::warn!("attest: cannot open state db: {e}");
                return;
            }
        }
    };
    if head == 0 {
        return;
    }

    // On-chain checkpoints we might attest.
    let checkpoints = match state_db.list_objects_by_path_prefix("/sys/checkpoints/") {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("attest: list checkpoints failed: {e}");
            return;
        }
    };

    let att_path = match sbo_core::message::Path::parse(&format!(
        "/u/{attestor}/attestations/checkpoints/"
    )) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("attest: invalid attestor '{attestor}': {e}");
            return;
        }
    };

    for o in checkpoints {
        let v: serde_json::Value = match serde_json::from_slice(&o.payload) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (Some(block), Some(cp_root)) = (
            v.get("block").and_then(|b| b.as_u64()),
            v.get("state_root").and_then(|r| r.as_str()),
        ) else {
            continue;
        };

        // Only attest heights we've independently reached, once each.
        if block > head || attested.contains(&block) {
            continue;
        }

        // Skip if an attestation already exists on chain (survives restarts).
        let att_id = match sbo_core::message::Id::new(&format!("block-{block}")) {
            Ok(i) => i,
            Err(_) => continue,
        };
        if state_db.object_exists_at_path_id(&att_path, &att_id).unwrap_or(false) {
            attested.insert(block);
            continue;
        }

        // Independent verification: compare OUR recorded root at `block` to the
        // checkpoint's. If we never recorded it (e.g. bootstrapped past it), we
        // cannot independently vouch → skip. Mismatch → divergence alarm, no post.
        let our_root = match state_db.get_state_root_at_block(block) {
            Ok(Some(r)) => hex::encode(r),
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("attest: root lookup for block {block} failed: {e}");
                continue;
            }
        };
        if our_root != cp_root {
            tracing::error!(
                "attest: DIVERGENCE at block {block}: checkpoint root {cp_root} != our root {our_root}; not attesting"
            );
            attested.insert(block); // don't re-alarm every tick
            continue;
        }

        let wire = build_attestation_wire(key, attestor, block, &our_root, now);
        match turbo.submit_raw(&wire).await {
            Ok(_) => {
                tracing::info!("posted checkpoint-attestation.v1 for block {block}");
                attested.insert(block);
            }
            Err(e) => tracing::error!("attest: submit for block {block} failed: {e}"),
        }
    }
}

/// Build a signed `checkpoint-attestation.v1` wire message: the attestor's own
/// signed `(block, state_root)` claim, written under its `/u/<attestor>/` namespace.
fn build_attestation_wire(
    key: &sbo_core::crypto::SigningKey,
    attestor: &str,
    block: u64,
    state_root_hex: &str,
    now_secs: i64,
) -> Vec<u8> {
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Id, Message, ObjectType, Path};

    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": format!("/sys/checkpoints/block-{block}"),
        "block": block,
        "state_root": state_root_hex,
        "method": "replay",
        "issued_at": now_secs.max(0),
    }))
    .expect("checkpoint-attestation.v1 payload serialization");
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(&format!("/u/{attestor}/attestations/checkpoints/")).unwrap(),
        id: Id::new(&format!("block-{block}")).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("checkpoint-attestation.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: Some(format!("{}.0", (now_secs.max(0) as u128) * 1000)),
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(key);
    sbo_core::wire::serialize(&msg)
}

/// Load the checkpoint-authority signing key from a JSON file `{"secret_key":"<hex>"}`.
fn load_checkpoint_key(path: &std::path::Path) -> anyhow::Result<sbo_core::crypto::SigningKey> {
    let bytes = std::fs::read(path)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    let hex_key = v
        .get("secret_key")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("key file missing string field `secret_key`"))?;
    let raw = hex::decode(hex_key.trim())?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret_key must be 32 bytes hex"))?;
    Ok(sbo_core::crypto::SigningKey::from_bytes(&arr))
}

/// Build a signed `checkpoint.v1` wire message committing `state_root` (hex) at
/// `block`. Write-once (`create`): each `block-<h>` id is written exactly once.
fn build_checkpoint_wire(
    key: &sbo_core::crypto::SigningKey,
    block: u64,
    state_root_hex: &str,
    prev: Option<&str>,
    now_secs: i64,
) -> Vec<u8> {
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Id, Message, ObjectType, Path};

    let payload = serde_json::to_vec(&serde_json::json!({
        "block": block,
        "state_root": state_root_hex,
        "prev_checkpoint": prev,
    }))
    .expect("checkpoint.v1 payload serialization");
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/checkpoints/").unwrap(),
        id: Id::new(&format!("block-{block}")).unwrap(),
        object_type: ObjectType::Object,
        signing_key: key.public_key(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&payload)),
        payload: Some(payload),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("checkpoint.v1".to_string()),
        policy_ref: None,
        related: None,
        // Content-layer clock: physical ms ≈ inclusion time (passes HLC bounds).
        hlc: Some(format!("{}.0", (now_secs.max(0) as u128) * 1000)),
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    msg.sign(key);
    sbo_core::wire::serialize(&msg)
}

/// Keep only the newest `keep` snapshots on disk (delete older file+meta pairs).
fn prune_snapshots(dir: &std::path::Path, keep: usize) {
    for m in sbo_daemon::snapshot::list_snapshot_metas(dir)
        .into_iter()
        .skip(keep)
    {
        let _ = std::fs::remove_file(dir.join(&m.file));
        let _ = std::fs::remove_file(dir.join(sbo_daemon::snapshot::meta_file_name(m.block)));
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load or create config
    let config_path = cli.config.unwrap_or_else(Config::config_path);
    let config = Config::load(&config_path).unwrap_or_default();

    match cli.command {
        Commands::Init => {
            init_config(&config_path, &config)?;
        }
        Commands::Start { foreground, verbose, debug, prover, light } => {
            // Auto-create sample config if it doesn't exist
            if !config_path.exists() {
                std::fs::create_dir_all(Config::sbo_dir())?;
                Config::save_sample(&config_path)?;
                tracing::info!("Created sample config at {}", config_path.display());
            }
            if !foreground {
                tracing::warn!("Daemonizing not yet implemented, running in foreground");
            }
            if prover && light {
                anyhow::bail!("Cannot enable both --prover and --light modes simultaneously");
            }
            let verbose_flags = VerboseFlags::from_args(&verbose);
            let debug_flags = DebugFlags::from_args(&debug);

            // Override config with CLI flags
            let mut config = config;
            if prover {
                if config.light.enabled {
                    anyhow::bail!("Cannot enable --prover when light mode is enabled in config");
                }
                config.prover.enabled = true;
                tracing::info!("Prover mode enabled via CLI flag");
            }
            if light {
                config.light.enabled = true;
                config.prover.enabled = false; // Mutually exclusive with light mode
                tracing::info!("Light mode enabled via CLI flag");
            }

            run_daemon(config, verbose_flags, debug_flags).await?;
        }
        Commands::Status => {
            show_status(&config).await?;
        }
        Commands::Bootstrap { node, state_dir } => {
            // repos.json is only needed to derive the default state dir and to set
            // the head afterward; tolerate its absence when --state-dir is given.
            let repos = RepoManager::load(config.daemon.repos_index.clone()).ok();
            let dir = match state_dir {
                Some(d) => d,
                None => {
                    let r = repos
                        .as_ref()
                        .and_then(|m| m.list().next())
                        .ok_or_else(|| {
                            anyhow::anyhow!("no usable repos.json; pass --state-dir")
                        })?;
                    sbo_daemon::state_db_path_for_uri(&r.uri.to_string())
                }
            };
            let db = sbo_daemon::shared_state_db(&dir)?;
            println!("Bootstrapping from {node} into {} …", dir.display());
            let result = sbo_daemon::bootstrap::bootstrap(&db, &node).await?;
            println!(
                "✓ loaded snapshot at block {} ({} objects); trust={:?}; state_root={}",
                result.block,
                result.object_count,
                result.trust,
                hex::encode(result.state_root)
            );
            match repos {
                Some(mut m) => {
                    let first = m.list().next().cloned();
                    if let Some(r) = first {
                        m.update_head(&r.path, result.block)?;
                        println!(
                            "✓ set repo head to {}; run `start` to tail from block {}",
                            result.block,
                            result.block + 1
                        );
                    }
                }
                None => println!("note: repos.json not loaded — head not updated"),
            }
        }
    }

    Ok(())
}

fn init_config(path: &PathBuf, _config: &Config) -> anyhow::Result<()> {
    if path.exists() {
        println!("Config already exists at {}", path.display());
        println!("Delete it first if you want to regenerate: rm {}", path.display());
        return Ok(());
    }

    // Create directories first
    std::fs::create_dir_all(Config::sbo_dir())?;

    // Save a well-documented sample config
    Config::save_sample(path)?;
    println!("Created config at {}", path.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit {} to set your TurboDA API key", path.display());
    println!("  2. Start the daemon: sbo daemon start");
    println!();
    println!("Get a TurboDA API key at: https://turbo.availproject.org");

    Ok(())
}

/// Check DNS for all sbo:// repos and log warnings for mismatches
async fn check_dns_on_startup(repos: &RepoManager) {
    for repo in repos.list() {
        if !sbo_core::dns::is_dns_uri(&repo.display_uri) {
            continue;
        }

        match sbo_core::dns::resolve_uri(&repo.display_uri).await {
            Ok(current_resolved) => {
                let stored_resolved = repo.uri.to_string();
                if current_resolved == stored_resolved {
                    tracing::info!("DNS check: {} → {} ✓", repo.display_uri, stored_resolved);
                } else {
                    tracing::warn!(
                        "DNS mismatch: {} resolves to {} but repo is tracking {}. Run 'sbo repo relink {}' to update",
                        repo.display_uri,
                        current_resolved,
                        stored_resolved,
                        repo.path.display()
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "DNS check failed for {}: {} (continuing with cached resolution)",
                    repo.display_uri,
                    e
                );
            }
        }
    }
}

async fn run_daemon(config: Config, verbose: VerboseFlags, debug: DebugFlags) -> anyhow::Result<()> {
    tracing::info!("Starting SBO daemon");

    // Check for existing daemon
    if config.daemon.socket_path.exists() {
        anyhow::bail!(
            "Socket already exists at {}. Is another daemon running?",
            config.daemon.socket_path.display()
        );
    }

    // Initialize state
    let state = Arc::new(RwLock::new(DaemonState::new(config.clone()).await?));

    // Start light client manager
    {
        let mut state = state.write().await;
        if let Err(e) = state.lc.start().await {
            tracing::warn!("Light client not available: {}. Sync will be limited.", e);
        }
    }

    // Check DNS for sbo:// repos
    {
        let state = state.read().await;
        check_dns_on_startup(&state.repos).await;
    }

    // Enforcement invariant: on any chain that has synced past genesis, the root
    // policy (/sys/policies/root, posted at genesis) MUST be present. If it isn't,
    // validate_message silently runs in "genesis mode" and accepts EVERY write
    // with no policy checks. That failure is invisible in normal operation — it
    // was how a hardcoded-creator lookup missing an email-rooted sys (Mode-B
    // genesis) disabled all enforcement chain-wide. Assert it loudly at startup
    // so the silent-genesis symptom is operator-visible (see mingo-9vck).
    {
        let state = state.read().await;
        for repo in state.repos.list() {
            let genesis_applied = match repo.uri.first_block {
                Some(fb) => repo.head >= fb,
                None => repo.head > 0,
            };
            if !genesis_applied {
                continue; // nothing synced yet — genesis mode is legitimately expected
            }
            match repo.state_db() {
                Ok(db) if !sbo_daemon::validate::root_policy_present(db.as_ref()) => {
                    tracing::error!(
                        "ENFORCEMENT INVARIANT VIOLATED: repo {} synced to head {} but /sys/policies/root is absent. \
                         The daemon would run in genesis mode and accept ALL writes with NO policy enforcement. \
                         This indicates a genesis-mode regression (see mingo-9vck) — investigate before trusting writes.",
                        repo.uri, repo.head
                    );
                }
                Ok(_) => {
                    tracing::debug!("Enforcement invariant OK for repo {} (root policy present)", repo.uri);
                }
                Err(e) => {
                    tracing::warn!("Could not open state for {} to check enforcement invariant: {}", repo.uri, e);
                }
            }
        }
    }

    // Start IPC server
    let ipc_server = IpcServer::new(config.daemon.socket_path.clone());
    let state_for_ipc = Arc::clone(&state);

    let ipc_handle = tokio::spawn(async move {
        let handler = move |req: Request| {
            let state = Arc::clone(&state_for_ipc);
            async move { handle_request(req, state).await }
        };

        if let Err(e) = ipc_server.run(handler).await {
            tracing::error!("IPC server error: {}", e);
        }
    });

    // Start HTTP server for web auth
    let state_for_http = Arc::clone(&state);
    let http_handle = tokio::spawn(async move {
        if let Err(e) = http::run_server(state_for_http, 7890).await {
            tracing::error!("HTTP server error: {}", e);
        }
    });

    // Start sync engine
    let state_for_sync = Arc::clone(&state);
    let pending_for_sync = state.read().await.pending.clone();
    let verbose_for_sync = verbose.clone();
    let debug_for_sync = debug.clone();
    let prover_config = config.prover.clone();
    let turbo_config = config.turbo_da.clone();
    let light_mode = config.light.enabled;
    let checkpoint_config = config.checkpoint.clone();
    let attest_config = config.attest.clone();
    let sync_handle = tokio::spawn(async move {
        // Give IPC server time to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create prover if enabled
        let mut prover = if prover_config.enabled {
            tracing::info!(
                "Prover mode enabled: batch_size={}, receipt_kind={}, dev_mode={}",
                prover_config.batch_size,
                prover_config.receipt_kind,
                prover_config.dev_mode
            );
            Some(Prover::new(prover_config.clone()))
        } else {
            None
        };

        // Create TurboDA client for proof submission
        let turbo = TurboDaClient::new(turbo_config);

        // Checkpoint/snapshot scheduling state (State Commitment fast-sync).
        // Counted from process start; the manifest reads the actual snapshot files
        // on disk, so a restart just resumes counting (may skip one early snapshot).
        let mut last_checkpoint_block: u64 = 0;
        let mut writes_since_checkpoint: u64 = 0;
        let mut prev_checkpoint: Option<String> = None;
        // Load the checkpoint-authority key up front (only when publishing on-chain).
        let checkpoint_key = if checkpoint_config.publish {
            match checkpoint_config.key_file.as_ref() {
                Some(p) => match load_checkpoint_key(p) {
                    Ok(k) => {
                        tracing::info!("checkpoint on-chain publishing enabled (authority key loaded)");
                        Some(k)
                    }
                    Err(e) => {
                        tracing::error!("checkpoint publish=true but key load failed: {e}; publishing disabled");
                        None
                    }
                },
                None => {
                    tracing::error!("checkpoint publish=true but no key_file set; publishing disabled");
                    None
                }
            }
        } else {
            None
        };

        // Attestor state (State Commitment §Checkpoint Attestations). When enabled,
        // this node posts checkpoint-attestation.v1 for checkpoints it has
        // independently reached and reproduced. `attested` tracks heights we have
        // already posted this process, so we don't resubmit every tick.
        let attest_key = if attest_config.enabled {
            match attest_config.key_file.as_ref() {
                Some(p) => match load_checkpoint_key(p) {
                    Ok(k) => {
                        tracing::info!(
                            "checkpoint attestation enabled (attestor={})",
                            attest_config.attestor.as_deref().unwrap_or("<unset>")
                        );
                        Some(k)
                    }
                    Err(e) => {
                        tracing::error!("attest enabled but key load failed: {e}; attestation disabled");
                        None
                    }
                },
                None => {
                    tracing::error!("attest enabled but no key_file set; attestation disabled");
                    None
                }
            }
        } else {
            None
        };
        let mut attested: std::collections::HashSet<u64> = std::collections::HashSet::new();

        loop {
            // Get config with short lock
            let (lc_config, rpc_config) = {
                let state = state_for_sync.read().await;
                (state.config.light_client.clone(), state.config.rpc.clone())
            };

            // Resolve the chain head + availability window. Prefer the light
            // client; if it's not running, fall back to the RPC finalized head
            // and run in RPC-only mode (trust the full node for block data —
            // real DA, no light-client sampling). Sleep+retry if both fail.
            let lc = LcManager::new(lc_config.clone());
            let (mut status, mut rpc_only) = match lc.status().await {
                Ok(s) => {
                    tracing::debug!(
                        "LC status: latest={}, available={}-{}",
                        s.latest_block, s.available_first, s.available_last
                    );
                    (s, false)
                }
                Err(e) => {
                    let mut rpc = RpcClient::new(rpc_config.clone(), false, false, false);
                    match rpc.get_finalized_head().await {
                        Ok(head) => {
                            tracing::debug!("LC unavailable ({e}); RPC-only sync at head {head}");
                            (
                                sbo_daemon::lc::LcStatus {
                                    modes: vec!["rpc-only".to_string()],
                                    app_id: None,
                                    network: lc_config.network.clone(),
                                    latest_block: head,
                                    available_first: 0,
                                    available_last: head,
                                },
                                true,
                            )
                        }
                        Err(rpc_err) => {
                            tracing::debug!("LC unavailable ({e}); RPC head failed ({rpc_err})");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                }
            };

            // If the light client is up but its DAS availability window has
            // stalled well behind finality, it has stopped sampling. Because
            // block processing is ceilinged at `available_last` (and the
            // per-block DAS check is the same `<= available_last` test), a frozen
            // window freezes sync entirely — new writes never confirm even as the
            // chain advances (mingo-stho problem 2). Fall back to RPC-only tailing
            // (trust the full node, exactly as when the LC is unreachable) so
            // liveness continues, and surface the stall to the operator.
            if !rpc_only {
                let lag = status.latest_block.saturating_sub(status.available_last);
                if lag > LC_STALL_LAG_BLOCKS {
                    tracing::warn!(
                        "LC availability window stalled: available_last={} is {} blocks behind finalized head {}; falling back to RPC-only tailing until it recovers",
                        status.available_last, lag, status.latest_block
                    );
                    rpc_only = true;
                    status.available_first = 0;
                    status.available_last = status.latest_block;
                }
            }

            // Process blocks for each repo
            let mut sync = SyncEngine::new(
                LcManager::new(lc_config),
                RpcClient::new(rpc_config, verbose_for_sync.rpc, verbose_for_sync.rpc_decode, debug_for_sync.save_raw_block),
                verbose_for_sync.raw_incoming,
                verbose_for_sync.rpc_decode,
                light_mode,
                rpc_only,
                pending_for_sync.clone(),
            );

            // Sweep mempool overlay entries whose writes never confirmed (TTL).
            {
                let swept = pending_for_sync
                    .write()
                    .map(|mut p| p.sweep_expired(unix_now(), sbo_daemon::pending::DEFAULT_TTL_SECS))
                    .unwrap_or(0);
                if swept > 0 {
                    tracing::debug!("Swept {} expired pending overlay entries", swept);
                }
            }

            // Get repo info with read lock
            let repos_info: Vec<_> = {
                let state = state_for_sync.read().await;
                state.repos.list().map(|r| (r.uri.clone(), r.head, r.path.clone())).collect()
            };

            // Find minimum head and maximum end across all repos
            let mut min_start = u64::MAX;
            let mut max_end = 0u64;
            for (_uri, head, _path) in &repos_info {
                let start = (*head + 1).max(status.available_first);
                let end = status.available_last.min(status.latest_block);
                if start <= end {
                    min_start = min_start.min(start);
                    max_end = max_end.max(end);
                }
            }

            if min_start <= max_end {
                // Process blocks in order
                for block_num in min_start..=max_end {
                    // Process block with write lock
                    let mut state = state_for_sync.write().await;
                    match sync.process_block(block_num, &mut state.repos).await {
                        Ok(result) => {
                            // Only log if there was data or verbose blocks enabled
                            if result.tx_count > 0 || verbose_for_sync.blocks {
                                tracing::info!("Processed block {} ({} transactions)", block_num, result.tx_count);
                            }
                            // Drive the write-count checkpoint trigger (approximate;
                            // includes the occasional checkpoint object itself).
                            writes_since_checkpoint += result.tx_count as u64;

                            // Genesis verification: when this block is a repo's genesis
                            // anchor and an expected hash was recorded, verify the
                            // reconstructed genesis. Non-fatal — a mismatch is logged
                            // loudly (operator-visible) rather than crashing sync.
                            let to_verify: Vec<(String, Result<(), String>)> = state
                                .repos
                                .list()
                                .filter(|r| {
                                    r.expected_genesis.is_some()
                                        && r.uri.first_block == Some(block_num)
                                })
                                .map(|r| (r.id.clone(), r.verify_genesis(&result.block_data)))
                                .collect();
                            for (id, outcome) in to_verify {
                                match outcome {
                                    Ok(()) => tracing::info!(
                                        "Genesis verified for repo {} at block {}",
                                        id, block_num
                                    ),
                                    Err(e) => tracing::error!(
                                        "GENESIS VERIFICATION FAILED for repo {} at block {}: {}",
                                        id, block_num, e
                                    ),
                                }
                            }

                            // Add block to prover if enabled and genesis has been processed
                            if let Some(ref mut p) = prover {
                                // Only prove if genesis has been processed (objects exist)
                                if !result.has_genesis {
                                    // Skip proving until genesis is processed
                                    if result.tx_count > 0 {
                                        tracing::debug!(
                                            "Skipping prover for block {} - genesis not yet processed",
                                            block_num
                                        );
                                    }
                                } else if block_num < max_end {
                                    // Skip proving while catching up (not at head yet)
                                    // Only prove once we're processing the latest block
                                    tracing::debug!(
                                        "Skipping prover for block {} - catching up ({} blocks behind)",
                                        block_num, max_end - block_num
                                    );
                                } else {
                                    // Use real state roots and objects from process_block result
                                    let pre_root = result.pre_state_root.unwrap_or([0u8; 32]);
                                    let post_root = result.post_state_root;

                                    p.add_block(
                                        block_num,
                                        pre_root,
                                        post_root,
                                        result.block_data,
                                        result.state_witness,
                                    );

                                    // Check if we should generate and submit a proof
                                    if p.should_prove(block_num) {
                                        if let Some(proof_result) = p.generate_proof() {
                                            let sbop_bytes = p.create_sbop_message(&proof_result);
                                            tracing::info!(
                                                "Generated {} proof for blocks {}-{} ({} bytes)",
                                                proof_result.receipt_kind.as_str(),
                                                proof_result.from_block,
                                                proof_result.to_block,
                                                sbop_bytes.len()
                                            );

                                            // Submit to Avail via TurboDA
                                            match turbo.submit_proof(sbop_bytes).await {
                                                Ok(tx_hash) => {
                                                    tracing::info!(
                                                        "Submitted proof to Avail: {}",
                                                        tx_hash
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "Failed to submit proof: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to process block {}: {}", block_num, e);
                            // Don't update head, will retry next cycle
                            break;
                        }
                    }
                }
            }

            // Checkpoint + snapshot when due (State Commitment fast-sync). Runs in
            // this sync task after block processing, so it observes a consistent
            // confirmed state with no concurrent writer.
            checkpoint_if_due(
                &state_for_sync,
                &checkpoint_config,
                status.latest_block,
                &mut last_checkpoint_block,
                &mut writes_since_checkpoint,
                &turbo,
                checkpoint_key.as_ref(),
                &mut prev_checkpoint,
                unix_now(),
            )
            .await;

            // Post checkpoint attestations for checkpoints we've independently
            // reached (State Commitment §Checkpoint Attestations). Lags the
            // checkpoint: attests past heights from our own recorded roots.
            attest_if_due(
                &state_for_sync,
                &attest_config,
                &turbo,
                attest_key.as_ref(),
                &mut attested,
                unix_now(),
            )
            .await;

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });

    tracing::info!("Daemon running. Socket: {}", config.daemon.socket_path.display());

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");

    // Cleanup
    if config.daemon.socket_path.exists() {
        std::fs::remove_file(&config.daemon.socket_path)?;
    }

    ipc_handle.abort();
    http_handle.abort();
    sync_handle.abort();

    Ok(())
}

async fn handle_request(req: Request, state: Arc<RwLock<DaemonState>>) -> Response {
    match req {
        Request::RepoAdd { display_uri, resolved_uri, path, from_block, expected_genesis } => {
            // Parse the resolved URI (always sbo+raw://)
            let uri = match SboRawUri::parse(&resolved_uri) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid URI: {}", e)),
            };

            // Check for duplicates
            {
                let state = state.read().await;
                for repo in state.repos.list() {
                    // Compare on the anchor-independent identity so an idempotent
                    // re-add (e.g. on each deploy) whose URI differs only by the
                    // `@firstBlock` anchor is recognized as the same chain instead
                    // of spawning a duplicate repo that re-backfills from genesis.
                    if repo.uri.to_identity_string() == uri.to_identity_string() {
                        return Response::error(format!(
                            "Already tracking this chain as {}",
                            repo.display_uri
                        ));
                    }
                }
            }

            // Resolve negative from_block relative to current chain head
            let resolved_from_block = match from_block {
                Some(block) if block < 0 => {
                    // Need to query light client for latest block
                    let state_read = state.read().await;
                    match state_read.lc.status().await {
                        Ok(status) => {
                            let latest = status.latest_block as i64;
                            let resolved = (latest + block).max(0) as u64;
                            tracing::info!(
                                "Resolved from_block {} relative to latest {} = {}",
                                block, latest, resolved
                            );
                            Some(resolved)
                        }
                        Err(e) => {
                            return Response::error(format!(
                                "Cannot resolve negative from_block: light client unavailable: {}",
                                e
                            ));
                        }
                    }
                }
                Some(block) => Some(block as u64),
                // No explicit override → default to the @firstBlock genesis anchor from
                // the URI (the spec's sync-from-genesis start). Operator-supplied
                // from_block still wins above.
                None => uri.first_block,
            };
            if from_block.is_none() && resolved_from_block.is_some() {
                tracing::info!(
                    "Seeding repo from @firstBlock anchor = {}",
                    resolved_from_block.unwrap()
                );
            }

            // Expected genesis hash: explicit (from the _sbo record) wins; otherwise a
            // `?genesis=` selector on the resolved URI.
            let genesis_to_store = expected_genesis.or_else(|| uri.query.genesis.clone());

            let mut state = state.write().await;
            let added = match state.repos.add(display_uri.clone(), uri, path, resolved_from_block) {
                Ok(repo) => Ok(serde_json::json!({
                    "id": repo.id,
                    "display_uri": repo.display_uri,
                    "resolved_uri": repo.uri.to_string(),
                    "path": repo.path,
                    "head": repo.head,
                })),
                Err(e) => Err(e.to_string()),
            };
            match added {
                Ok(data) => {
                    if let Some(id) = data["id"].as_str() {
                        if let Err(e) =
                            state.repos.set_expected_genesis(&id.to_string(), genesis_to_store)
                        {
                            tracing::warn!("Failed to record expected genesis: {}", e);
                        }
                    }
                    Response::ok(data)
                }
                Err(e) => Response::error(e),
            }
        }

        Request::RepoRemove { path } => {
            let mut state = state.write().await;
            match state.repos.remove(&path) {
                Ok(repo) => Response::ok(serde_json::json!({
                    "removed": repo.uri.to_string(),
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::RepoRemoveByUri { uri } => {
            let mut state = state.write().await;
            match state.repos.remove_by_uri(&uri) {
                Ok(repo) => Response::ok(serde_json::json!({
                    "removed": repo.uri.to_string(),
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::RepoList => {
            let state = state.read().await;
            let repos: Vec<_> = state
                .repos
                .list()
                .map(|r| {
                    serde_json::json!({
                        "display_uri": r.display_uri,
                        "resolved_uri": r.uri.to_string(),
                        "path": r.path.to_string_lossy(),
                        "head": r.head,
                        "dns_checked_at": r.dns_checked_at,
                    })
                })
                .collect();
            Response::ok(serde_json::json!({ "repos": repos }))
        }

        Request::RepoRelink { path } => {
            let mut state = state.write().await;

            // Find repo by path
            let repo = match state.repos.find_by_path(&path) {
                Some(r) => r.clone(),
                None => return Response::error(format!("No repo at path: {}", path.display())),
            };

            // Check if it's a DNS-based URI
            if !sbo_core::dns::is_dns_uri(&repo.display_uri) {
                return Response::error("Repo is not using a DNS-based URI (sbo://)");
            }

            // Re-resolve DNS
            let new_resolved = match sbo_core::dns::resolve_uri(&repo.display_uri).await {
                Ok(r) => r,
                Err(e) => return Response::error(format!("DNS resolution failed: {}", e)),
            };

            // Parse new URI
            let new_uri = match SboRawUri::parse(&new_resolved) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid resolved URI: {}", e)),
            };

            let old_resolved = repo.uri.to_string();

            // Update repo
            if let Err(e) = state.repos.update_uri(&repo.id, repo.display_uri.clone(), new_uri) {
                return Response::error(format!("Failed to update repo: {}", e));
            }

            Response::ok(serde_json::json!({
                "display_uri": repo.display_uri,
                "old_resolved": old_resolved,
                "new_resolved": new_resolved,
                "message": "Repo relinked. Will re-sync from new chain."
            }))
        }

        Request::Status => {
            let state = state.read().await;

            let lc_status = match state.lc.status().await {
                Ok(s) => serde_json::json!({
                    "connected": true,
                    "network": s.network,
                    "latest_block": s.latest_block,
                    "modes": s.modes,
                }),
                Err(e) => serde_json::json!({
                    "connected": false,
                    "error": e.to_string(),
                }),
            };

            let repo_count = state.repos.list().count();

            Response::ok(serde_json::json!({
                "light_client": lc_status,
                "repos": repo_count,
                "app_ids": state.repos.followed_app_ids(),
            }))
        }

        Request::Submit { repo_path, sbo_path: _, id: _, data } => {
            let state = state.read().await;

            // Find the repo
            let repo = match state.repos.get_by_path(&repo_path) {
                Some(r) => r,
                None => return Response::error(format!("No repo at path: {}", repo_path.display())),
            };

            // TODO: Build proper SBO message with signing
            // For now, just submit raw data
            match state.turbo.submit_raw(&data).await {
                Ok(result) => Response::ok(serde_json::json!({
                    "submission_id": result.submission_id,
                    "app_id": repo.uri.app_id,
                })),
                Err(e) => Response::error(e.to_string()),
            }
        }

        Request::GetObject { repo_path, path, id, with_proof } => {
            let state = state.read().await;
            let repo = match state.repos.get_by_path(&repo_path) {
                Some(r) => r,
                None => return Response::error(format!("No repo at path: {}", repo_path.display())),
            };
            match read_object_view(repo, &path, &id, with_proof, &state.pending) {
                Ok(view) => Response::ok(view),
                Err(e) => Response::error(e.message),
            }
        }

        Request::ListObjects { repo_path, prefix, schema } => {
            let state = state.read().await;
            let repo = match state.repos.get_by_path(&repo_path) {
                Some(r) => r,
                None => return Response::error(format!("No repo at path: {}", repo_path.display())),
            };
            let selector = match (prefix, schema) {
                (Some(p), None) => ListSelector::Prefix(p),
                (None, Some(s)) => ListSelector::Schema(s),
                (Some(_), Some(_)) => {
                    return Response::error("provide exactly one of `prefix` or `schema`")
                }
                (None, None) => return Response::error("`prefix` or `schema` is required"),
            };
            match read_object_list(repo, &selector, &state.pending) {
                Ok(views) => Response::ok(serde_json::json!({ "objects": views })),
                Err(e) => Response::error(e.message),
            }
        }

        Request::ObjectProof { repo_path, path, id } => {
            let state = state.read().await;

            // Find the repo
            let repo = match state.repos.get_by_path(&repo_path) {
                Some(r) => r,
                None => return Response::error(format!("No repo at path: {}", repo_path.display())),
            };

            // Get state db for this repo
            let state_db = match repo.state_db() {
                Ok(db) => db,
                Err(e) => return Response::error(format!("Failed to open state db: {}", e)),
            };

            // Parse path and id
            let sbo_path = match sbo_core::message::Path::parse(&path) {
                Ok(p) => p,
                Err(e) => return Response::error(format!("Invalid path: {}", e)),
            };
            let sbo_id = match sbo_core::message::Id::new(&id) {
                Ok(i) => i,
                Err(e) => return Response::error(format!("Invalid id: {}", e)),
            };

            // Generate trie proof (auto-detects creator)
            match state_db.generate_trie_proof_auto(&sbo_path, &sbo_id) {
                Ok(Some((creator, trie_proof))) => {
                    // Read the object file from disk
                    // Object path is: repo_path / sbo_path (without leading /) / id
                    let object_file_path = repo.path.join(path.trim_start_matches('/')).join(&id);
                    let object_bytes = match std::fs::read(&object_file_path) {
                        Ok(bytes) => Some(bytes),
                        Err(e) => {
                            tracing::warn!(
                                "Could not read object file at {}: {}",
                                object_file_path.display(), e
                            );
                            None
                        }
                    };

                    // Create SBOQ message with trie proof
                    let sboq = sbo_core::proof::SboqMessage {
                        version: "0.2".to_string(),
                        path: path.clone(),
                        id: id.clone(),
                        creator: creator.to_string(),
                        block: repo.head,
                        state_root: trie_proof.state_root,
                        object_hash: trie_proof.object_hash,
                        trie_proof,
                        object: object_bytes,
                    };

                    let sboq_bytes = sbo_core::proof::serialize_sboq(&sboq);
                    let sboq_text = String::from_utf8_lossy(&sboq_bytes).to_string();

                    Response::ok(serde_json::json!({
                        "sboq": sboq_text,
                        "creator": creator.to_string(),
                        "state_root": hex::encode(sboq.state_root),
                        "object_hash": sboq.object_hash.map(hex::encode),
                    }))
                }
                Ok(None) => Response::error("Object not found"),
                Err(e) => Response::error(format!("Failed to generate proof: {}", e)),
            }
        }

        Request::SubmitIdentity { uri, name, data, wait: _ } => {
            // Get state for repo lookup
            let state_read = state.read().await;

            // Find repo matching the URI (check both display_uri and resolved uri)
            // Normalize by trimming trailing slashes for comparison
            let uri_normalized = uri.trim_end_matches('/');
            let repo = state_read.repos.list().find(|r| {
                let repo_uri = r.uri.to_string();
                let repo_uri_normalized = repo_uri.trim_end_matches('/');
                let display_uri_normalized = r.display_uri.trim_end_matches('/');
                uri_normalized.starts_with(repo_uri_normalized)
                    || repo_uri_normalized.starts_with(uri_normalized)
                    || uri_normalized.starts_with(display_uri_normalized)
                    || display_uri_normalized.starts_with(uri_normalized)
            });

            let identity_uri = match repo {
                Some(r) => format!("{}/sys/names/{}", r.uri.to_string().trim_end_matches('/'), name),
                None => return Response::error(format!("No repo configured for URI: {}. Add with: sbo repo add {} <path>", uri, uri)),
            };

            // Submit via TurboDA
            match state_read.turbo.submit_raw(&data).await {
                Ok(result) => {
                    // Return submitted status - verification happens asynchronously via sync thread
                    // User can check status with 'sbo id show'
                    Response::ok(serde_json::json!({
                        "status": "submitted",
                        "uri": identity_uri,
                        "submission_id": result.submission_id,
                        "message": "Identity submitted to chain. Check verification with 'sbo id show'",
                    }))
                }
                Err(e) => Response::error(format!("Submission failed: {}", e)),
            }
        }

        Request::ListIdentities { uri } => {
            let state_read = state.read().await;
            let mut identities = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by URI if provided (check both display_uri and resolved uri)
                if let Some(ref filter_uri) = uri {
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(filter_uri) && !repo.display_uri.starts_with(filter_uri) {
                        continue;
                    }
                }

                // Scan /sys/names/ directory
                // Structure: /sys/names/<name> (file) or /sys/names/<name>/<object_id> (directory)
                let names_path = repo.path.join("sys").join("names");
                if names_path.exists() {
                    if let Ok(entries) = std::fs::read_dir(&names_path) {
                        for entry in entries.flatten() {
                            let name = entry.file_name().to_string_lossy().to_string();
                            let entry_path = entry.path();

                            // Try to find identity content - either direct file or file in directory
                            let content = if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                                // Direct file (e.g., /sys/names/sys)
                                std::fs::read(&entry_path).ok()
                            } else if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                // Directory - look for first file inside
                                std::fs::read_dir(&entry_path).ok().and_then(|files| {
                                    files.flatten().find(|f| f.file_type().map(|t| t.is_file()).unwrap_or(false))
                                        .and_then(|f| std::fs::read(f.path()).ok())
                                })
                            } else {
                                None
                            };

                            if let Some(content) = content {
                                if let Ok(msg) = sbo_core::wire::parse(&content) {
                                    if let Some(payload) = &msg.payload {
                                        // Parse identity payload - try multiple formats
                                        let identity_data = if let Ok(identity) = sbo_core::schema::parse_identity(payload) {
                                            // JSON identity schema
                                            Some((identity.public_key, identity.display_name))
                                        } else if let Ok(token_str) = std::str::from_utf8(payload) {
                                            // Try JWT format (Content-Type: application/jwt)
                                            sbo_core::jwt::decode_identity_claims(token_str).ok().map(|claims| {
                                                (claims.public_key, None)
                                            })
                                        } else {
                                            // Fallback for raw JSON
                                            serde_json::from_slice::<serde_json::Value>(payload).ok().and_then(|v| {
                                                let public_key = v.get("public_key")
                                                    .and_then(|k| k.as_str())
                                                    .map(|s| s.to_string())?;
                                                let display_name = v.get("display_name").and_then(|d| d.as_str()).map(|s| s.to_string());
                                                Some((public_key, display_name))
                                            })
                                        };

                                        if let Some((public_key, display_name)) = identity_data {
                                            identities.push(serde_json::json!({
                                                "uri": format!("{}/sys/names/{}", repo.display_uri.trim_end_matches('/'), name),
                                                "chain": &repo.display_uri,
                                                "name": name,
                                                "display_name": display_name,
                                                "public_key": public_key,
                                                "status": "verified",
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Response::ok(serde_json::json!({ "identities": identities }))
        }

        Request::GetIdentity { uri } => {
            let state_read = state.read().await;

            // Parse URI to extract chain and name
            // Supports: sbo+raw://avail:turing:506/sys/names/alice or just "alice"
            let (chain_uri, name) = if uri.starts_with("sbo+raw://") || uri.starts_with("sbo://") {
                // Full URI - extract chain and name
                if let Some(names_pos) = uri.find("/sys/names/") {
                    let chain = &uri[..names_pos + 1]; // Include trailing /
                    let name = &uri[names_pos + 11..]; // Skip "/sys/names/"
                    (Some(chain.to_string()), name.to_string())
                } else {
                    return Response::error("Invalid identity URI: must contain /sys/names/");
                }
            } else {
                // Just a name - search all repos
                (None, uri)
            };

            let mut found_identities = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by chain if provided (check both display_uri and resolved uri)
                if let Some(ref chain) = chain_uri {
                    let chain_trimmed = chain.trim_end_matches('/');
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(chain_trimmed) && !repo.display_uri.starts_with(chain_trimmed) {
                        continue;
                    }
                }

                // Try to read the identity file
                let identity_path = repo.path.join("sys").join("names").join(&name);
                if identity_path.exists() {
                    if let Ok(content) = std::fs::read(&identity_path) {
                        if let Ok(msg) = sbo_core::wire::parse(&content) {
                            if let Some(payload) = &msg.payload {
                                // Parse identity payload - try multiple formats
                                let identity_data = if let Ok(identity) = sbo_core::schema::parse_identity(payload) {
                                    // JSON identity schema
                                    Some((identity.public_key, identity.display_name, identity.description, identity.avatar, identity.links, identity.binding))
                                } else if let Ok(token_str) = std::str::from_utf8(payload) {
                                    // Try JWT format (Content-Type: application/jwt)
                                    sbo_core::jwt::decode_identity_claims(token_str).ok().map(|claims| {
                                        (claims.public_key, None, None, None, None, None)
                                    })
                                } else {
                                    // Fallback for raw JSON
                                    serde_json::from_slice::<serde_json::Value>(payload).ok().and_then(|v| {
                                        let public_key = v.get("public_key")
                                            .and_then(|k| k.as_str())
                                            .map(|s| s.to_string())?;
                                        let display_name = v.get("display_name").and_then(|d| d.as_str()).map(|s| s.to_string());
                                        Some((public_key, display_name, None, None, None, None))
                                    })
                                };

                                if let Some((public_key, display_name, description, avatar, links, binding)) = identity_data {
                                    found_identities.push(serde_json::json!({
                                        "uri": format!("{}/sys/names/{}", repo.display_uri.trim_end_matches('/'), name),
                                        "chain": &repo.display_uri,
                                        "name": name,
                                        "public_key": public_key,
                                        "display_name": display_name,
                                        "description": description,
                                        "avatar": avatar,
                                        "links": links,
                                        "binding": binding,
                                        "status": "verified",
                                    }));
                                }
                            }
                        }
                    }
                }
            }

            if found_identities.is_empty() {
                Response::error(format!("Identity '{}' not found", name))
            } else if found_identities.len() == 1 {
                Response::ok(found_identities.into_iter().next().unwrap())
            } else {
                // Multiple identities with same name across chains
                Response::ok(serde_json::json!({ "identities": found_identities }))
            }
        }

        Request::SubmitDomain { uri, domain_name, data } => {
            // Get state for repo lookup
            let state_read = state.read().await;

            // Find repo matching the URI
            let repo = state_read.repos.list().find(|r| {
                uri.starts_with(&r.uri.to_string()) || uri.starts_with(&r.display_uri)
            });

            let domain_uri = match repo {
                Some(r) => format!("{}/sys/domains/{}", r.uri.to_string().trim_end_matches('/'), domain_name),
                None => return Response::error(format!("No repo configured for URI: {}. Add with: sbo repo add {} <path>", uri, uri)),
            };

            // Submit via TurboDA
            match state_read.turbo.submit_raw(&data).await {
                Ok(result) => {
                    Response::ok(serde_json::json!({
                        "status": "submitted",
                        "uri": domain_uri,
                        "submission_id": result.submission_id,
                    }))
                }
                Err(e) => Response::error(format!("Submission failed: {}", e)),
            }
        }

        Request::ListDomains { uri } => {
            let state_read = state.read().await;
            let mut domains = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by URI if provided
                if let Some(ref filter_uri) = uri {
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(filter_uri) && !repo.display_uri.starts_with(filter_uri) {
                        continue;
                    }
                }

                // Scan /sys/domains/ directory
                let domains_path = repo.path.join("sys").join("domains");
                if domains_path.exists() {
                    if let Ok(entries) = std::fs::read_dir(&domains_path) {
                        for entry in entries.flatten() {
                            let domain_name = entry.file_name().to_string_lossy().to_string();
                            let entry_path = entry.path();

                            // Try to read domain content
                            let content = if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                                std::fs::read(&entry_path).ok()
                            } else if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                std::fs::read_dir(&entry_path).ok().and_then(|files| {
                                    files.flatten().find(|f| f.file_type().map(|t| t.is_file()).unwrap_or(false))
                                        .and_then(|f| std::fs::read(f.path()).ok())
                                })
                            } else {
                                None
                            };

                            if let Some(content) = content {
                                if let Ok(msg) = sbo_core::wire::parse(&content) {
                                    if let Some(payload) = &msg.payload {
                                        // Parse domain JWT to get public key
                                        if let Ok(token_str) = std::str::from_utf8(payload) {
                                            if let Ok(claims) = sbo_core::jwt::decode_identity_claims(token_str) {
                                                domains.push(serde_json::json!({
                                                    "uri": format!("{}/sys/domains/{}", repo.display_uri.trim_end_matches('/'), domain_name),
                                                    "chain": &repo.display_uri,
                                                    "domain": domain_name,
                                                    "public_key": claims.public_key,
                                                    "status": "verified",
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Response::ok(serde_json::json!({ "domains": domains }))
        }

        Request::GetDomain { domain } => {
            let state_read = state.read().await;

            // Parse domain reference - either full URI or just domain name
            let (chain_uri, domain_name) = if domain.starts_with("sbo+raw://") || domain.starts_with("sbo://") {
                // Full URI - extract chain and domain
                if let Some(domains_pos) = domain.find("/sys/domains/") {
                    let chain = &domain[..domains_pos + 1];
                    let name = &domain[domains_pos + 13..]; // Skip "/sys/domains/"
                    (Some(chain.to_string()), name.to_string())
                } else {
                    return Response::error("Invalid domain URI: must contain /sys/domains/");
                }
            } else {
                // Just a domain name - search all repos
                (None, domain)
            };

            let mut found_domains = Vec::new();

            for repo in state_read.repos.list() {
                // Filter by chain if provided
                if let Some(ref chain) = chain_uri {
                    let chain_trimmed = chain.trim_end_matches('/');
                    let resolved = repo.uri.to_string();
                    if !resolved.starts_with(chain_trimmed) && !repo.display_uri.starts_with(chain_trimmed) {
                        continue;
                    }
                }

                // Try to read the domain file
                let domain_path = repo.path.join("sys").join("domains").join(&domain_name);
                if domain_path.exists() {
                    if let Ok(content) = std::fs::read(&domain_path) {
                        if let Ok(msg) = sbo_core::wire::parse(&content) {
                            if let Some(payload) = &msg.payload {
                                // Parse domain JWT
                                if let Ok(token_str) = std::str::from_utf8(payload) {
                                    if let Ok(claims) = sbo_core::jwt::decode_identity_claims(token_str) {
                                        found_domains.push(serde_json::json!({
                                            "uri": format!("{}/sys/domains/{}", repo.display_uri.trim_end_matches('/'), domain_name),
                                            "chain": &repo.display_uri,
                                            "domain": domain_name,
                                            "public_key": claims.public_key,
                                            "status": "verified",
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if found_domains.is_empty() {
                Response::error(format!("Domain '{}' not found", domain_name))
            } else if found_domains.len() == 1 {
                Response::ok(found_domains.into_iter().next().unwrap())
            } else {
                Response::ok(serde_json::json!({ "domains": found_domains }))
            }
        }

        Request::RepoCreate { display_uri, resolved_uri, path, genesis_data } => {
            // Parse and validate the resolved URI (always sbo+raw://)
            let parsed_uri = match SboRawUri::parse(&resolved_uri) {
                Ok(u) => u,
                Err(e) => return Response::error(format!("Invalid URI: {}", e)),
            };

            // URI path must be "/" for genesis (no path prefix or empty)
            if parsed_uri.path.is_some() && parsed_uri.path.as_deref() != Some("/") {
                return Response::error("URI path must be '/' for repo creation");
            }

            let state_read = state.read().await;

            // Check if repo already exists
            if state_read.repos.list().any(|r| r.uri.to_string() == parsed_uri.to_string()) {
                return Response::error(format!("Repo already exists for URI: {}", resolved_uri));
            }

            // Get current block height before submission. Prefer the light
            // client; fall back to the Avail RPC finalized head when no light
            // client is running (a fresh RpcClient avoids needing &mut on the
            // shared one under the read lock).
            let current_block = match state_read.lc.status().await {
                Ok(status) => status.latest_block,
                Err(lc_err) => {
                    let mut rpc = RpcClient::new(state_read.config.rpc.clone(), false, false, false);
                    match rpc.get_finalized_head().await {
                        Ok(head) => head,
                        Err(rpc_err) => {
                            return Response::error(format!(
                                "Cannot get chain head (light client: {lc_err}; rpc: {rpc_err})"
                            ));
                        }
                    }
                }
            };

            // Submit genesis via TurboDA
            match state_read.turbo.submit_raw(&genesis_data).await {
                Ok(result) => {
                    tracing::info!(
                        "Genesis submitted for {}: submission_id={}",
                        display_uri, result.submission_id
                    );

                    // Drop read lock before taking write lock
                    drop(state_read);

                    // Add repo starting from current block
                    let mut state_write = state.write().await;
                    match state_write.repos.add(display_uri.clone(), parsed_uri.clone(), path.clone(), Some(current_block)) {
                        Ok(repo) => {
                            Response::ok(serde_json::json!({
                                "display_uri": repo.display_uri,
                                "resolved_uri": repo.uri.to_string(),
                                "path": repo.path,
                                "from_block": current_block,
                                "submission_id": result.submission_id,
                            }))
                        }
                        Err(e) => {
                            Response::error(format!(
                                "Genesis submitted (id={}) but failed to add repo: {}",
                                result.submission_id, e
                            ))
                        }
                    }
                }
                Err(e) => Response::error(format!("Failed to submit genesis: {}", e)),
            }
        }

        Request::Shutdown => {
            tracing::info!("Shutdown requested via IPC");
            // TODO: Graceful shutdown
            Response::ok(serde_json::json!({"status": "shutting down"}))
        }

        // ====================================================================
        // Auth / Sign Request Flow
        // ====================================================================

        Request::SubmitSignRequest {
            request_id,
            app_name,
            app_origin,
            email,
            challenge,
            purpose,
        } => {
            let mut state_write = state.write().await;

            // Check for duplicate request_id
            if state_write.sign_requests.contains_key(&request_id) {
                return Response::error(format!("Request ID '{}' already exists", request_id));
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let request = IpcSignRequest {
                request_id: request_id.clone(),
                app_name,
                app_origin,
                email,
                challenge,
                purpose,
                status: SignRequestStatus::Pending,
                created_at: now,
                assertion_jwt: None,
                session_binding_jwt: None,
                rejection_reason: None,
            };

            state_write.sign_requests.insert(request_id.clone(), request);

            tracing::info!("New sign request queued: {}", request_id);

            Response::ok(serde_json::json!({
                "status": "pending",
                "request_id": request_id,
            }))
        }

        Request::ListSignRequests => {
            let state_read = state.read().await;

            let requests: Vec<_> = state_read
                .sign_requests
                .values()
                .filter(|r| r.status == SignRequestStatus::Pending)
                .map(|r| serde_json::json!({
                    "request_id": r.request_id,
                    "app_name": r.app_name,
                    "app_origin": r.app_origin,
                    "email": r.email,
                    "challenge": r.challenge,
                    "purpose": r.purpose,
                    "created_at": r.created_at,
                }))
                .collect();

            Response::ok(serde_json::json!({ "requests": requests }))
        }

        Request::GetSignRequest { request_id } => {
            let state_read = state.read().await;

            match state_read.sign_requests.get(&request_id) {
                Some(request) => Response::ok(serde_json::json!({
                    "request_id": request.request_id,
                    "app_name": request.app_name,
                    "app_origin": request.app_origin,
                    "email": request.email,
                    "challenge": request.challenge,
                    "purpose": request.purpose,
                    "status": format!("{:?}", request.status),
                    "created_at": request.created_at,
                })),
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        Request::ApproveSignRequest {
            request_id,
            assertion_jwt,
            session_binding_jwt,
        } => {
            let mut state_write = state.write().await;

            match state_write.sign_requests.get_mut(&request_id) {
                Some(request) => {
                    if request.status != SignRequestStatus::Pending {
                        return Response::error(format!(
                            "Request '{}' is not pending (status: {:?})",
                            request_id, request.status
                        ));
                    }

                    request.status = SignRequestStatus::Approved;
                    request.assertion_jwt = Some(assertion_jwt);
                    request.session_binding_jwt = Some(session_binding_jwt);

                    tracing::info!("Sign request approved: {}", request_id);

                    Response::ok(serde_json::json!({
                        "status": "approved",
                        "request_id": request_id,
                    }))
                }
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        Request::RejectSignRequest { request_id, reason } => {
            let mut state_write = state.write().await;

            match state_write.sign_requests.get_mut(&request_id) {
                Some(request) => {
                    if request.status != SignRequestStatus::Pending {
                        return Response::error(format!(
                            "Request '{}' is not pending (status: {:?})",
                            request_id, request.status
                        ));
                    }

                    request.status = SignRequestStatus::Rejected;
                    request.rejection_reason = reason;

                    tracing::info!("Sign request rejected: {}", request_id);

                    Response::ok(serde_json::json!({
                        "status": "rejected",
                        "request_id": request_id,
                    }))
                }
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }

        Request::GetSignRequestResult { request_id } => {
            let state_read = state.read().await;

            match state_read.sign_requests.get(&request_id) {
                Some(request) => {
                    let status = format!("{:?}", request.status).to_lowercase();

                    // Return SignRequestResult format
                    let result = serde_json::json!({
                        "status": status,
                        "assertion_jwt": request.assertion_jwt,
                        "session_binding_jwt": request.session_binding_jwt,
                        "rejection_reason": request.rejection_reason,
                    });

                    Response::ok(result)
                }
                None => Response::error(format!("Sign request '{}' not found", request_id)),
            }
        }
    }
}

async fn show_status(config: &Config) -> anyhow::Result<()> {
    use sbo_daemon::ipc::IpcClient;

    let client = IpcClient::new(config.daemon.socket_path.clone());

    match client.request(Request::Status).await {
        Ok(Response::Ok { data }) => {
            println!("SBO Daemon Status");
            println!("=================");
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Ok(Response::Error { message }) => {
            println!("Error: {}", message);
        }
        Err(e) => {
            println!("Daemon not running or unreachable: {}", e);
        }
    }

    Ok(())
}
