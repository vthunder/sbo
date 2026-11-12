//! Daemon configuration

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Global daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub light_client: LightClientConfig,
    pub rpc: RpcConfig,
    pub turbo_da: TurboDaConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub prover: ProverConfig,
    #[serde(default)]
    pub light: LightModeConfig,
    #[serde(default)]
    pub checkpoint: CheckpointConfig,
    #[serde(default)]
    pub attest: AttestConfig,
    #[serde(default)]
    pub trust: TrustConfig,
    #[serde(default)]
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub pid_file: PathBuf,
    pub repos_dir: PathBuf,
    pub repos_index: PathBuf,
    /// The repo an HTTP request targets when it omits `?repo=` and more than
    /// one is followed (display or canonical URI, e.g.
    /// `sbo+raw://avail:turing:506/`). Absent ⇒ such requests are a 400. Env
    /// override: `SBO_DEFAULT_REPO`.
    #[serde(default)]
    pub default_repo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientConfig {
    pub network: String,
    pub identity_file: Option<PathBuf>,
    pub http_port: u16,
    pub binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub endpoints: Vec<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurboDaConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    /// App ID associated with this API key (informational - determined by TurboDA)
    #[serde(default)]
    pub app_id: Option<u32>,
    /// Per-repo credentials for a daemon that follows several databases: a
    /// submission for a repo on `app_id` uses that entry's key; a repo with
    /// no entry falls back to the default key above only when the default
    /// `app_id` matches (or is unset). Overridable per app id at runtime with
    /// `SBO_TURBO_DA_API_KEY_<app_id>` (see `apply_env_overrides`).
    #[serde(default)]
    pub repos: Vec<TurboDaRepoConfig>,
}

/// One TurboDA credential, scoped to an Avail app id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurboDaRepoConfig {
    pub app_id: u32,
    pub api_key: String,
}

impl TurboDaConfig {
    /// The API key to submit with for `app_id` (`None` = the default target).
    pub fn api_key_for(&self, app_id: Option<u32>) -> Result<&str, String> {
        if let Some(id) = app_id {
            if let Some(r) = self.repos.iter().find(|r| r.app_id == id) {
                return Ok(&r.api_key);
            }
            if self.app_id.is_some_and(|d| d != id) {
                return Err(format!(
                    "no TurboDA credentials for app {id} (set [[turbo_da.repos]] or SBO_TURBO_DA_API_KEY_{id})"
                ));
            }
        }
        self.api_key
            .as_deref()
            .ok_or_else(|| "TurboDA API key not configured".to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertsConfig {
    pub webhook_url: Option<String>,
}

/// Prover configuration for ZK proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// Enable prover mode (also via --prover flag)
    #[serde(default)]
    pub enabled: bool,

    /// Blocks per proof batch (1 = every block)
    #[serde(default = "default_batch_size")]
    pub batch_size: u64,

    /// Receipt kind: composite, succinct, groth16
    #[serde(default = "default_receipt_kind")]
    pub receipt_kind: String,

    /// Use RISC0_DEV_MODE for testing (fake proofs)
    #[serde(default)]
    pub dev_mode: bool,
}

fn default_batch_size() -> u64 { 1 }
fn default_receipt_kind() -> String { "composite".to_string() }

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_size: default_batch_size(),
            receipt_kind: default_receipt_kind(),
            dev_mode: false,
        }
    }
}

/// Checkpoint + snapshot configuration (State Commitment fast-sync).
///
/// `enabled` turns on LOCAL checkpoint scheduling + snapshot generation + the
/// sync-point manifest (no key needed). `publish` additionally submits the
/// `checkpoint.v1` object ON-CHAIN, which requires `key_file` — a deliberate
/// deploy decision, kept off by default so on-chain signing is never auto-armed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Also publish the checkpoint object on-chain (requires `key_file`).
    #[serde(default)]
    pub publish: bool,
    /// Checkpoint-authority signing key (JSON). Required iff `publish=true`.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// Dual trigger: checkpoint when EITHER this many confirmed writes since the
    /// last checkpoint (excluding checkpoint objects themselves) ...
    #[serde(default = "default_every_writes")]
    pub every_writes: u64,
    /// ... OR this many DA blocks have elapsed, whichever comes first.
    #[serde(default = "default_every_blocks")]
    pub every_blocks: u64,
    /// Directory for snapshot files; defaults to `<repo state dir>/snapshots`.
    #[serde(default)]
    pub snapshots_dir: Option<PathBuf>,
}

fn default_every_writes() -> u64 { 100 }
fn default_every_blocks() -> u64 { 1000 }

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            publish: false,
            key_file: None,
            every_writes: default_every_writes(),
            every_blocks: default_every_blocks(),
            snapshots_dir: None,
        }
    }
}

/// Checkpoint-attestation producer configuration (State Commitment §Checkpoint
/// Attestations). When `enabled`, this node watches `/sys/checkpoints/` and, for
/// each checkpoint at a height it has INDEPENDENTLY reached, compares its own
/// recorded state root at that height to the checkpoint's; on match it posts a
/// `checkpoint-attestation.v1` under `/u/<attestor>/attestations/checkpoints/`.
///
/// This is orthogonal to `[checkpoint]`: a node can attest without publishing
/// checkpoints, and vice versa. Requires `key_file` (the attestor's signing key)
/// and `attestor` (the identity whose `/u/<attestor>/` namespace it writes to;
/// MUST be the resolved controller of that key so the owner grant matches).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Attestor signing key (JSON `{"secret_key":"<hex>"}`). Required iff `enabled`.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// The attestor identity — its `/u/<attestor>/` namespace receives the
    /// attestations. MUST be the controller of `key_file`'s key.
    #[serde(default)]
    pub attestor: Option<String>,
}

impl Default for AttestConfig {
    fn default() -> Self {
        Self { enabled: false, key_file: None, attestor: None }
    }
}

/// Trust policy for fast-sync clients (State Commitment §Bootstrap and Fast-Sync).
/// A snapshot root loaded during fast-sync is UNTRUSTED until `threshold` distinct
/// pinned attestor keys have signed a matching `(block, state_root)` claim on
/// chain, observed by walking forward from the snapshot height. Attestors are
/// pinned by PUBLIC KEY (`ed25519:<hex>`), never by name — on-chain name state is
/// itself untrusted before the anchor is verified, so trusting it is circular.
///
/// Empty `attestors` (the default) means no gating: fast-sync keeps the legacy
/// trust-the-serving-node behaviour, and a full-replay node is unaffected either
/// way. The checkpoint authority is not special — pin its key here like any other
/// attestor. For a threshold-2 web-of-trust, pin the `sys-checkpointer` key plus
/// an independent attestor key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Pinned attestor public keys, `ed25519:<hex>`.
    #[serde(default)]
    pub attestors: Vec<String>,
    /// Distinct pinned keys that must agree on the anchor root to trust it.
    #[serde(default)]
    pub threshold: usize,
    /// While a fast-sync anchor is unverified, stop tailing and error out after
    /// this many blocks past the anchor without reaching threshold (0 = never
    /// give up; keep waiting, gated). Reads stay refused throughout: this is
    /// the daemon's liveness fallback (State Commitment spec "bounded wait") --
    /// it reports trust not established and never degrades to a weaker policy
    /// or an older checkpoint.
    #[serde(default)]
    pub timeout_blocks: u64,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self { attestors: Vec::new(), threshold: 0, timeout_blocks: 0 }
    }
}

/// HTTP exposure (security audit 2026-11, Q15). `mode` defaults from the
/// bind address: a loopback bind runs the localhost convenience server
/// (open CORS, private-network header, no limits); any other bind is
/// `public` (origin allowlist, no private-network header, per-source limits,
/// `/v1/submit` gated on an allowlisted `Origin` or a bearer token).
/// Binding a routable address with `mode = "loopback"` is refused at start.
///
/// Env overrides (`apply_env_overrides`): `SBO_HTTP_BIND`, `SBO_HTTP_MODE`,
/// `SBO_HTTP_ALLOWED_ORIGINS` (comma-separated), `SBO_HTTP_BEARER_TOKENS`
/// (comma-separated; keeps secrets out of the committed config).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Listen address, `host:port`.
    #[serde(default = "default_http_bind")]
    pub bind: String,
    /// `loopback` | `public`; derived from `bind` when unset.
    #[serde(default)]
    pub mode: Option<crate::http::HttpMode>,
    /// Browser origins (`https://host[:port]`) CORS reflects and that may
    /// `POST /v1/submit`. Public mode only.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Bearer tokens admitting non-browser clients to `/v1/submit`
    /// (`Authorization: Bearer <token>`). Public mode only.
    #[serde(default)]
    pub bearer_tokens: Vec<String>,
    /// Per-source read budget (requests/minute, also the burst). Public mode only.
    #[serde(default = "default_reads_per_minute")]
    pub reads_per_minute: u32,
    /// Per-source `/v1/submit` budget (requests/minute, also the burst). Public mode only.
    #[serde(default = "default_spends_per_minute")]
    pub spends_per_minute: u32,
}

fn default_http_bind() -> String { "127.0.0.1:7890".to_string() }
fn default_reads_per_minute() -> u32 { crate::http::RateLimits::default().reads_per_minute }
fn default_spends_per_minute() -> u32 { crate::http::RateLimits::default().spends_per_minute }

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: default_http_bind(),
            mode: None,
            allowed_origins: Vec::new(),
            bearer_tokens: Vec::new(),
            reads_per_minute: default_reads_per_minute(),
            spends_per_minute: default_spends_per_minute(),
        }
    }
}

impl HttpConfig {
    /// The effective mode: explicit `mode`, else loopback iff `bind` names a
    /// loopback address. An unparseable bind (e.g. a hostname) is treated as
    /// public, the conservative choice.
    pub fn effective_mode(&self) -> crate::http::HttpMode {
        use crate::http::HttpMode;
        if let Some(m) = self.mode {
            return m;
        }
        match self.bind.parse::<std::net::SocketAddr>() {
            Ok(a) if a.ip().is_loopback() => HttpMode::Loopback,
            _ => HttpMode::Public,
        }
    }

    /// Resolve into router options, refusing the one unsafe combination: a
    /// non-loopback bind in loopback mode (open CORS + private-network header
    /// on a routable address — the W5-1 shape).
    pub fn resolve(&self) -> crate::Result<crate::http::HttpOptions> {
        use crate::http::{HttpMode, HttpOptions, RateLimits};
        let mode = self.effective_mode();
        let bind_is_loopback = matches!(
            self.bind.parse::<std::net::SocketAddr>(),
            Ok(a) if a.ip().is_loopback()
        );
        if mode == HttpMode::Loopback && !bind_is_loopback {
            return Err(crate::DaemonError::Config(format!(
                "[http] mode = \"loopback\" but bind {} is not a loopback address; \
                 set mode = \"public\" (with allowed_origins / bearer_tokens) or bind 127.0.0.1",
                self.bind
            )));
        }
        let mut opts = match mode {
            HttpMode::Loopback => HttpOptions::loopback(),
            HttpMode::Public => HttpOptions::public(
                self.allowed_origins.iter().map(|o| o.trim().trim_end_matches('/').to_string()).filter(|o| !o.is_empty()).collect(),
                self.bearer_tokens.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
            ),
        };
        opts.limits = RateLimits {
            reads_per_minute: self.reads_per_minute,
            spends_per_minute: self.spends_per_minute,
        };
        Ok(opts)
    }
}

/// Light client mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightModeConfig {
    /// Enable light client mode (also via --light flag)
    #[serde(default)]
    pub enabled: bool,

    /// Verify object proofs when requested
    #[serde(default = "default_true")]
    pub verify_objects: bool,
}

fn default_true() -> bool { true }

impl Default for LightModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_objects: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let sbo_dir = dirs::home_dir()
            .map(|h| h.join(".sbo"))
            .unwrap_or_else(|| PathBuf::from(".sbo"));

        Self {
            daemon: DaemonConfig {
                socket_path: sbo_dir.join("daemon.sock"),
                pid_file: sbo_dir.join("daemon.pid"),
                repos_dir: sbo_dir.join("repos"),
                repos_index: sbo_dir.join("repos.json"),
                default_repo: None,
            },
            light_client: LightClientConfig {
                network: "turing".to_string(),
                identity_file: None,
                http_port: 7007,
                binary_path: None,
            },
            rpc: RpcConfig {
                // avail-rust uses HTTP JSON-RPC, not WebSocket
                endpoints: vec!["https://turing-rpc.avail.so/rpc".to_string()],
                timeout_secs: 30,
            },
            turbo_da: TurboDaConfig {
                endpoint: "https://staging.turbo-api.availproject.org".to_string(),
                api_key: None,
                app_id: None,
                repos: Vec::new(),
            },
            alerts: AlertsConfig::default(),
            prover: ProverConfig::default(),
            light: LightModeConfig::default(),
            checkpoint: CheckpointConfig::default(),
            attest: AttestConfig::default(),
            trust: TrustConfig::default(),
            http: HttpConfig::default(),
        }
    }
}

impl Config {
    /// Load config from file, or create default
    pub fn load(path: &Path) -> crate::Result<Self> {
        let mut config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let parsed = toml::from_str::<Self>(&content)
                .map_err(|e| crate::DaemonError::Config(format!("Failed to parse config: {}", e)))?;
            // W7-5: the file is where the TurboDA key goes. A world/group
            // readable config that actually holds a credential is refused; a
            // credential-free one (the container image's, which takes its key
            // from the environment) only warns.
            if let Some(mode) = file_mode(path) {
                if mode & 0o077 != 0 {
                    let holds_secret = parsed.turbo_da.api_key.is_some()
                        || !parsed.turbo_da.repos.is_empty()
                        || !parsed.http.bearer_tokens.is_empty();
                    if holds_secret {
                        return Err(crate::DaemonError::Config(format!(
                            "{} is mode {:o} but holds credentials; chmod 600 it",
                            path.display(),
                            mode
                        )));
                    }
                    tracing::warn!(
                        "{} is mode {:o}; chmod 600 it before putting an api_key in it",
                        path.display(),
                        mode
                    );
                }
            }
            parsed
        } else {
            Self::default()
        };
        config.apply_env_overrides();
        Ok(config)
    }

    /// Assert that a secret-key file (`[checkpoint] key_file`, `[attest]
    /// key_file`) is owner-only before it is read (W7-14).
    pub fn assert_private_key_file(path: &Path) -> crate::Result<()> {
        match file_mode(path) {
            Some(mode) if mode & 0o077 != 0 => Err(crate::DaemonError::Config(format!(
                "key file {} is mode {:o}; it must be 0600",
                path.display(),
                mode
            ))),
            _ => Ok(()),
        }
    }

    /// Overlay secrets/overrides from the environment so they need not live in a
    /// committed config file (the repo is public). `SBO_TURBO_DA_API_KEY` sets
    /// the TurboDA submit key (provided via `dokku config:set` in prod).
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SBO_DEFAULT_REPO") {
            let v = v.trim().to_string();
            self.daemon.default_repo = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(key) = std::env::var("SBO_TURBO_DA_API_KEY") {
            if !key.is_empty() {
                self.turbo_da.api_key = Some(key);
            }
        }
        // Per-app credentials: SBO_TURBO_DA_API_KEY_<app_id>=<key> (one per
        // followed database whose writes this node submits).
        for (k, v) in std::env::vars() {
            let Some(id) = k.strip_prefix("SBO_TURBO_DA_API_KEY_") else { continue };
            let (Ok(app_id), false) = (id.parse::<u32>(), v.is_empty()) else { continue };
            match self.turbo_da.repos.iter_mut().find(|r| r.app_id == app_id) {
                Some(r) => r.api_key = v,
                None => self.turbo_da.repos.push(TurboDaRepoConfig { app_id, api_key: v }),
            }
        }
        // Checkpoint/snapshot cadence — overridable at runtime so it can be tuned
        // (e.g. a faster cadence for testing) via `dokku config:set` + restart,
        // without rebuilding the image.
        // HTTP exposure (Q15). SBO_HTTP_BIND predates [http] and keeps working;
        // the allowlist and bearer tokens are env-settable so the public
        // deploy config stays secret-free.
        if let Ok(v) = std::env::var("SBO_HTTP_BIND") {
            if !v.trim().is_empty() {
                self.http.bind = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("SBO_HTTP_MODE") {
            self.http.mode = match v.trim().to_ascii_lowercase().as_str() {
                "loopback" => Some(crate::http::HttpMode::Loopback),
                "public" => Some(crate::http::HttpMode::Public),
                _ => self.http.mode,
            };
        }
        let split = |v: String| -> Vec<String> {
            v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        };
        if let Ok(v) = std::env::var("SBO_HTTP_ALLOWED_ORIGINS") {
            self.http.allowed_origins = split(v);
        }
        if let Ok(v) = std::env::var("SBO_HTTP_BEARER_TOKENS") {
            self.http.bearer_tokens = split(v);
        }
        if let Ok(v) = std::env::var("SBO_CHECKPOINT_ENABLED") {
            self.checkpoint.enabled = matches!(v.trim(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("SBO_CHECKPOINT_EVERY_WRITES") {
            if let Ok(n) = v.trim().parse::<u64>() {
                self.checkpoint.every_writes = n;
            }
        }
        if let Ok(v) = std::env::var("SBO_CHECKPOINT_EVERY_BLOCKS") {
            if let Ok(n) = v.trim().parse::<u64>() {
                self.checkpoint.every_blocks = n;
            }
        }
    }

    /// Save config to file (owner-only: it may hold the TurboDA key).
    pub fn save(&self, path: &Path) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::DaemonError::Config(format!("Failed to serialize config: {}", e)))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_private(path, content.as_bytes())?;
        Ok(())
    }

    /// Save a well-documented sample config to file
    pub fn save_sample(path: &Path) -> crate::Result<()> {
        let sbo_dir = Self::sbo_dir();
        let content = format!(r#"# SBO Daemon Configuration
# ========================
#
# This file configures the SBO daemon. Edit as needed.
# Documentation: https://docs.sbo.dev/daemon/config

# ------------------------------------------------------------------------------
# Daemon Settings
# ------------------------------------------------------------------------------
[daemon]
# Unix socket for CLI-daemon communication
socket_path = "{sbo_dir}/daemon.sock"

# PID file for daemon process tracking
pid_file = "{sbo_dir}/daemon.pid"

# Directory where repository data is stored
repos_dir = "{sbo_dir}/repos"

# When several databases are followed, HTTP requests that omit ?repo= target
# this one (display or canonical URI). Unset ⇒ such requests get a 400.
# default_repo = "sbo+raw://avail:turing:506/"

# JSON file tracking configured repositories
repos_index = "{sbo_dir}/repos.json"

# ------------------------------------------------------------------------------
# Light Client Settings (Avail Light Client)
# ------------------------------------------------------------------------------
[light_client]
# Network to connect to: "mainnet" or "turing" (testnet)
network = "turing"

# Optional: Path to light client identity file for persistent peer ID
# identity_file = "{sbo_dir}/identity.toml"

# HTTP port for light client API (used internally)
http_port = 7007

# Optional: Path to avail-light binary (auto-detected if not set)
# binary_path = "/usr/local/bin/avail-light"

# ------------------------------------------------------------------------------
# RPC Settings (Avail Full Node)
# ------------------------------------------------------------------------------
[rpc]
# RPC endpoints to query block data from
# Multiple endpoints provide fallback redundancy
endpoints = [
    "https://turing-rpc.avail.so/rpc",
    # "https://avail-turing.public.blastapi.io",
]

# Request timeout in seconds
timeout_secs = 30

# ------------------------------------------------------------------------------
# TurboDA Settings (Data Submission)
# ------------------------------------------------------------------------------
[turbo_da]
# TurboDA API endpoint
# Staging (testnet): https://staging.turbo-api.availproject.org
# Production:        https://turbo-api.availproject.org
endpoint = "https://staging.turbo-api.availproject.org"

# Your TurboDA API key (REQUIRED for submitting data)
# Get one at: https://turbo.availproject.org
# api_key = "your-api-key-here"

# App ID associated with your API key (informational only)
# app_id = 506
#
# Per-repo credentials when this node follows (and submits to) several
# databases — env override: SBO_TURBO_DA_API_KEY_<app_id>=<key>.
# [[turbo_da.repos]]
# app_id = 530
# api_key = "..."

# ------------------------------------------------------------------------------
# HTTP Settings (browser read + submit API)
# ------------------------------------------------------------------------------
[http]
# Listen address. A loopback bind runs the localhost convenience server (open
# CORS, private-network header, no limits). Any other bind is "public" mode:
# CORS reflects only allowed_origins, no private-network header, per-source
# rate limits, and /v1/submit is admitted only for an allowed origin or a
# bearer token. Env override: SBO_HTTP_BIND.
bind = "127.0.0.1:7890"

# Force the mode ("loopback" | "public"); derived from bind when unset.
# A non-loopback bind with mode = "loopback" is refused at start.
# mode = "public"

# Public mode: browser origins that may read with CORS and POST /v1/submit.
# Env override: SBO_HTTP_ALLOWED_ORIGINS="https://a.example,https://b.example"
# allowed_origins = ["https://mingo.place"]

# Public mode: bearer tokens for non-browser clients of /v1/submit
# (Authorization: Bearer <token>). Prefer the env override so the secret
# stays out of this file: SBO_HTTP_BEARER_TOKENS="tok1,tok2"
# bearer_tokens = []

# Public mode: per-source budgets (requests per minute; also the burst size).
# reads_per_minute = 600
# spends_per_minute = 60

# ------------------------------------------------------------------------------
# Alerts Settings (Optional)
# ------------------------------------------------------------------------------
[alerts]
# Webhook URL for error notifications (Discord, Slack, etc.)
# webhook_url = "https://discord.com/api/webhooks/..."

# ------------------------------------------------------------------------------
# Prover Settings (ZK Proof Generation)
# ------------------------------------------------------------------------------
[prover]
# Enable prover mode to generate ZK proofs for state transitions
# Can also be enabled with: sbo-daemon start --prover
enabled = false

# Number of blocks to batch into a single proof
# 1 = proof per block, higher = more efficient but delayed
batch_size = 1

# Proof type to generate:
# - "composite": Fast, large proofs (~1MB) - good for testing
# - "succinct":  Slower, smaller proofs (~200KB)
# - "groth16":   Slowest, tiny proofs (~256 bytes) - for on-chain verification
receipt_kind = "composite"

# Development mode: generate fake proofs instantly (for testing only!)
dev_mode = false

# ------------------------------------------------------------------------------
# Light Mode Settings (Proof Verification Only)
# ------------------------------------------------------------------------------
[light]
# Enable light mode: verify proofs instead of executing state transitions
# Mutually exclusive with prover mode
# Can also be enabled with: sbo-daemon start --light
enabled = false

# Verify object proofs when they are requested
verify_objects = true
"#, sbo_dir = sbo_dir.display());

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_private(path, content.as_bytes())?;
        Ok(())
    }

    /// Get the base SBO directory
    pub fn sbo_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".sbo"))
            .unwrap_or_else(|| PathBuf::from(".sbo"))
    }

    /// Get the config file path
    pub fn config_path() -> PathBuf {
        Self::sbo_dir().join("config.toml")
    }
}

/// The file's permission bits, or `None` off unix / when unreadable.
fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Write `content` to `path` created (or truncated) owner-only, never
/// following a symlink at `path`.
pub fn write_private(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        // The mode above applies only on create; an existing file keeps its
        // bits, so pin them.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(content)
}

#[cfg(test)]
mod turbo_credentials_tests {
    use super::*;

    fn cfg(default_app: Option<u32>) -> TurboDaConfig {
        TurboDaConfig {
            endpoint: "x".into(),
            api_key: Some("default-key".into()),
            app_id: default_app,
            repos: vec![TurboDaRepoConfig { app_id: 530, api_key: "key-530".into() }],
        }
    }

    #[test]
    fn selects_the_repo_key_then_the_default_only_when_it_matches() {
        let c = cfg(Some(506));
        assert_eq!(c.api_key_for(Some(530)).unwrap(), "key-530");
        assert_eq!(c.api_key_for(Some(506)).unwrap(), "default-key");
        assert_eq!(c.api_key_for(None).unwrap(), "default-key");
        assert!(c.api_key_for(Some(999)).unwrap_err().contains("no TurboDA credentials for app 999"));
        // An unpinned default key serves any app without its own entry.
        assert_eq!(cfg(None).api_key_for(Some(999)).unwrap(), "default-key");
    }

    #[test]
    fn env_override_adds_or_replaces_a_repo_key() {
        std::env::set_var("SBO_TURBO_DA_API_KEY_530", "env-530");
        std::env::set_var("SBO_TURBO_DA_API_KEY_777", "env-777");
        let mut c = Config::default();
        c.turbo_da = cfg(Some(506));
        c.apply_env_overrides();
        std::env::remove_var("SBO_TURBO_DA_API_KEY_530");
        std::env::remove_var("SBO_TURBO_DA_API_KEY_777");
        assert_eq!(c.turbo_da.api_key_for(Some(530)).unwrap(), "env-530");
        assert_eq!(c.turbo_da.api_key_for(Some(777)).unwrap(), "env-777");
    }
}

#[cfg(test)]
mod http_exposure_tests {
    use super::*;
    use crate::http::HttpMode;

    #[test]
    fn mode_defaults_from_the_bind_address() {
        let mut c = HttpConfig::default();
        assert_eq!(c.effective_mode(), HttpMode::Loopback);
        c.bind = "0.0.0.0:5000".into();
        assert_eq!(c.effective_mode(), HttpMode::Public);
        c.bind = "[::1]:5000".into();
        assert_eq!(c.effective_mode(), HttpMode::Loopback);
        c.bind = "[::]:5000".into();
        assert_eq!(c.effective_mode(), HttpMode::Public);
    }

    #[test]
    fn loopback_mode_on_a_routable_bind_is_refused() {
        let c = HttpConfig { bind: "0.0.0.0:5000".into(), mode: Some(HttpMode::Loopback), ..Default::default() };
        let err = c.resolve().unwrap_err().to_string();
        assert!(err.contains("not a loopback address"), "{err}");
    }

    #[test]
    fn public_mode_carries_the_allowlist_and_limits() {
        let c = HttpConfig {
            bind: "0.0.0.0:5000".into(),
            allowed_origins: vec!["https://mingo.place/".into(), " ".into()],
            bearer_tokens: vec!["tok".into()],
            reads_per_minute: 10,
            spends_per_minute: 2,
            ..Default::default()
        };
        let o = c.resolve().unwrap();
        assert_eq!(o.mode, HttpMode::Public);
        assert_eq!(o.allowed_origins, vec!["https://mingo.place".to_string()]);
        assert_eq!(o.bearer_tokens, vec!["tok".to_string()]);
        assert_eq!(o.limits.reads_per_minute, 10);
        assert_eq!(o.limits.spends_per_minute, 2);
    }

    #[test]
    fn env_overrides_set_bind_mode_origins_and_tokens() {
        std::env::set_var("SBO_HTTP_BIND", "0.0.0.0:5000");
        std::env::set_var("SBO_HTTP_MODE", "public");
        std::env::set_var("SBO_HTTP_ALLOWED_ORIGINS", "https://a.example, https://b.example");
        std::env::set_var("SBO_HTTP_BEARER_TOKENS", "t1,t2");
        let mut c = Config::default();
        c.apply_env_overrides();
        for k in ["SBO_HTTP_BIND", "SBO_HTTP_MODE", "SBO_HTTP_ALLOWED_ORIGINS", "SBO_HTTP_BEARER_TOKENS"] {
            std::env::remove_var(k);
        }
        assert_eq!(c.http.bind, "0.0.0.0:5000");
        assert_eq!(c.http.mode, Some(HttpMode::Public));
        assert_eq!(c.http.allowed_origins, vec!["https://a.example", "https://b.example"]);
        assert_eq!(c.http.bearer_tokens, vec!["t1", "t2"]);
    }
}
