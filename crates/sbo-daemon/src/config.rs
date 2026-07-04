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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub pid_file: PathBuf,
    pub repos_dir: PathBuf,
    pub repos_index: PathBuf,
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
            },
            alerts: AlertsConfig::default(),
            prover: ProverConfig::default(),
            light: LightModeConfig::default(),
            checkpoint: CheckpointConfig::default(),
            attest: AttestConfig::default(),
        }
    }
}

impl Config {
    /// Load config from file, or create default
    pub fn load(path: &Path) -> crate::Result<Self> {
        let mut config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str::<Self>(&content)
                .map_err(|e| crate::DaemonError::Config(format!("Failed to parse config: {}", e)))?
        } else {
            Self::default()
        };
        config.apply_env_overrides();
        Ok(config)
    }

    /// Overlay secrets/overrides from the environment so they need not live in a
    /// committed config file (the repo is public). `SBO_TURBO_DA_API_KEY` sets
    /// the TurboDA submit key (provided via `dokku config:set` in prod).
    fn apply_env_overrides(&mut self) {
        if let Ok(key) = std::env::var("SBO_TURBO_DA_API_KEY") {
            if !key.is_empty() {
                self.turbo_da.api_key = Some(key);
            }
        }
        // Checkpoint/snapshot cadence — overridable at runtime so it can be tuned
        // (e.g. a faster cadence for testing) via `dokku config:set` + restart,
        // without rebuilding the image.
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

    /// Save config to file
    pub fn save(&self, path: &Path) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::DaemonError::Config(format!("Failed to serialize config: {}", e)))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
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
        std::fs::write(path, content)?;
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
