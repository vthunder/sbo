# ZK Testing Infrastructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

This plan implements the testing infrastructure for ZK validity proofs, enabling full node verification and light client sync. See `2024-12-14-zk-testing-infrastructure-design.md` for the design document.

**Tech Stack:** risc0-zkvm, sbo-daemon, sbo-core, RocksDB, Avail DA

---

## Phase 1: Core Infrastructure

### Task 1.1: Add SBOP Message Types

**Files:**
- Create: `reference_impl/sbo-core/src/proof/mod.rs`
- Create: `reference_impl/sbo-core/src/proof/sbop.rs`
- Modify: `reference_impl/sbo-core/src/lib.rs`

**Step 1: Create proof module**

Create `reference_impl/sbo-core/src/proof/mod.rs`:

```rust
//! ZK proof message types (SBOP, SBOQ)

mod sbop;

pub use sbop::{SbopMessage, parse_sbop, serialize_sbop, SbopError};
```

**Step 2: Create SBOP parser**

Create `reference_impl/sbo-core/src/proof/sbop.rs`:

```rust
//! SBOP (SBO Proof) message format
//!
//! Format:
//! ```text
//! SBOP-Version: 0.1
//! Block-From: 1
//! Block-To: 100
//! Receipt-Kind: succinct
//! Receipt-Length: 45678
//! Content-Encoding: base64
//!
//! <base64 encoded receipt bytes>
//! ```

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SbopError {
    #[error("Missing header: {0}")]
    MissingHeader(String),
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("Invalid base64: {0}")]
    InvalidBase64(String),
    #[error("Receipt length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

/// Parsed SBOP message
#[derive(Debug, Clone)]
pub struct SbopMessage {
    pub version: String,
    pub block_from: u64,
    pub block_to: u64,
    pub receipt_kind: String,
    pub receipt_bytes: Vec<u8>,
}

/// Check if bytes start with SBOP-Version header
pub fn is_sbop_message(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SBOP-Version:")
}

/// Parse SBOP message from bytes
pub fn parse_sbop(bytes: &[u8]) -> Result<SbopMessage, SbopError> {
    use std::collections::HashMap;
    use base64::{Engine, engine::general_purpose::STANDARD};

    // Split headers and payload at blank line
    let mut pos = 0;
    let mut headers: HashMap<String, String> = HashMap::new();

    while pos < bytes.len() {
        let line_end = bytes[pos..].iter().position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(bytes.len());

        let line = &bytes[pos..line_end];

        if line.is_empty() {
            pos = line_end + 1;
            break;
        }

        let line_str = std::str::from_utf8(line)
            .map_err(|_| SbopError::InvalidHeader("Invalid UTF-8".to_string()))?;

        let colon_pos = line_str.find(": ")
            .ok_or_else(|| SbopError::InvalidHeader("Missing ': ' separator".to_string()))?;

        let name = line_str[..colon_pos].to_string();
        let value = line_str[colon_pos + 2..].to_string();
        headers.insert(name, value);

        pos = line_end + 1;
    }

    // Parse required headers
    let version = headers.get("SBOP-Version")
        .ok_or_else(|| SbopError::MissingHeader("SBOP-Version".to_string()))?
        .clone();

    if !version.starts_with("0.") {
        return Err(SbopError::UnsupportedVersion(version));
    }

    let block_from: u64 = headers.get("Block-From")
        .ok_or_else(|| SbopError::MissingHeader("Block-From".to_string()))?
        .parse()
        .map_err(|_| SbopError::InvalidHeader("Block-From not a number".to_string()))?;

    let block_to: u64 = headers.get("Block-To")
        .ok_or_else(|| SbopError::MissingHeader("Block-To".to_string()))?
        .parse()
        .map_err(|_| SbopError::InvalidHeader("Block-To not a number".to_string()))?;

    let receipt_kind = headers.get("Receipt-Kind")
        .ok_or_else(|| SbopError::MissingHeader("Receipt-Kind".to_string()))?
        .clone();

    let receipt_length: usize = headers.get("Receipt-Length")
        .ok_or_else(|| SbopError::MissingHeader("Receipt-Length".to_string()))?
        .parse()
        .map_err(|_| SbopError::InvalidHeader("Receipt-Length not a number".to_string()))?;

    // Payload is base64-encoded receipt
    let payload = &bytes[pos..];
    let payload_str = std::str::from_utf8(payload)
        .map_err(|_| SbopError::InvalidBase64("Not valid UTF-8".to_string()))?
        .trim();

    let receipt_bytes = STANDARD.decode(payload_str)
        .map_err(|e| SbopError::InvalidBase64(e.to_string()))?;

    if receipt_bytes.len() != receipt_length {
        return Err(SbopError::LengthMismatch {
            expected: receipt_length,
            actual: receipt_bytes.len(),
        });
    }

    Ok(SbopMessage {
        version,
        block_from,
        block_to,
        receipt_kind,
        receipt_bytes,
    })
}

/// Serialize SBOP message to bytes
pub fn serialize_sbop(msg: &SbopMessage) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let encoded = STANDARD.encode(&msg.receipt_bytes);

    format!(
        "SBOP-Version: {}\n\
         Block-From: {}\n\
         Block-To: {}\n\
         Receipt-Kind: {}\n\
         Receipt-Length: {}\n\
         Content-Encoding: base64\n\
         \n\
         {}",
        msg.version,
        msg.block_from,
        msg.block_to,
        msg.receipt_kind,
        msg.receipt_bytes.len(),
        encoded
    ).into_bytes()
}
```

**Step 3: Export from sbo-core**

In `reference_impl/sbo-core/src/lib.rs`, add:

```rust
pub mod proof;
pub use proof::{SbopMessage, parse_sbop, serialize_sbop, is_sbop_message, SbopError};
```

**Step 4: Add base64 dependency**

In `reference_impl/sbo-core/Cargo.toml`, add to dependencies:

```toml
base64 = "0.22"
```

**Step 5: Verify compilation**

Run: `cargo check -p sbo-core`
Expected: Compiles successfully

**Step 6: Add unit tests**

In `reference_impl/sbo-core/src/proof/sbop.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let msg = SbopMessage {
            version: "0.1".to_string(),
            block_from: 1,
            block_to: 100,
            receipt_kind: "succinct".to_string(),
            receipt_bytes: vec![1, 2, 3, 4, 5],
        };

        let bytes = serialize_sbop(&msg);
        let parsed = parse_sbop(&bytes).unwrap();

        assert_eq!(parsed.version, msg.version);
        assert_eq!(parsed.block_from, msg.block_from);
        assert_eq!(parsed.block_to, msg.block_to);
        assert_eq!(parsed.receipt_kind, msg.receipt_kind);
        assert_eq!(parsed.receipt_bytes, msg.receipt_bytes);
    }

    #[test]
    fn test_is_sbop() {
        assert!(is_sbop_message(b"SBOP-Version: 0.1\n"));
        assert!(!is_sbop_message(b"SBO-Version: 0.5\n"));
    }
}
```

**Step 7: Commit**

```bash
git add reference_impl/sbo-core/src/proof/
git add reference_impl/sbo-core/src/lib.rs
git add reference_impl/sbo-core/Cargo.toml
git commit -m "feat(sbo-core): add SBOP message format for proof transmission"
```

---

### Task 1.2: Add State Root Tracking to StateDb

**Files:**
- Modify: `reference_impl/sbo-core/src/state/db.rs`

**Step 1: Add state_roots column family**

In `db.rs`, add the constant:

```rust
const CF_STATE_ROOTS: &str = "state_roots";
```

Update the `open` function to include the new CF:

```rust
let cfs = vec![
    rocksdb::ColumnFamilyDescriptor::new(CF_OBJECTS, rocksdb::Options::default()),
    rocksdb::ColumnFamilyDescriptor::new(CF_BY_OWNER, rocksdb::Options::default()),
    rocksdb::ColumnFamilyDescriptor::new(CF_POLICIES, rocksdb::Options::default()),
    rocksdb::ColumnFamilyDescriptor::new(CF_NAMES, rocksdb::Options::default()),
    rocksdb::ColumnFamilyDescriptor::new(CF_META, rocksdb::Options::default()),
    rocksdb::ColumnFamilyDescriptor::new(CF_STATE_ROOTS, rocksdb::Options::default()),
];
```

**Step 2: Add state root methods**

Add these methods to `impl StateDb`:

```rust
/// Record the state root after processing a block
pub fn record_state_root(&self, block: u64, state_root: [u8; 32]) -> Result<(), DbError> {
    let cf = self.db.cf_handle(CF_STATE_ROOTS)
        .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

    self.db.put_cf(&cf, &block.to_be_bytes(), &state_root)
        .map_err(|e| DbError::RocksDb(e.to_string()))
}

/// Get the state root at a specific block
pub fn get_state_root_at_block(&self, block: u64) -> Result<Option<[u8; 32]>, DbError> {
    let cf = self.db.cf_handle(CF_STATE_ROOTS)
        .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

    match self.db.get_cf(&cf, &block.to_be_bytes()) {
        Ok(Some(bytes)) => {
            let root: [u8; 32] = bytes.try_into()
                .map_err(|_| DbError::RocksDb("Invalid state root length".to_string()))?;
            Ok(Some(root))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(DbError::RocksDb(e.to_string())),
    }
}

/// Get the latest recorded state root and its block number
pub fn get_latest_state_root(&self) -> Result<Option<(u64, [u8; 32])>, DbError> {
    let cf = self.db.cf_handle(CF_STATE_ROOTS)
        .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

    // Iterate in reverse to find latest
    let mut iter = self.db.raw_iterator_cf(&cf);
    iter.seek_to_last();

    if iter.valid() {
        if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
            let block = u64::from_be_bytes(key.try_into()
                .map_err(|_| DbError::RocksDb("Invalid block key".to_string()))?);
            let root: [u8; 32] = value.try_into()
                .map_err(|_| DbError::RocksDb("Invalid state root".to_string()))?;
            return Ok(Some((block, root)));
        }
    }

    Ok(None)
}
```

**Step 3: Verify compilation**

Run: `cargo check -p sbo-core`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-core/src/state/db.rs
git commit -m "feat(sbo-core): add state root tracking per block in StateDb"
```

---

### Task 1.3: Compute Transition State Root in Sync Engine

**Files:**
- Modify: `reference_impl/sbo-daemon/src/sync.rs`

**Step 1: Add state root computation**

Add helper function for computing transition root:

```rust
use sha2::{Sha256, Digest};

/// Compute transition state root: sha256(prev_root || actions_data)
fn compute_transition_root(prev_root: [u8; 32], actions_data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&prev_root);
    hasher.update(actions_data);
    hasher.finalize().into()
}
```

**Step 2: Update process_block to track state**

In `process_block`, after processing all transactions for a block, add:

```rust
// After processing all transactions, compute and record state root
// Collect all valid actions for this block
let mut block_actions: Vec<u8> = Vec::new();
// ... serialize valid messages into block_actions ...

// Get previous state root (or zeros for genesis)
let prev_root = match block_number {
    0 => [0u8; 32],
    _ => {
        // Get from StateDb
        let uri = /* repo URI */;
        if let Some(db) = self.state_dbs.get(&uri) {
            db.get_state_root_at_block(block_number - 1)?
                .unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        }
    }
};

let new_root = compute_transition_root(prev_root, &block_actions);

// Record in StateDb
if let Some(db) = self.state_dbs.get(&uri) {
    db.record_state_root(block_number, new_root)?;
}
```

**Note:** This is a simplified transition root. Phase 4 will upgrade to merkle state root.

**Step 3: Add sha2 dependency**

In `reference_impl/sbo-daemon/Cargo.toml`:

```toml
sha2 = "0.10"
```

**Step 4: Verify compilation**

Run: `cargo check -p sbo-daemon`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add reference_impl/sbo-daemon/
git commit -m "feat(sbo-daemon): compute and record transition state roots"
```

---

## Phase 2: Prover Daemon

### Task 2.1: Add Prover Config

**Files:**
- Modify: `reference_impl/sbo-daemon/src/config.rs`

**Step 1: Add prover configuration**

Add to config structs:

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProverConfig {
    /// Enable prover mode
    #[serde(default)]
    pub enabled: bool,

    /// Blocks per proof batch (1 = every block)
    #[serde(default = "default_batch_size")]
    pub batch_size: u64,

    /// Receipt kind: composite, succinct, groth16
    #[serde(default = "default_receipt_kind")]
    pub receipt_kind: String,

    /// Use RISC0_DEV_MODE for testing
    #[serde(default)]
    pub dev_mode: bool,
}

fn default_batch_size() -> u64 { 1 }
fn default_receipt_kind() -> String { "composite".to_string() }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    // ... existing fields ...

    #[serde(default)]
    pub prover: ProverConfig,
}
```

**Step 2: Verify compilation**

Run: `cargo check -p sbo-daemon`

**Step 3: Commit**

```bash
git add reference_impl/sbo-daemon/src/config.rs
git commit -m "feat(sbo-daemon): add prover configuration"
```

---

### Task 2.2: Add --prover CLI Flag

**Files:**
- Modify: `reference_impl/sbo-daemon/src/main.rs` or CLI module

**Step 1: Add CLI flag**

Add to daemon start command:

```rust
#[derive(Parser)]
struct StartCmd {
    /// Enable prover mode
    #[arg(long)]
    prover: bool,
    // ... existing args ...
}
```

**Step 2: Pass flag to daemon**

When starting, check flag and set config:

```rust
if args.prover {
    config.prover.enabled = true;
}
```

**Step 3: Verify compilation**

Run: `cargo check -p sbo-daemon`

**Step 4: Commit**

```bash
git add reference_impl/sbo-daemon/
git commit -m "feat(sbo-daemon): add --prover CLI flag"
```

---

### Task 2.3: Create Prover Module

**Files:**
- Create: `reference_impl/sbo-daemon/src/prover.rs`

**Step 1: Create prover module**

```rust
//! Proof generation for blocks

use crate::config::ProverConfig;
use sbo_core::proof::{SbopMessage, serialize_sbop};
use std::path::PathBuf;

pub struct BlockProver {
    config: ProverConfig,
    proof_dir: PathBuf,
}

impl BlockProver {
    pub fn new(config: ProverConfig) -> Self {
        let proof_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sbo")
            .join("proofs");

        Self { config, proof_dir }
    }

    /// Generate proof for a block range
    pub fn prove_block_range(
        &self,
        block_from: u64,
        block_to: u64,
        prev_state_root: [u8; 32],
        actions_data: Vec<u8>,
        prev_receipt: Option<&[u8]>,
    ) -> Result<SbopMessage, ProverError> {
        use sbo_zkvm::{BlockProofInput, prove_block, ReceiptKind};

        // Build input
        let input = BlockProofInput {
            prev_state_root,
            block_number: block_to,
            block_hash: [0u8; 32], // TODO: Get from block data
            parent_hash: [0u8; 32],
            actions_data,
            prev_journal: None,
            prev_receipt_bytes: prev_receipt.map(|b| b.to_vec()),
            data_proof: None,
            row_commitments: Vec::new(),
            cell_proofs: Vec::new(),
            grid_cols: 256,
        };

        // Generate proof
        let receipt = prove_block(input, prev_receipt)
            .map_err(|e| ProverError::ProofFailed(e.to_string()))?;

        // Build SBOP message
        Ok(SbopMessage {
            version: "0.1".to_string(),
            block_from,
            block_to,
            receipt_kind: format!("{:?}", receipt.kind).to_lowercase(),
            receipt_bytes: receipt.receipt_bytes,
        })
    }

    /// Save proof to local storage
    pub fn save_proof(&self, repo: &str, msg: &SbopMessage) -> Result<PathBuf, ProverError> {
        let dir = self.proof_dir.join(repo);
        std::fs::create_dir_all(&dir)?;

        let filename = format!("{}-{}.sbop", msg.block_from, msg.block_to);
        let path = dir.join(filename);

        std::fs::write(&path, serialize_sbop(msg))?;
        Ok(path)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

**Step 2: Export module**

In `reference_impl/sbo-daemon/src/lib.rs`:

```rust
#[cfg(feature = "prover")]
pub mod prover;
```

**Step 3: Add feature flag to Cargo.toml**

```toml
[features]
default = []
prover = ["sbo-zkvm/prove"]
```

**Step 4: Verify compilation**

Run: `cargo check -p sbo-daemon --features prover`

**Step 5: Commit**

```bash
git add reference_impl/sbo-daemon/
git commit -m "feat(sbo-daemon): add BlockProver for proof generation"
```

---

### Task 2.4: Integrate Prover into Sync Loop

**Files:**
- Modify: `reference_impl/sbo-daemon/src/sync.rs`

**Step 1: Add prover to SyncEngine**

```rust
pub struct SyncEngine {
    // ... existing fields ...
    #[cfg(feature = "prover")]
    prover: Option<crate::prover::BlockProver>,
}
```

**Step 2: Update process_block for proof generation**

After recording state root, if prover is enabled:

```rust
#[cfg(feature = "prover")]
if let Some(ref prover) = self.prover {
    if block_number % self.prover_batch_size == 0 {
        let proof = prover.prove_block_range(
            block_from,
            block_number,
            prev_root,
            block_actions,
            prev_receipt.as_deref(),
        )?;

        // Save locally
        let path = prover.save_proof(&repo_uri, &proof)?;
        tracing::info!("Generated proof for blocks {}-{}: {}",
            proof.block_from, proof.block_to, path.display());

        // TODO: Submit to Avail in Task 2.5
    }
}
```

**Step 3: Verify compilation**

Run: `cargo check -p sbo-daemon --features prover`

**Step 4: Commit**

```bash
git add reference_impl/sbo-daemon/src/sync.rs
git commit -m "feat(sbo-daemon): integrate prover into sync loop"
```

---

### Task 2.5: Submit Proofs to Avail

**Files:**
- Modify: `reference_impl/sbo-daemon/src/prover.rs`
- Modify: `reference_impl/sbo-avail/src/lib.rs` (if needed)

**Step 1: Add submit method to BlockProver**

```rust
impl BlockProver {
    /// Submit proof to Avail DA
    pub async fn submit_proof(
        &self,
        app_id: u32,
        msg: &SbopMessage,
        client: &sbo_avail::Client,
    ) -> Result<(), ProverError> {
        let bytes = serialize_sbop(msg);
        client.submit(app_id, &bytes).await
            .map_err(|e| ProverError::SubmitFailed(e.to_string()))?;
        Ok(())
    }
}
```

**Step 2: Call submit after generating proof**

In sync loop, after saving:

```rust
// Submit to Avail
if let Err(e) = prover.submit_proof(app_id, &proof, &self.avail_client).await {
    tracing::error!("Failed to submit proof: {}", e);
}
```

**Step 3: Verify compilation**

Run: `cargo check -p sbo-daemon --features prover`

**Step 4: Commit**

```bash
git add reference_impl/
git commit -m "feat(sbo-daemon): submit proofs to Avail DA"
```

---

## Phase 3: Full Node Verification

### Task 3.1: Detect SBOP Messages in Sync

**Files:**
- Modify: `reference_impl/sbo-daemon/src/sync.rs`

**Step 1: Check for SBOP before parsing SBO**

In `process_block`, before `parse_batch`:

```rust
// Check if this is a proof message
if sbo_core::proof::is_sbop_message(&tx.data) {
    match sbo_core::proof::parse_sbop(&tx.data) {
        Ok(proof_msg) => {
            tracing::info!(
                "[{}/{}] Received SBOP proof for blocks {}-{}",
                block_number, tx.index,
                proof_msg.block_from, proof_msg.block_to
            );
            self.handle_proof_message(proof_msg, &uri).await?;
            continue; // Don't try to parse as SBO message
        }
        Err(e) => {
            tracing::warn!(
                "[{}/{}] Invalid SBOP message: {}",
                block_number, tx.index, e
            );
            continue;
        }
    }
}
```

**Step 2: Verify compilation**

Run: `cargo check -p sbo-daemon`

**Step 3: Commit**

```bash
git add reference_impl/sbo-daemon/src/sync.rs
git commit -m "feat(sbo-daemon): detect and parse SBOP messages in sync"
```

---

### Task 3.2: Verify Proofs Against Historical State

**Files:**
- Modify: `reference_impl/sbo-daemon/src/sync.rs`

**Step 1: Add handle_proof_message method**

```rust
impl SyncEngine {
    async fn handle_proof_message(
        &mut self,
        msg: sbo_core::proof::SbopMessage,
        uri: &str,
    ) -> crate::Result<()> {
        use sbo_zkvm::{verify_receipt, BlockProofOutput};

        // Verify the proof cryptographically
        let output: BlockProofOutput = match verify_receipt(&msg.receipt_bytes, None) {
            Ok(output) => output,
            Err(e) => {
                tracing::error!("Proof verification failed: {}", e);
                return Ok(()); // Don't fail sync, just log
            }
        };

        // Get our computed state root at this block
        let state_db = self.get_state_db(uri)?;
        let our_root = state_db.get_state_root_at_block(output.block_number)?;

        match our_root {
            Some(computed) => {
                if output.new_state_root == computed {
                    tracing::info!(
                        "Block {} proof VERIFIED: state root matches",
                        output.block_number
                    );
                } else {
                    tracing::error!(
                        "DISCREPANCY at block {}: proof={} computed={}",
                        output.block_number,
                        hex::encode(&output.new_state_root),
                        hex::encode(&computed)
                    );
                    // TODO: Raise alarm, halt sync, or mark untrusted
                }
            }
            None => {
                tracing::warn!(
                    "Cannot verify proof for block {}: no computed state root",
                    output.block_number
                );
            }
        }

        Ok(())
    }
}
```

**Step 2: Add hex dependency**

In `Cargo.toml`:

```toml
hex = "0.4"
```

**Step 3: Verify compilation**

Run: `cargo check -p sbo-daemon`

**Step 4: Commit**

```bash
git add reference_impl/sbo-daemon/
git commit -m "feat(sbo-daemon): verify proofs against historical state roots"
```

---

### Task 3.3: Store Verified Proofs

**Files:**
- Modify: `reference_impl/sbo-core/src/state/db.rs`

**Step 1: Add proofs column family**

```rust
const CF_PROOFS: &str = "proofs";
```

Add to CF list in `open`.

**Step 2: Add proof storage methods**

```rust
impl StateDb {
    /// Store a verified proof receipt
    pub fn store_verified_proof(
        &self,
        block_to: u64,
        receipt_bytes: &[u8],
    ) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.put_cf(&cf, &block_to.to_be_bytes(), receipt_bytes)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Get proof for a block
    pub fn get_proof_at_block(&self, block: u64) -> Result<Option<Vec<u8>>, DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, &block.to_be_bytes()) {
            Ok(bytes) => Ok(bytes.map(|b| b.to_vec())),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Get the latest proven block number
    pub fn get_latest_proven_block(&self) -> Result<Option<u64>, DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_last();

        if iter.valid() {
            if let Some(key) = iter.key() {
                let block = u64::from_be_bytes(key.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid block key".to_string()))?);
                return Ok(Some(block));
            }
        }

        Ok(None)
    }
}
```

**Step 3: Store proofs after verification**

In `handle_proof_message`, after successful verification:

```rust
// Store verified proof
state_db.store_verified_proof(output.block_number, &msg.receipt_bytes)?;
```

**Step 4: Commit**

```bash
git add reference_impl/sbo-core/src/state/db.rs
git add reference_impl/sbo-daemon/src/sync.rs
git commit -m "feat: store verified proofs in StateDb"
```

---

## Phase 4: Merkle State Root

### Task 4.1: Add Merkle Tree Implementation

**Files:**
- Create: `reference_impl/sbo-core/src/state/merkle.rs`
- Modify: `reference_impl/sbo-core/src/state/mod.rs`

**Step 1: Create merkle module**

```rust
//! Merkle tree for state root computation
//!
//! Leaf: sha256(path || object_data)
//! Root: merkle_root(sorted_leaves)

use sha2::{Sha256, Digest};

/// Compute leaf hash for an object
pub fn object_leaf(path: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute merkle root from sorted leaves
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                // Odd number: duplicate last
                hasher.update(&chunk[0]);
            }
            next_level.push(hasher.finalize().into());
        }

        level = next_level;
    }

    level[0]
}

/// Generate merkle proof for a leaf at index
pub fn generate_proof(leaves: &[[u8; 32]], index: usize) -> Vec<([u8; 32], bool)> {
    let mut proof = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let is_right = idx % 2 == 0;

        if sibling_idx < level.len() {
            proof.push((level[sibling_idx], is_right));
        } else {
            // Odd number: sibling is self
            proof.push((level[idx], is_right));
        }

        // Build next level
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]);
            }
            next_level.push(hasher.finalize().into());
        }

        level = next_level;
        idx /= 2;
    }

    proof
}

/// Verify merkle proof
pub fn verify_proof(
    leaf: [u8; 32],
    proof: &[([u8; 32], bool)],
    root: [u8; 32],
) -> bool {
    let mut current = leaf;

    for (sibling, is_right) in proof {
        let mut hasher = Sha256::new();
        if *is_right {
            hasher.update(&current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(&current);
        }
        current = hasher.finalize().into();
    }

    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof() {
        let leaves: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut h = Sha256::new();
                h.update(&[i]);
                h.finalize().into()
            })
            .collect();

        let root = merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = generate_proof(&leaves, i);
            assert!(verify_proof(*leaf, &proof, root));
        }
    }
}
```

**Step 2: Export from state module**

```rust
mod merkle;
pub use merkle::{object_leaf, merkle_root, generate_proof, verify_proof};
```

**Step 3: Commit**

```bash
git add reference_impl/sbo-core/src/state/
git commit -m "feat(sbo-core): add merkle tree for state root computation"
```

---

### Task 4.2: Compute Merkle State Root

**Files:**
- Modify: `reference_impl/sbo-daemon/src/sync.rs`
- Modify: `reference_impl/sbo-core/src/state/db.rs`

**Step 1: Add method to get all objects for merkle root**

In `db.rs`:

```rust
impl StateDb {
    /// Get all object keys and data for merkle root computation
    pub fn get_all_objects_for_merkle(&self) -> Result<Vec<(String, Vec<u8>)>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut objects = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        for item in iter {
            match item {
                Ok((key, value)) => {
                    let key_str = String::from_utf8_lossy(&key).to_string();
                    objects.push((key_str, value.to_vec()));
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }

        // Sort by key for deterministic ordering
        objects.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(objects)
    }
}
```

**Step 2: Update state root computation**

In `sync.rs`, replace `compute_transition_root` with:

```rust
fn compute_merkle_state_root(state_db: &StateDb) -> Result<[u8; 32], crate::DaemonError> {
    use sbo_core::state::{object_leaf, merkle_root};

    let objects = state_db.get_all_objects_for_merkle()
        .map_err(|e| crate::DaemonError::State(e.to_string()))?;

    let leaves: Vec<[u8; 32]> = objects
        .iter()
        .map(|(key, data)| object_leaf(key, data))
        .collect();

    Ok(merkle_root(&leaves))
}
```

**Step 3: Update state root recording**

After processing block, use merkle root:

```rust
let new_root = compute_merkle_state_root(state_db)?;
state_db.record_state_root(block_number, new_root)?;
```

**Step 4: Commit**

```bash
git add reference_impl/
git commit -m "feat: compute merkle state root from all objects"
```

---

## Phase 5: Light Client Mode

### Task 5.1: Add Light Client Config

**Files:**
- Modify: `reference_impl/sbo-daemon/src/config.rs`

**Step 1: Add light client configuration**

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LightConfig {
    /// Enable light client mode
    #[serde(default)]
    pub enabled: bool,

    /// Verify object proofs when requested
    #[serde(default = "default_true")]
    pub verify_objects: bool,
}

fn default_true() -> bool { true }
```

Add to main Config struct.

**Step 2: Commit**

```bash
git add reference_impl/sbo-daemon/src/config.rs
git commit -m "feat(sbo-daemon): add light client configuration"
```

---

### Task 5.2: Add --light CLI Flag

**Files:**
- Modify: `reference_impl/sbo-daemon/src/main.rs`

**Step 1: Add CLI flag**

```rust
#[arg(long)]
light: bool,
```

**Step 2: Pass to config**

```rust
if args.light {
    config.light.enabled = true;
}
```

**Step 3: Commit**

```bash
git add reference_impl/sbo-daemon/
git commit -m "feat(sbo-daemon): add --light CLI flag"
```

---

### Task 5.3: Implement Light Client Sync

**Files:**
- Create: `reference_impl/sbo-daemon/src/light.rs`
- Modify: `reference_impl/sbo-daemon/src/sync.rs`

**Step 1: Create light client module**

```rust
//! Light client sync - verify proofs instead of re-executing

use sbo_core::state::StateDb;
use sbo_zkvm::{verify_receipt, BlockProofOutput};

pub struct LightSync {
    /// Latest verified state root
    verified_root: Option<([u8; 32], u64)>,
}

impl LightSync {
    pub fn new() -> Self {
        Self { verified_root: None }
    }

    /// Process a proof message
    pub fn process_proof(
        &mut self,
        receipt_bytes: &[u8],
        state_db: &StateDb,
    ) -> Result<BlockProofOutput, LightSyncError> {
        // Verify proof cryptographically
        let output: BlockProofOutput = verify_receipt(receipt_bytes, None)
            .map_err(|e| LightSyncError::VerificationFailed(e.to_string()))?;

        // Check chain continuity
        if let Some((prev_root, prev_block)) = self.verified_root {
            if output.prev_state_root != prev_root {
                return Err(LightSyncError::ChainBreak {
                    expected: prev_root,
                    got: output.prev_state_root,
                });
            }
        }

        // Update verified state
        self.verified_root = Some((output.new_state_root, output.block_number));

        // Record in StateDb
        state_db.record_state_root(output.block_number, output.new_state_root)
            .map_err(|e| LightSyncError::DbError(e.to_string()))?;

        Ok(output)
    }

    /// Get the latest verified block
    pub fn latest_verified(&self) -> Option<(u64, [u8; 32])> {
        self.verified_root.map(|(root, block)| (block, root))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LightSyncError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Chain break: expected {expected:?}, got {got:?}")]
    ChainBreak { expected: [u8; 32], got: [u8; 32] },
    #[error("Database error: {0}")]
    DbError(String),
}
```

**Step 2: Integrate into sync**

In `SyncEngine`, add light client path:

```rust
if self.config.light.enabled {
    // Light client: only process proof messages
    if sbo_core::proof::is_sbop_message(&tx.data) {
        // Verify and trust proof
        self.light_sync.process_proof(&msg.receipt_bytes, state_db)?;
    }
    // Skip regular SBO message processing
    continue;
}
```

**Step 3: Commit**

```bash
git add reference_impl/sbo-daemon/
git commit -m "feat(sbo-daemon): implement light client proof-only sync"
```

---

## Phase 6: Object Proofs

### Task 6.1: Add SBOQ Message Format

**Files:**
- Create: `reference_impl/sbo-core/src/proof/sboq.rs`
- Modify: `reference_impl/sbo-core/src/proof/mod.rs`

**Step 1: Create SBOQ parser**

```rust
//! SBOQ (SBO Query) message format for object proofs
//!
//! Format:
//! ```text
//! SBOQ-Version: 0.1
//! Block: 100
//! Path: /alice/identity
//! State-Root: a1b2c3d4...
//! Object-Length: 1234
//! Proof-Length: 512
//! Content-Encoding: base64
//!
//! <base64 object data>
//!
//! <base64 merkle proof>
//! ```

use thiserror::Error;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Debug, Error)]
pub enum SboqError {
    #[error("Missing header: {0}")]
    MissingHeader(String),
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    #[error("Invalid base64: {0}")]
    InvalidBase64(String),
    #[error("Length mismatch")]
    LengthMismatch,
}

#[derive(Debug, Clone)]
pub struct SboqMessage {
    pub version: String,
    pub block: u64,
    pub path: String,
    pub state_root: [u8; 32],
    pub object_data: Vec<u8>,
    pub merkle_proof: Vec<u8>,
}

pub fn parse_sboq(bytes: &[u8]) -> Result<SboqMessage, SboqError> {
    use std::collections::HashMap;

    let mut pos = 0;
    let mut headers: HashMap<String, String> = HashMap::new();

    // Parse headers
    while pos < bytes.len() {
        let line_end = bytes[pos..].iter().position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(bytes.len());

        let line = &bytes[pos..line_end];
        if line.is_empty() {
            pos = line_end + 1;
            break;
        }

        let line_str = std::str::from_utf8(line)
            .map_err(|_| SboqError::InvalidHeader("Invalid UTF-8".to_string()))?;

        if let Some(colon) = line_str.find(": ") {
            headers.insert(
                line_str[..colon].to_string(),
                line_str[colon + 2..].to_string()
            );
        }

        pos = line_end + 1;
    }

    // Parse required headers
    let version = headers.get("SBOQ-Version")
        .ok_or_else(|| SboqError::MissingHeader("SBOQ-Version".to_string()))?
        .clone();

    let block: u64 = headers.get("Block")
        .ok_or_else(|| SboqError::MissingHeader("Block".to_string()))?
        .parse()
        .map_err(|_| SboqError::InvalidHeader("Block".to_string()))?;

    let path = headers.get("Path")
        .ok_or_else(|| SboqError::MissingHeader("Path".to_string()))?
        .clone();

    let state_root_hex = headers.get("State-Root")
        .ok_or_else(|| SboqError::MissingHeader("State-Root".to_string()))?;
    let state_root: [u8; 32] = hex::decode(state_root_hex)
        .map_err(|_| SboqError::InvalidHeader("State-Root".to_string()))?
        .try_into()
        .map_err(|_| SboqError::InvalidHeader("State-Root length".to_string()))?;

    let object_length: usize = headers.get("Object-Length")
        .ok_or_else(|| SboqError::MissingHeader("Object-Length".to_string()))?
        .parse()
        .map_err(|_| SboqError::InvalidHeader("Object-Length".to_string()))?;

    let proof_length: usize = headers.get("Proof-Length")
        .ok_or_else(|| SboqError::MissingHeader("Proof-Length".to_string()))?
        .parse()
        .map_err(|_| SboqError::InvalidHeader("Proof-Length".to_string()))?;

    // Parse payload: object\n\nproof
    let payload = std::str::from_utf8(&bytes[pos..])
        .map_err(|_| SboqError::InvalidBase64("Not UTF-8".to_string()))?;

    let parts: Vec<&str> = payload.split("\n\n").collect();
    if parts.len() != 2 {
        return Err(SboqError::InvalidHeader("Expected two payload sections".to_string()));
    }

    let object_data = STANDARD.decode(parts[0].trim())
        .map_err(|e| SboqError::InvalidBase64(e.to_string()))?;

    let merkle_proof = STANDARD.decode(parts[1].trim())
        .map_err(|e| SboqError::InvalidBase64(e.to_string()))?;

    if object_data.len() != object_length || merkle_proof.len() != proof_length {
        return Err(SboqError::LengthMismatch);
    }

    Ok(SboqMessage {
        version,
        block,
        path,
        state_root,
        object_data,
        merkle_proof,
    })
}

pub fn serialize_sboq(msg: &SboqMessage) -> Vec<u8> {
    let object_b64 = STANDARD.encode(&msg.object_data);
    let proof_b64 = STANDARD.encode(&msg.merkle_proof);

    format!(
        "SBOQ-Version: {}\n\
         Block: {}\n\
         Path: {}\n\
         State-Root: {}\n\
         Object-Length: {}\n\
         Proof-Length: {}\n\
         Content-Encoding: base64\n\
         \n\
         {}\n\
         \n\
         {}",
        msg.version,
        msg.block,
        msg.path,
        hex::encode(&msg.state_root),
        msg.object_data.len(),
        msg.merkle_proof.len(),
        object_b64,
        proof_b64
    ).into_bytes()
}
```

**Step 2: Export from proof module**

**Step 3: Commit**

```bash
git add reference_impl/sbo-core/src/proof/
git commit -m "feat(sbo-core): add SBOQ message format for object proofs"
```

---

### Task 6.2: Add CLI Commands for Object Proofs

**Files:**
- Modify: `reference_impl/sbo-cli/src/main.rs`

**Step 1: Add prove-object command**

```rust
#[derive(Subcommand)]
enum ZkvmCmd {
    /// Generate proof for object
    ProveObject {
        /// Object path (e.g., /alice/identity)
        path: String,
        #[arg(long)]
        block: u64,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Verify object proof
    VerifyObject {
        /// Path to .sboq file
        file: PathBuf,
    },
}
```

**Step 2: Implement prove-object**

```rust
ZkvmCmd::ProveObject { path, block, output } => {
    use sbo_core::state::{object_leaf, generate_proof, merkle_root};
    use sbo_core::proof::{SboqMessage, serialize_sboq};

    // Load state DB
    let state_db = StateDb::open(&state_path)?;

    // Get all objects for merkle tree
    let objects = state_db.get_all_objects_for_merkle()?;

    // Find target object
    let (idx, (_, object_data)) = objects.iter()
        .enumerate()
        .find(|(_, (k, _))| k.starts_with(&path))
        .ok_or_else(|| anyhow::anyhow!("Object not found"))?;

    // Build merkle tree and proof
    let leaves: Vec<[u8; 32]> = objects.iter()
        .map(|(k, d)| object_leaf(k, d))
        .collect();

    let root = merkle_root(&leaves);
    let proof = generate_proof(&leaves, idx);

    // Serialize proof to bytes
    let proof_bytes = postcard::to_allocvec(&proof)?;

    let msg = SboqMessage {
        version: "0.1".to_string(),
        block,
        path: path.clone(),
        state_root: root,
        object_data: object_data.clone(),
        merkle_proof: proof_bytes,
    };

    let out_path = output.unwrap_or_else(|| PathBuf::from("object.sboq"));
    std::fs::write(&out_path, serialize_sboq(&msg))?;
    println!("Wrote object proof to {}", out_path.display());
}
```

**Step 3: Implement verify-object**

```rust
ZkvmCmd::VerifyObject { file } => {
    use sbo_core::state::{object_leaf, verify_proof};
    use sbo_core::proof::parse_sboq;

    let bytes = std::fs::read(&file)?;
    let msg = parse_sboq(&bytes)?;

    // Deserialize proof
    let proof: Vec<([u8; 32], bool)> = postcard::from_bytes(&msg.merkle_proof)?;

    // Compute leaf
    let leaf = object_leaf(&msg.path, &msg.object_data);

    // Verify
    if verify_proof(leaf, &proof, msg.state_root) {
        println!("Object proof VALID");
        println!("  Path: {}", msg.path);
        println!("  Block: {}", msg.block);
        println!("  State root: {}", hex::encode(&msg.state_root));
    } else {
        println!("Object proof INVALID");
        std::process::exit(1);
    }
}
```

**Step 4: Commit**

```bash
git add reference_impl/sbo-cli/
git commit -m "feat(sbo-cli): add zkvm prove-object and verify-object commands"
```

---

### Task 6.3: Add --with-proof Flag to Get Command

**Files:**
- Modify: `reference_impl/sbo-cli/src/main.rs`

**Step 1: Add flag**

```rust
#[derive(Parser)]
struct GetCmd {
    path: String,
    #[arg(long)]
    with_proof: bool,
}
```

**Step 2: Generate proof if requested**

When `--with-proof` is set, generate and output SBOQ alongside object data.

**Step 3: Commit**

```bash
git add reference_impl/sbo-cli/
git commit -m "feat(sbo-cli): add --with-proof flag to get command"
```

---

## Final Integration

### Task F.1: Full Integration Test

**Step 1: Build workspace**

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo build --workspace
```

**Step 2: Run tests**

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo test --workspace
```

**Step 3: Manual test flow**

```bash
# Start daemon in prover mode
sbo daemon start --prover

# Submit some actions
sbo put /test/hello --data "world"

# Check for generated proofs
ls ~/.sbo/proofs/

# Start light client daemon
sbo daemon start --light

# Verify object proof
sbo get /test/hello --with-proof > hello.sboq
sbo zkvm verify-object hello.sboq
```

**Step 4: Commit**

```bash
git add reference_impl/
git commit -m "feat: complete ZK testing infrastructure implementation"
```

---

## Summary

This plan implements:

1. **Phase 1**: SBOP message format, state root tracking
2. **Phase 2**: Prover daemon with `--prover` flag
3. **Phase 3**: Full node proof verification against historical state
4. **Phase 4**: Merkle state root for object inclusion proofs
5. **Phase 5**: Light client mode with `--light` flag
6. **Phase 6**: SBOQ object proofs with CLI commands

**Testing paths:**
- **Path A**: Full node computes state, verifies proofs against historical state
- **Path B**: Light client verifies proofs only, trusts proven state

**Deferred:**
- Snapshots (SBOS messages)
- On-chain Groth16 verification
- Proof aggregation
