# ZK Validity Proofs Phase 2: zkVM Guest Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create RISC Zero zkVM guest program that verifies SBO actions and produces validity proofs.

**Architecture:** The zkVM project follows RISC Zero's standard structure with a `methods/` crate containing the guest program and a host crate for proof generation. The guest imports our `no_std` compatible `sbo-types` and `sbo-crypto` crates.

**Tech Stack:** RISC Zero zkVM 3.0, `risc0-zkvm`, `risc0-build`, `sbo-types`, `sbo-crypto`

---

## Prerequisites

Before starting, install the RISC Zero toolchain:

```bash
curl -L https://risczero.com/install | bash
rzup install
```

Verify installation: `cargo risczero --version`

---

## Task 1: Create sbo-zkvm Directory Structure

**Files:**
- Create: `reference_impl/sbo-zkvm/Cargo.toml`
- Create: `reference_impl/sbo-zkvm/src/lib.rs`
- Create: `reference_impl/sbo-zkvm/methods/Cargo.toml`
- Create: `reference_impl/sbo-zkvm/methods/build.rs`
- Modify: `reference_impl/Cargo.toml` (workspace)

**Step 1: Create directories**

```bash
mkdir -p reference_impl/sbo-zkvm/src
mkdir -p reference_impl/sbo-zkvm/methods/guest/src
```

**Step 2: Create sbo-zkvm/Cargo.toml (host crate)**

Create file `reference_impl/sbo-zkvm/Cargo.toml`:

```toml
[package]
name = "sbo-zkvm"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "SBO ZK validity proof generation and verification"

[dependencies]
sbo-zkvm-methods = { path = "methods" }
sbo-types = { path = "../sbo-types", features = ["serde"] }
sbo-crypto = { path = "../sbo-crypto" }
risc0-zkvm = { version = "3.0", default-features = false, features = ["client"] }
serde = { version = "1", features = ["derive"] }
hex = "0.4"
thiserror = "2"

[dev-dependencies]
risc0-zkvm = { version = "3.0", features = ["prove"] }

[features]
default = []
prove = ["risc0-zkvm/prove"]
cuda = ["risc0-zkvm/cuda"]
```

**Step 3: Create sbo-zkvm/src/lib.rs**

Create file `reference_impl/sbo-zkvm/src/lib.rs`:

```rust
//! SBO ZK Validity Proofs
//!
//! This crate provides proof generation and verification for SBO.

pub mod types;
pub mod prover;
pub mod verifier;

pub use types::{BlockProofInput, BlockProofOutput};
```

**Step 4: Create methods/Cargo.toml**

Create file `reference_impl/sbo-zkvm/methods/Cargo.toml`:

```toml
[package]
name = "sbo-zkvm-methods"
version = "0.1.0"
edition = "2024"

[build-dependencies]
risc0-build = "3.0"

[package.metadata.risc0]
methods = ["guest"]
```

**Step 5: Create methods/build.rs**

Create file `reference_impl/sbo-zkvm/methods/build.rs`:

```rust
fn main() {
    risc0_build::embed_methods();
}
```

**Step 6: Add sbo-zkvm to workspace**

Edit `reference_impl/Cargo.toml`, add to members:

```toml
[workspace]
resolver = "2"
members = ["sbo-core", "sbo-avail", "sbo-daemon", "sbo-cli", "sbo-types", "sbo-crypto", "sbo-zkvm", "sbo-zkvm/methods"]
```

**Step 7: Verify structure**

Run: `ls -la reference_impl/sbo-zkvm/`

Expected: Cargo.toml, src/, methods/

---

## Task 2: Create Proof I/O Types

**Files:**
- Create: `reference_impl/sbo-zkvm/src/types.rs`

**Step 1: Create types.rs**

Create file `reference_impl/sbo-zkvm/src/types.rs`:

```rust
//! Types for zkVM proof input and output

use serde::{Serialize, Deserialize};

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    /// Previous block's state root (32 bytes)
    pub prev_state_root: [u8; 32],

    /// Block number being proven
    pub block_number: u64,

    /// Block hash (for header chain verification)
    pub block_hash: [u8; 32],

    /// Parent block hash
    pub parent_hash: [u8; 32],

    /// Raw SBO actions data
    pub actions_data: Vec<u8>,

    /// Previous proof's journal (for recursive verification)
    /// None for genesis proof
    pub prev_journal: Option<Vec<u8>>,
}

/// Output committed by the zkVM (the "journal")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockProofOutput {
    /// State root before this block
    pub prev_state_root: [u8; 32],

    /// State root after this block
    pub new_state_root: [u8; 32],

    /// Block number that was proven
    pub block_number: u64,

    /// Hash of the block that was proven
    pub block_hash: [u8; 32],

    /// Protocol version
    pub version: u32,
}

impl BlockProofOutput {
    /// Current protocol version
    pub const VERSION: u32 = 1;

    /// Empty state root (for genesis)
    pub const EMPTY_STATE_ROOT: [u8; 32] = [0u8; 32];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_serialization() {
        let output = BlockProofOutput {
            prev_state_root: [0u8; 32],
            new_state_root: [1u8; 32],
            block_number: 42,
            block_hash: [2u8; 32],
            version: 1,
        };

        let encoded = bincode::serialize(&output).unwrap();
        let decoded: BlockProofOutput = bincode::deserialize(&encoded).unwrap();
        assert_eq!(output, decoded);
    }
}
```

**Step 2: Add bincode dependency**

Edit `reference_impl/sbo-zkvm/Cargo.toml`, add:

```toml
bincode = "1"
```

**Step 3: Run tests**

Run: `cd reference_impl && cargo test -p sbo-zkvm`

Expected: PASS (1 test)

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/
git add reference_impl/Cargo.toml
git commit -m "feat: add sbo-zkvm crate with proof I/O types"
```

---

## Task 3: Create zkVM Guest Crate

**Files:**
- Create: `reference_impl/sbo-zkvm/methods/guest/Cargo.toml`
- Create: `reference_impl/sbo-zkvm/methods/guest/src/main.rs`
- Create: `reference_impl/sbo-zkvm/methods/src/lib.rs`

**Step 1: Create guest/Cargo.toml**

Create file `reference_impl/sbo-zkvm/methods/guest/Cargo.toml`:

```toml
[package]
name = "sbo-zkvm-guest"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
risc0-zkvm = { version = "3.0", default-features = false }
sbo-types = { path = "../../../sbo-types", default-features = false, features = ["alloc"] }
sbo-crypto = { path = "../../../sbo-crypto", default-features = false, features = ["alloc", "ed25519"] }
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
```

**Step 2: Create guest/src/main.rs**

Create file `reference_impl/sbo-zkvm/methods/guest/src/main.rs`:

```rust
//! SBO zkVM Guest Program
//!
//! This program runs inside the RISC Zero zkVM and produces validity proofs.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Serialize, Deserialize};

risc0_zkvm::guest::entry!(main);

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    pub prev_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub actions_data: Vec<u8>,
    pub prev_journal: Option<Vec<u8>>,
}

/// Output committed by the zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofOutput {
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub version: u32,
}

fn main() {
    // Read input from host
    let input: BlockProofInput = env::read();

    // Verify header chain (genesis vs continuation)
    if input.block_number == 0 {
        // Genesis block: no previous proof, state starts empty
        assert!(input.prev_journal.is_none(), "Genesis has no previous proof");
        assert_eq!(input.prev_state_root, [0u8; 32], "Genesis starts with empty state");
    } else {
        // Continuation: verify previous proof exists
        assert!(input.prev_journal.is_some(), "Non-genesis needs previous proof");

        // Decode previous output
        let prev_journal = input.prev_journal.as_ref().unwrap();
        let prev_output: BlockProofOutput = bincode::deserialize(prev_journal)
            .expect("Invalid previous journal");

        // Verify header chain continuity
        assert_eq!(input.parent_hash, prev_output.block_hash, "Parent hash mismatch");
        assert_eq!(input.block_number, prev_output.block_number + 1, "Block number mismatch");
        assert_eq!(input.prev_state_root, prev_output.new_state_root, "State root mismatch");
    }

    // Process SBO actions (simplified for now - just hash the data)
    let new_state_root = compute_new_state_root(&input.prev_state_root, &input.actions_data);

    // Commit output
    let output = BlockProofOutput {
        prev_state_root: input.prev_state_root,
        new_state_root,
        block_number: input.block_number,
        block_hash: input.block_hash,
        version: 1,
    };

    env::commit(&output);
}

/// Compute new state root (simplified: SHA-256 of prev + actions)
fn compute_new_state_root(prev: &[u8; 32], actions: &[u8]) -> [u8; 32] {
    use sbo_crypto::sha256;

    let mut data = prev.to_vec();
    data.extend_from_slice(actions);
    sha256(&data)
}
```

**Step 3: Add bincode to guest dependencies**

Edit `reference_impl/sbo-zkvm/methods/guest/Cargo.toml`, add:

```toml
bincode = { version = "1", default-features = false, features = ["alloc"] }
```

**Step 4: Create methods/src/lib.rs**

Create file `reference_impl/sbo-zkvm/methods/src/lib.rs`:

```rust
//! SBO zkVM Methods
//!
//! This crate provides the compiled guest ELF and image ID.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
```

**Step 5: Verify guest compiles**

Run: `cd reference_impl && cargo build -p sbo-zkvm-methods`

Expected: Success (builds guest ELF for RISC-V target)

Note: This requires the RISC Zero toolchain installed (`rzup install`)

**Step 6: Commit**

```bash
git add reference_impl/sbo-zkvm/methods/
git commit -m "feat: add zkVM guest program for SBO proofs"
```

---

## Task 4: Implement Host Prover

**Files:**
- Create: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Create prover.rs**

Create file `reference_impl/sbo-zkvm/src/prover.rs`:

```rust
//! Proof generation for SBO blocks

use crate::types::{BlockProofInput, BlockProofOutput};
use sbo_zkvm_methods::SBO_ZKVM_GUEST_ELF;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Receipt containing proof and journal
pub struct ProofReceipt {
    /// The verified output (journal)
    pub journal: BlockProofOutput,

    /// Raw receipt bytes (for transmission)
    pub receipt_bytes: Vec<u8>,
}

/// Generate a proof for a block
#[cfg(feature = "prove")]
pub fn prove_block(input: BlockProofInput) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::{default_prover, ExecutorEnv};

    // Build executor environment
    let env = ExecutorEnv::builder()
        .write(&input)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?
        .build()
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?;

    // Get prover and generate proof
    let prover = default_prover();
    let receipt = prover
        .prove(env, SBO_ZKVM_GUEST_ELF)
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?;

    // Decode journal
    let journal: BlockProofOutput = receipt
        .journal
        .decode()
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    // Serialize receipt
    let receipt_bytes = bincode::serialize(&receipt)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    Ok(ProofReceipt {
        journal,
        receipt_bytes,
    })
}

/// Generate genesis proof (block 0)
#[cfg(feature = "prove")]
pub fn prove_genesis(
    block_hash: [u8; 32],
    genesis_actions: Vec<u8>,
) -> Result<ProofReceipt, ProverError> {
    let input = BlockProofInput {
        prev_state_root: [0u8; 32],
        block_number: 0,
        block_hash,
        parent_hash: [0u8; 32],
        actions_data: genesis_actions,
        prev_journal: None,
    };

    prove_block(input)
}

/// Generate continuation proof (block N > 0)
#[cfg(feature = "prove")]
pub fn prove_continuation(
    prev_journal: Vec<u8>,
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
) -> Result<ProofReceipt, ProverError> {
    // Decode previous output to get state root
    let prev_output: BlockProofOutput = bincode::deserialize(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
    };

    prove_block(input)
}
```

**Step 2: Update lib.rs**

Edit `reference_impl/sbo-zkvm/src/lib.rs`:

```rust
//! SBO ZK Validity Proofs
//!
//! This crate provides proof generation and verification for SBO.

pub mod types;

#[cfg(feature = "prove")]
pub mod prover;

pub mod verifier;

pub use types::{BlockProofInput, BlockProofOutput};

#[cfg(feature = "prove")]
pub use prover::{prove_block, prove_genesis, prove_continuation, ProofReceipt, ProverError};
```

**Step 3: Verify it compiles**

Run: `cd reference_impl && cargo check -p sbo-zkvm`

Expected: Success (without prove feature, prover is not compiled)

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/src/
git commit -m "feat: add proof generation for SBO blocks"
```

---

## Task 5: Implement Verifier

**Files:**
- Create: `reference_impl/sbo-zkvm/src/verifier.rs`

**Step 1: Create verifier.rs**

Create file `reference_impl/sbo-zkvm/src/verifier.rs`:

```rust
//! Proof verification for SBO blocks

use crate::types::BlockProofOutput;
use sbo_zkvm_methods::SBO_ZKVM_GUEST_ID;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Journal decode error: {0}")]
    JournalError(String),

    #[error("Receipt decode error: {0}")]
    ReceiptError(String),
}

/// Verify a proof receipt
pub fn verify_receipt(receipt_bytes: &[u8]) -> Result<BlockProofOutput, VerifierError> {
    use risc0_zkvm::Receipt;

    // Deserialize receipt
    let receipt: Receipt = bincode::deserialize(receipt_bytes)
        .map_err(|e| VerifierError::ReceiptError(e.to_string()))?;

    // Verify proof against our guest program
    receipt
        .verify(SBO_ZKVM_GUEST_ID)
        .map_err(|e| VerifierError::InvalidProof(e.to_string()))?;

    // Decode and return journal
    let output: BlockProofOutput = receipt
        .journal
        .decode()
        .map_err(|e| VerifierError::JournalError(e.to_string()))?;

    Ok(output)
}

/// Verify proof and check it matches expected block
pub fn verify_block_proof(
    receipt_bytes: &[u8],
    expected_block_number: u64,
    expected_block_hash: [u8; 32],
) -> Result<BlockProofOutput, VerifierError> {
    let output = verify_receipt(receipt_bytes)?;

    if output.block_number != expected_block_number {
        return Err(VerifierError::InvalidProof(format!(
            "Block number mismatch: expected {}, got {}",
            expected_block_number, output.block_number
        )));
    }

    if output.block_hash != expected_block_hash {
        return Err(VerifierError::InvalidProof(
            "Block hash mismatch".to_string()
        ));
    }

    Ok(output)
}

/// Verify a chain of proofs
pub fn verify_proof_chain(
    receipts: &[Vec<u8>],
) -> Result<BlockProofOutput, VerifierError> {
    if receipts.is_empty() {
        return Err(VerifierError::InvalidProof("Empty proof chain".to_string()));
    }

    let mut prev_output: Option<BlockProofOutput> = None;

    for (i, receipt_bytes) in receipts.iter().enumerate() {
        let output = verify_receipt(receipt_bytes)?;

        // Verify chain continuity
        if let Some(prev) = &prev_output {
            if output.block_number != prev.block_number + 1 {
                return Err(VerifierError::InvalidProof(format!(
                    "Block number discontinuity at {}",
                    i
                )));
            }
            if output.prev_state_root != prev.new_state_root {
                return Err(VerifierError::InvalidProof(format!(
                    "State root mismatch at block {}",
                    output.block_number
                )));
            }
        } else {
            // First proof should be genesis
            if output.block_number != 0 {
                return Err(VerifierError::InvalidProof(
                    "Chain must start at genesis".to_string()
                ));
            }
        }

        prev_output = Some(output);
    }

    Ok(prev_output.unwrap())
}
```

**Step 2: Run cargo check**

Run: `cd reference_impl && cargo check -p sbo-zkvm`

Expected: Success

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/src/verifier.rs
git commit -m "feat: add proof verification for SBO blocks"
```

---

## Task 6: Add Integration Test (Dev Mode)

**Files:**
- Create: `reference_impl/sbo-zkvm/tests/integration.rs`

**Step 1: Create integration test**

Create file `reference_impl/sbo-zkvm/tests/integration.rs`:

```rust
//! Integration tests for SBO zkVM proofs
//!
//! These tests use RISC0_DEV_MODE=1 for fast execution.

#[cfg(feature = "prove")]
mod tests {
    use sbo_zkvm::{
        prove_genesis, prove_continuation,
        verifier::{verify_receipt, verify_proof_chain},
        BlockProofOutput,
    };

    #[test]
    fn test_genesis_proof() {
        // Set dev mode for fast testing
        std::env::set_var("RISC0_DEV_MODE", "1");

        let block_hash = [1u8; 32];
        let genesis_actions = b"genesis data".to_vec();

        let receipt = prove_genesis(block_hash, genesis_actions)
            .expect("Genesis proof failed");

        assert_eq!(receipt.journal.block_number, 0);
        assert_eq!(receipt.journal.block_hash, block_hash);
        assert_eq!(receipt.journal.prev_state_root, [0u8; 32]);
        assert_ne!(receipt.journal.new_state_root, [0u8; 32]);

        // Verify the proof
        let verified = verify_receipt(&receipt.receipt_bytes)
            .expect("Verification failed");
        assert_eq!(verified, receipt.journal);
    }

    #[test]
    fn test_continuation_proof() {
        std::env::set_var("RISC0_DEV_MODE", "1");

        // First, generate genesis
        let genesis_hash = [1u8; 32];
        let genesis_receipt = prove_genesis(genesis_hash, b"genesis".to_vec())
            .expect("Genesis proof failed");

        // Get journal bytes from genesis
        let genesis_journal = bincode::serialize(&genesis_receipt.journal).unwrap();

        // Generate block 1
        let block1_hash = [2u8; 32];
        let block1_receipt = prove_continuation(
            genesis_journal,
            1,
            block1_hash,
            genesis_hash,  // parent is genesis
            b"block 1 actions".to_vec(),
        ).expect("Block 1 proof failed");

        assert_eq!(block1_receipt.journal.block_number, 1);
        assert_eq!(block1_receipt.journal.prev_state_root, genesis_receipt.journal.new_state_root);

        // Verify
        let verified = verify_receipt(&block1_receipt.receipt_bytes)
            .expect("Verification failed");
        assert_eq!(verified, block1_receipt.journal);
    }

    #[test]
    fn test_verify_chain() {
        std::env::set_var("RISC0_DEV_MODE", "1");

        // Generate 3 blocks
        let mut receipts = Vec::new();
        let mut prev_journal: Option<Vec<u8>> = None;
        let mut prev_hash = [0u8; 32];
        let mut prev_output: Option<BlockProofOutput> = None;

        for i in 0..3 {
            let block_hash = [(i + 1) as u8; 32];
            let actions = format!("block {} actions", i).into_bytes();

            let receipt = if i == 0 {
                prove_genesis(block_hash, actions).expect("Genesis failed")
            } else {
                prove_continuation(
                    prev_journal.unwrap(),
                    i as u64,
                    block_hash,
                    prev_hash,
                    actions,
                ).expect(&format!("Block {} failed", i))
            };

            receipts.push(receipt.receipt_bytes.clone());
            prev_journal = Some(bincode::serialize(&receipt.journal).unwrap());
            prev_hash = block_hash;
            prev_output = Some(receipt.journal);
        }

        // Verify the entire chain
        let final_output = verify_proof_chain(&receipts)
            .expect("Chain verification failed");

        assert_eq!(final_output.block_number, 2);
        assert_eq!(final_output, prev_output.unwrap());
    }
}
```

**Step 2: Run integration test (dev mode)**

Run: `cd reference_impl && RISC0_DEV_MODE=1 cargo test -p sbo-zkvm --features prove -- --nocapture`

Expected: PASS (3 tests, may take 10-30 seconds each even in dev mode)

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/tests/
git commit -m "test: add zkVM integration tests with dev mode"
```

---

## Task 7: Update sbo-types for zkVM Compatibility

**Files:**
- Modify: `reference_impl/sbo-types/Cargo.toml`

**Step 1: Add serde/alloc feature combination**

The guest needs serde with alloc but without std. Verify `sbo-types/Cargo.toml` supports this:

```toml
[features]
default = ["std"]
std = ["alloc", "serde?/std"]
alloc = []
serde = ["dep:serde"]

[dependencies]
serde = { version = "1", default-features = false, features = ["derive", "alloc"], optional = true }
```

**Step 2: Verify guest can use sbo-types**

Run: `cd reference_impl && cargo check -p sbo-zkvm-guest --target riscv32im-risc0-zkvm-elf`

Note: Requires RISC Zero toolchain and may need target installation.

**Step 3: Commit if changes made**

```bash
git add reference_impl/sbo-types/Cargo.toml
git commit -m "fix: ensure sbo-types works in zkVM guest"
```

---

## Task 8: Final Verification

**Step 1: Build everything**

Run: `cd reference_impl && cargo build`

Expected: Success

**Step 2: Run all tests**

Run: `cd reference_impl && cargo test`

Expected: All tests pass (sbo-types: 15, sbo-crypto: 7, sbo-core: 15+)

**Step 3: Run zkVM tests with proving**

Run: `cd reference_impl && RISC0_DEV_MODE=1 cargo test -p sbo-zkvm --features prove`

Expected: All 3 integration tests pass

**Step 4: Final commit**

```bash
git add .
git commit -m "feat: complete Phase 2 zkVM guest implementation

- sbo-zkvm crate with host prover and verifier
- zkVM guest program for SBO validity proofs
- Header chain verification
- Simplified state transition (SHA-256 based)
- Integration tests in dev mode"
```

---

## Summary

Phase 2 creates the foundational zkVM infrastructure:

| Component | Purpose |
|-----------|---------|
| `sbo-zkvm` | Host crate for proof generation/verification |
| `sbo-zkvm-methods` | Compiles guest to RISC-V ELF |
| `sbo-zkvm-guest` | Guest program running in zkVM |
| `BlockProofInput` | Input structure for proving |
| `BlockProofOutput` | Journal committed by proof |

**Next Phase (Phase 3):** Add KZG verification for Avail data inclusion proofs.

---

## References

- [RISC Zero zkVM Quick Start](https://dev.risczero.com/api/zkvm/quickstart)
- [RISC Zero GitHub](https://github.com/risc0/risc0)
- [risc0-zkvm crate docs](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/)
