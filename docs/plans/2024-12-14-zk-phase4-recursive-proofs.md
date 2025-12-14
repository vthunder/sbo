# Phase 4: Recursive Proof Verification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable recursive proof verification where each block proof verifies the previous block's proof, creating a proof chain back to genesis.

**Architecture:** Use RISC Zero's proof composition with `env::verify()` in the guest and `add_assumption()` on the host. Each continuation proof cryptographically verifies its predecessor, ensuring trustless chain verification with O(1) final verification.

**Tech Stack:** RISC Zero 3.0 proof composition, risc0-zkvm, postcard serialization

---

## Background

RISC Zero proof composition works as follows:
1. **Host-side**: Call `add_assumption(receipt)` to provide a receipt for verification
2. **Guest-side**: Call `env::verify(image_id, journal)` to verify the receipt
3. **Resolution**: When proving with Succinct/Groth16, assumptions are resolved automatically

Current state (Phase 3):
- Guest receives `prev_journal: Option<Vec<u8>>` and decodes it
- No actual cryptographic verification of previous proof
- Prover doesn't pass previous receipt

Phase 4 changes:
- Add `prev_receipt_bytes: Option<Vec<u8>>` to pass full receipt
- Guest calls `env::verify()` for cryptographic verification
- Prover uses `add_assumption()` to inject previous receipt

---

## Task 1: Update Types with Receipt Field

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/types.rs`

**Step 1: Add prev_receipt_bytes field to BlockProofInput**

In `reference_impl/sbo-zkvm/src/types.rs`, find `BlockProofInput` struct and add after `prev_journal`:

```rust
    /// Previous proof's journal (for chain verification)
    /// None for genesis proof
    pub prev_journal: Option<Vec<u8>>,

    /// Previous proof's receipt bytes (for recursive verification)
    /// None for genesis proof - passed via assumption mechanism
    pub prev_receipt_bytes: Option<Vec<u8>>,
```

**Step 2: Update Default impl**

Update the Default impl to include:

```rust
impl Default for BlockProofInput {
    fn default() -> Self {
        Self {
            prev_state_root: [0u8; 32],
            block_number: 0,
            block_hash: [0u8; 32],
            parent_hash: [0u8; 32],
            actions_data: Vec::new(),
            prev_journal: None,
            prev_receipt_bytes: None,  // Add this
            data_proof: None,
            row_commitments: Vec::new(),
            cell_proofs: Vec::new(),
            grid_cols: 256,
        }
    }
}
```

**Step 3: Verify compilation**

Run: `cargo check -p sbo-zkvm`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/src/types.rs
git commit -m "feat(sbo-zkvm): add prev_receipt_bytes field for recursive proofs"
```

---

## Task 2: Update Guest for Recursive Verification

**Files:**
- Modify: `reference_impl/sbo-zkvm/methods/guest/src/main.rs`

**Step 1: Update BlockProofInput in guest**

Find the `BlockProofInput` struct in main.rs and add the new field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    pub prev_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub actions_data: Vec<u8>,
    pub prev_journal: Option<Vec<u8>>,
    pub prev_receipt_bytes: Option<Vec<u8>>,  // Add this
    pub data_proof: Option<DataProof>,
    pub row_commitments: Vec<KzgCommitment>,
    pub cell_proofs: Vec<CellProof>,
    pub grid_cols: u32,
}
```

**Step 2: Update verify_header_chain to use env::verify**

Replace the `verify_header_chain` function:

```rust
/// Verify header chain continuity with recursive proof verification
fn verify_header_chain(input: &BlockProofInput) {
    if input.block_number == 0 {
        // Genesis block - no previous proof to verify
        assert!(input.prev_journal.is_none(), "Genesis has no previous proof");
        assert!(input.prev_receipt_bytes.is_none(), "Genesis has no previous receipt");
        assert_eq!(input.prev_state_root, [0u8; 32], "Genesis starts with empty state");
    } else {
        // Continuation block - verify previous proof recursively
        assert!(input.prev_journal.is_some(), "Non-genesis needs previous proof");

        let prev_journal = input.prev_journal.as_ref().unwrap();

        // Cryptographically verify previous proof using RISC Zero composition
        // This adds an "assumption" that must be resolved during proving
        env::verify(
            sbo_zkvm_methods::SBO_ZKVM_GUEST_ID,
            prev_journal,
        ).expect("Previous proof verification failed");

        // Decode previous output for chain continuity checks
        let prev_output: BlockProofOutput = postcard::from_bytes(prev_journal)
            .expect("Invalid previous journal");

        // Verify header chain continuity
        assert_eq!(input.parent_hash, prev_output.block_hash, "Parent hash mismatch");
        assert_eq!(input.block_number, prev_output.block_number + 1, "Block number mismatch");
        assert_eq!(input.prev_state_root, prev_output.new_state_root, "State root mismatch");
    }
}
```

**Step 3: Add import for guest ID**

At the top of the file, after the existing imports:

```rust
// Import guest ID for recursive verification
#[cfg(not(feature = "std"))]
extern crate sbo_zkvm_methods;
```

**Step 4: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm-methods`
Expected: Compiles (may have warnings)

**Step 5: Commit**

```bash
git add reference_impl/sbo-zkvm/methods/guest/
git commit -m "feat(sbo-zkvm): add recursive proof verification with env::verify"
```

---

## Task 3: Update Prover for Composition

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Update prove_block to support assumptions**

Replace the `prove_block` function:

```rust
/// Generate a proof for a block with optional recursive verification
#[cfg(feature = "prove")]
pub fn prove_block(input: BlockProofInput, prev_receipt: Option<&[u8]>) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

    // Build executor environment
    let mut env_builder = ExecutorEnv::builder();

    // Write input
    env_builder
        .write(&input)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    // Add assumption for previous receipt (if continuation block)
    if let Some(receipt_bytes) = prev_receipt {
        let prev_receipt: Receipt = postcard::from_bytes(receipt_bytes)
            .map_err(|e| ProverError::SerializationError(format!("Invalid previous receipt: {}", e)))?;
        env_builder.add_assumption(prev_receipt);
    }

    let env = env_builder
        .build()
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?;

    // Get prover and generate proof
    let prover = default_prover();
    let receipt = prover
        .prove(env, SBO_ZKVM_GUEST_ELF)
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?
        .receipt;

    // Decode journal
    let journal: BlockProofOutput = receipt
        .journal
        .decode()
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    // Serialize receipt
    let receipt_bytes = postcard::to_allocvec(&receipt)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    Ok(ProofReceipt {
        journal,
        receipt_bytes,
    })
}
```

**Step 2: Update prove_genesis**

```rust
/// Generate genesis proof (block 0) - no recursion needed
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
        prev_receipt_bytes: None,
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input, None)
}
```

**Step 3: Update prove_continuation**

```rust
/// Generate continuation proof (block N > 0) with recursive verification
#[cfg(feature = "prove")]
pub fn prove_continuation(
    prev_receipt_bytes: &[u8],
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::Receipt;

    // Decode previous receipt to get journal
    let prev_receipt: Receipt = postcard::from_bytes(prev_receipt_bytes)
        .map_err(|e| ProverError::SerializationError(format!("Invalid previous receipt: {}", e)))?;

    let prev_journal = prev_receipt.journal.bytes.clone();
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        prev_receipt_bytes: Some(prev_receipt_bytes.to_vec()),
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input, Some(prev_receipt_bytes))
}
```

**Step 4: Update prove_continuation_with_da similarly**

Add prev_receipt_bytes parameter and update accordingly.

**Step 5: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add reference_impl/sbo-zkvm/src/prover.rs
git commit -m "feat(sbo-zkvm): add proof composition with add_assumption"
```

---

## Task 4: Update Guest Cargo.toml for Methods Dependency

**Files:**
- Modify: `reference_impl/sbo-zkvm/methods/guest/Cargo.toml`

**Step 1: Add sbo-zkvm-methods dependency**

The guest needs access to the guest ID for recursive verification. Add:

```toml
[dependencies]
risc0-zkvm = { version = "3.0", default-features = false }
sbo-types = { path = "../../../sbo-types", default-features = false, features = ["alloc"] }
sbo-crypto = { path = "../../../sbo-crypto", default-features = false, features = ["alloc", "ed25519"] }
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
postcard = { version = "1", default-features = false, features = ["alloc"] }

[build-dependencies]
# The methods crate's build.rs generates the guest ID we need
```

Note: The guest ID comes from the methods crate which is built by risc0's build system. The `sbo_zkvm_methods::SBO_ZKVM_GUEST_ID` is available at compile time.

**Step 2: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm-methods`
Expected: Compiles

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/methods/guest/Cargo.toml
git commit -m "chore(sbo-zkvm): update guest dependencies for recursive proofs"
```

---

## Task 5: Add Chain Proving Helper

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Add prove_chain function**

Append to prover.rs:

```rust
/// Prove an entire chain of blocks from genesis
///
/// Takes a list of (block_hash, parent_hash, actions) tuples.
/// Returns the final receipt that proves the entire chain.
#[cfg(feature = "prove")]
pub fn prove_chain(
    blocks: Vec<([u8; 32], [u8; 32], Vec<u8>)>,
) -> Result<ProofReceipt, ProverError> {
    if blocks.is_empty() {
        return Err(ProverError::InvalidInput("Empty block list".to_string()));
    }

    // Prove genesis
    let (genesis_hash, _, genesis_actions) = &blocks[0];
    let mut current_receipt = prove_genesis(*genesis_hash, genesis_actions.clone())?;

    // Prove each continuation block
    for (i, (block_hash, parent_hash, actions)) in blocks.iter().enumerate().skip(1) {
        current_receipt = prove_continuation(
            &current_receipt.receipt_bytes,
            i as u64,
            *block_hash,
            *parent_hash,
            actions.clone(),
        )?;
    }

    Ok(current_receipt)
}
```

**Step 2: Export in lib.rs**

In `sbo-zkvm/src/lib.rs`, add to the prove feature exports:

```rust
#[cfg(feature = "prove")]
pub use prover::{
    prove_block, prove_genesis, prove_genesis_with_da,
    prove_continuation, prove_continuation_with_da,
    prove_chain,  // Add this
    ProofReceipt, ProverError
};
```

**Step 3: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/
git commit -m "feat(sbo-zkvm): add prove_chain helper for chain proving"
```

---

## Task 6: Final Integration Test

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/lib.rs`

**Step 1: Update lib.rs exports**

Ensure all new types and functions are exported:

```rust
//! SBO ZK Validity Proofs
//!
//! This crate provides proof generation and verification for SBO.

pub mod types;

#[cfg(feature = "prove")]
pub mod prover;

pub mod verifier;

pub use types::{
    BlockProofInput, BlockProofOutput,
    DataProof, CellProof, KzgCommitment, KzgProof
};

#[cfg(feature = "prove")]
pub use prover::{
    prove_block, prove_genesis, prove_genesis_with_da,
    prove_continuation, prove_continuation_with_da,
    prove_chain,
    ProofReceipt, ProverError
};

pub use verifier::{
    verify_receipt, verify_block_proof, verify_block_proof_with_da,
    verify_proof_chain, VerifierError
};
```

**Step 2: Run full workspace build**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo build --workspace`
Expected: Builds successfully

**Step 3: Run full workspace tests**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo test --workspace`
Expected: All tests pass

**Step 4: Commit**

```bash
git add reference_impl/
git commit -m "feat(sbo-zkvm): complete Phase 4 recursive proof verification"
```

---

## Summary

Phase 4 adds:
1. **prev_receipt_bytes field** - Full receipt for recursive verification
2. **env::verify() in guest** - Cryptographic verification of previous proof
3. **add_assumption() in prover** - Host-side composition setup
4. **prove_chain helper** - Convenient multi-block proving

The proof chain now provides:
- **Trustless verification**: Each proof cryptographically verifies its predecessor
- **O(1) final verification**: Only need to verify the latest proof
- **Constant proof size**: Regardless of chain length

Note: Full testing requires Metal/GPU for actual proof generation. Use `RISC0_DEV_MODE=1` for faster testing with fake proofs.
