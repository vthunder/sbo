# Phase 5: Groth16 SNARK Proof Compression

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Groth16 SNARK compression to reduce proof size from ~MB to ~256 bytes for efficient transmission and optional on-chain verification.

**Architecture:** Use RISC Zero's `Prover::compress()` with `ProverOpts::groth16()` to wrap STARK proofs in Groth16 SNARKs. Provide both direct Groth16 proving and post-hoc compression of existing receipts.

**Tech Stack:** risc0-zkvm with groth16 feature, risc0-groth16, Docker (required for STARK-to-SNARK)

---

## Background

RISC Zero proof types:
1. **Composite Receipt** - Vector of STARKs, one per segment (~MB)
2. **Succinct Receipt** - Single aggregated STARK (~hundreds KB)
3. **Groth16 Receipt** - Single SNARK (~256 bytes)

The compression path: Composite → Succinct → Groth16

**Requirements:**
- Docker must be installed (STARK-to-SNARK uses circom in Docker)
- x86 architecture for local proving (Apple Silicon must use remote/Bonsai)
- Feature flag: `risc0-zkvm` with `prove` feature

---

## Task 1: Add Receipt Kind Types

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/types.rs`

**Step 1: Add ReceiptKind enum**

In `reference_impl/sbo-zkvm/src/types.rs`, add after the imports:

```rust
/// Kind of proof receipt (affects size and verification cost)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptKind {
    /// Composite STARK receipt (~MB, fast to generate)
    Composite,
    /// Succinct STARK receipt (~100KB, aggregated)
    Succinct,
    /// Groth16 SNARK receipt (~256 bytes, on-chain verifiable)
    Groth16,
}

impl Default for ReceiptKind {
    fn default() -> Self {
        ReceiptKind::Composite
    }
}
```

**Step 2: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/src/types.rs
git commit -m "feat(sbo-zkvm): add ReceiptKind enum for proof types"
```

---

## Task 2: Update ProofReceipt with Kind

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Update ProofReceipt struct**

Replace the `ProofReceipt` struct:

```rust
/// Receipt containing proof and journal
pub struct ProofReceipt {
    /// The verified output (journal)
    pub journal: BlockProofOutput,

    /// Raw receipt bytes (for transmission)
    pub receipt_bytes: Vec<u8>,

    /// Kind of receipt (affects size)
    pub kind: crate::types::ReceiptKind,
}
```

**Step 2: Update prove_block to set kind**

In `prove_block`, update the return:

```rust
    Ok(ProofReceipt {
        journal,
        receipt_bytes,
        kind: crate::types::ReceiptKind::Composite,
    })
```

**Step 3: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/src/prover.rs
git commit -m "feat(sbo-zkvm): add kind field to ProofReceipt"
```

---

## Task 3: Add Compress Function

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Add compress_receipt function**

Add this function after `prove_chain`:

```rust
/// Compress a receipt to a more compact form
///
/// Compression levels:
/// - Composite → Succinct: Aggregates segments
/// - Succinct → Groth16: STARK-to-SNARK (requires Docker)
///
/// If already at requested level or more compressed, returns unchanged.
#[cfg(feature = "prove")]
pub fn compress_receipt(
    receipt: &ProofReceipt,
    target_kind: crate::types::ReceiptKind,
) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::{default_prover, ProverOpts, Receipt};

    // Deserialize the receipt
    let r0_receipt: Receipt = postcard::from_bytes(&receipt.receipt_bytes)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    // Determine target opts
    let opts = match target_kind {
        crate::types::ReceiptKind::Composite => {
            // Already composite, nothing to do
            return Ok(receipt.clone());
        }
        crate::types::ReceiptKind::Succinct => ProverOpts::succinct(),
        crate::types::ReceiptKind::Groth16 => ProverOpts::groth16(),
    };

    // Compress using the prover
    let prover = default_prover();
    let compressed = prover
        .compress(&opts, &r0_receipt)
        .map_err(|e| ProverError::ProofFailed(format!("Compression failed: {}", e)))?;

    // Serialize compressed receipt
    let receipt_bytes = postcard::to_allocvec(&compressed)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    Ok(ProofReceipt {
        journal: receipt.journal.clone(),
        receipt_bytes,
        kind: target_kind,
    })
}
```

**Step 2: Update ProofReceipt to derive Clone**

Update the struct definition to add Clone:

```rust
/// Receipt containing proof and journal
#[derive(Clone)]
pub struct ProofReceipt {
```

**Step 3: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/src/prover.rs
git commit -m "feat(sbo-zkvm): add compress_receipt for Groth16 compression"
```

---

## Task 4: Add Direct Groth16 Proving

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Add prove_block_groth16 function**

Add this function after `compress_receipt`:

```rust
/// Generate a Groth16 proof directly (skips intermediate STARK)
///
/// This is more efficient than prove_block + compress when you know
/// you want a Groth16 proof. Requires Docker.
#[cfg(feature = "prove")]
pub fn prove_block_groth16(
    input: BlockProofInput,
    prev_receipt: Option<&[u8]>,
) -> Result<ProofReceipt, ProverError> {
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

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

    // Get prover and generate Groth16 proof directly
    let prover = default_prover();
    let prove_info = prover
        .prove_with_opts(env, SBO_ZKVM_GUEST_ELF, &ProverOpts::groth16())
        .map_err(|e| ProverError::ProofFailed(e.to_string()))?;

    let receipt = prove_info.receipt;

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
        kind: crate::types::ReceiptKind::Groth16,
    })
}
```

**Step 2: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/src/prover.rs
git commit -m "feat(sbo-zkvm): add prove_block_groth16 for direct SNARK proving"
```

---

## Task 5: Update Exports

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/lib.rs`

**Step 1: Export ReceiptKind from types**

Update the types export:

```rust
pub use types::{
    BlockProofInput, BlockProofOutput,
    DataProof, CellProof, KzgCommitment, KzgProof,
    ReceiptKind,
};
```

**Step 2: Export new prover functions**

Update the prover export:

```rust
#[cfg(feature = "prove")]
pub use prover::{
    prove_block, prove_genesis, prove_genesis_with_da,
    prove_continuation, prove_continuation_with_da,
    prove_chain, prove_block_groth16, compress_receipt,
    ProofReceipt, ProverError
};
```

**Step 3: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/src/lib.rs
git commit -m "feat(sbo-zkvm): export Groth16 proving functions"
```

---

## Task 6: Update Verifier for Receipt Kinds

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/verifier.rs`

**Step 1: Read current verifier**

First read the current verifier to understand structure.

**Step 2: Update verify_receipt**

The existing `verify_receipt` should work with all receipt kinds since risc0's `Receipt::verify()` handles all types. Add a helper to check receipt kind:

```rust
/// Get the kind of a serialized receipt
pub fn get_receipt_kind(receipt_bytes: &[u8]) -> Result<crate::types::ReceiptKind, VerifierError> {
    use risc0_zkvm::Receipt;

    let receipt: Receipt = postcard::from_bytes(receipt_bytes)
        .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

    // Check the inner receipt type
    match &receipt.inner {
        risc0_zkvm::InnerReceipt::Composite(_) => Ok(crate::types::ReceiptKind::Composite),
        risc0_zkvm::InnerReceipt::Succinct(_) => Ok(crate::types::ReceiptKind::Succinct),
        risc0_zkvm::InnerReceipt::Groth16(_) => Ok(crate::types::ReceiptKind::Groth16),
        _ => Ok(crate::types::ReceiptKind::Composite), // Default for unknown
    }
}
```

**Step 3: Export get_receipt_kind in lib.rs**

Add to verifier exports:

```rust
pub use verifier::{
    verify_receipt, verify_block_proof, verify_block_proof_with_da,
    verify_proof_chain, get_receipt_kind, VerifierError
};
```

**Step 4: Verify compilation**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add reference_impl/sbo-zkvm/
git commit -m "feat(sbo-zkvm): add get_receipt_kind helper for verifier"
```

---

## Task 7: Final Integration Test

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/lib.rs`

**Step 1: Run workspace build**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo build --workspace`
Expected: Builds successfully

**Step 2: Run workspace tests**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo test --workspace`
Expected: All tests pass

**Step 3: Commit**

```bash
git add reference_impl/
git commit -m "feat(sbo-zkvm): complete Phase 5 Groth16 SNARK compression"
```

---

## Summary

Phase 5 adds:
1. **ReceiptKind enum** - Composite, Succinct, Groth16
2. **compress_receipt()** - Compress existing receipts to smaller form
3. **prove_block_groth16()** - Direct Groth16 proving
4. **get_receipt_kind()** - Detect receipt type from bytes

**Usage:**

```rust
// Option 1: Generate STARK then compress
let receipt = prove_block(input, None)?;
let groth16 = compress_receipt(&receipt, ReceiptKind::Groth16)?;

// Option 2: Direct Groth16 proving
let groth16 = prove_block_groth16(input, None)?;

// Verification works the same for all types
verify_receipt(&groth16.receipt_bytes, &expected_output)?;
```

**Size comparison:**
- Composite: ~1-10 MB
- Succinct: ~100-500 KB
- Groth16: ~256 bytes

**Note:** Groth16 compression requires Docker installed. Local proving only works on x86 (not Apple Silicon). For Apple Silicon, use Bonsai remote proving.
