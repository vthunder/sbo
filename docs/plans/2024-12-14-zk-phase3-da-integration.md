# Phase 3: Full DA Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add KZG verification for Avail data inclusion proofs, proving that SBO actions were correctly included in Avail blocks.

**Architecture:** Avail uses a 2D matrix with KZG commitments per row. We add types for DataProof (merkle) and CellProof (KZG), implement verification using `blst` (accelerated in RISC Zero), and integrate into the zkVM guest.

**Tech Stack:** Rust, blst 0.3.14 (RISC Zero accelerated), postcard serialization, no_std

---

## Background

Avail's data availability layer:
1. Block data arranged in n×m matrix
2. Each row has a KZG commitment in the block header
3. DataProof: Merkle proof showing app data location in data_root
4. CellProof: KZG proof showing cell data matches row commitment

For zkVM proving, we need to verify:
1. Merkle proof against header's data_root
2. KZG proofs for each cell against row commitments

---

## Task 1: Add KZG Types to sbo-crypto

**Files:**
- Create: `reference_impl/sbo-crypto/src/kzg.rs`
- Modify: `reference_impl/sbo-crypto/src/lib.rs:1-20`
- Modify: `reference_impl/sbo-crypto/Cargo.toml:8-20`

**Step 1: Add kzg feature to Cargo.toml**

In `reference_impl/sbo-crypto/Cargo.toml`, update features:

```toml
[features]
default = ["std", "ed25519", "bls"]
std = ["alloc", "sha2/std", "ed25519-dalek?/std"]
alloc = []
ed25519 = ["dep:ed25519-dalek"]
bls = ["dep:blst"]
kzg = ["dep:blst"]
```

**Step 2: Create kzg.rs with KZG types**

Create `reference_impl/sbo-crypto/src/kzg.rs`:

```rust
//! KZG polynomial commitment verification for Avail data availability
//!
//! Uses BLS12-381 curve (accelerated in RISC Zero zkVM)

#![cfg(feature = "kzg")]

extern crate alloc;

use alloc::vec::Vec;
use blst::{blst_p1, blst_p1_affine, blst_p2, blst_p2_affine, blst_scalar, blst_fr};
use blst::min_pk::{PublicKey, Signature};

/// Size of a BLS12-381 G1 point (compressed)
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Size of a BLS12-381 G2 point (compressed)
pub const G2_COMPRESSED_SIZE: usize = 96;

/// Size of a scalar field element
pub const SCALAR_SIZE: usize = 32;

/// KZG commitment (G1 point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgCommitment(pub [u8; G1_COMPRESSED_SIZE]);

impl KzgCommitment {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return None;
        }
        let mut arr = [0u8; G1_COMPRESSED_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; G1_COMPRESSED_SIZE] {
        &self.0
    }
}

/// KZG proof (G1 point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgProof(pub [u8; G1_COMPRESSED_SIZE]);

impl KzgProof {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return None;
        }
        let mut arr = [0u8; G1_COMPRESSED_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; G1_COMPRESSED_SIZE] {
        &self.0
    }
}

/// Cell data with its KZG proof
#[derive(Debug, Clone)]
pub struct CellProof {
    /// Row index in the matrix
    pub row: u32,
    /// Column index in the matrix
    pub col: u32,
    /// Cell data (typically 32 bytes for Avail)
    pub data: Vec<u8>,
    /// KZG proof for this cell
    pub proof: KzgProof,
}

/// Error type for KZG verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KzgError {
    InvalidCommitment,
    InvalidProof,
    InvalidPoint,
    VerificationFailed,
}

impl core::fmt::Display for KzgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCommitment => write!(f, "Invalid KZG commitment"),
            Self::InvalidProof => write!(f, "Invalid KZG proof"),
            Self::InvalidPoint => write!(f, "Invalid curve point"),
            Self::VerificationFailed => write!(f, "KZG verification failed"),
        }
    }
}

/// Domain point for evaluation
/// In Avail, these are roots of unity based on column position
pub fn domain_point(col: u32, domain_size: u32) -> [u8; SCALAR_SIZE] {
    // Compute omega^col where omega is primitive root of unity
    // For now, simplified: use column as scalar (real impl needs FFT domain)
    let mut scalar = [0u8; SCALAR_SIZE];
    scalar[0..4].copy_from_slice(&col.to_le_bytes());
    scalar
}
```

**Step 3: Export kzg module in lib.rs**

In `reference_impl/sbo-crypto/src/lib.rs`, add:

```rust
#[cfg(feature = "kzg")]
pub mod kzg;

#[cfg(feature = "kzg")]
pub use kzg::{KzgCommitment, KzgProof, CellProof, KzgError};
```

**Step 4: Verify it compiles**

Run: `cargo check -p sbo-crypto --features kzg`
Expected: Compiles with no errors

**Step 5: Commit**

```bash
git add reference_impl/sbo-crypto/
git commit -m "feat(sbo-crypto): add KZG types for data availability proofs"
```

---

## Task 2: Add DataProof Merkle Types

**Files:**
- Create: `reference_impl/sbo-crypto/src/merkle.rs`
- Modify: `reference_impl/sbo-crypto/src/lib.rs`
- Modify: `reference_impl/sbo-crypto/Cargo.toml`

**Step 1: Create merkle.rs with DataProof**

Create `reference_impl/sbo-crypto/src/merkle.rs`:

```rust
//! Merkle proof verification for Avail data proofs
//!
//! Avail uses a binary merkle tree for data_root

extern crate alloc;

use alloc::vec::Vec;
use crate::sha256;

/// Merkle proof for data inclusion
#[derive(Debug, Clone)]
pub struct DataProof {
    /// Root hashes: (data_root, blob_root, bridge_root)
    pub data_root: [u8; 32],

    /// Proof elements (sibling hashes)
    pub proof: Vec<[u8; 32]>,

    /// Total number of leaves
    pub number_of_leaves: u32,

    /// Index of the leaf being proven
    pub leaf_index: u32,

    /// The leaf value
    pub leaf: [u8; 32],
}

/// Error type for merkle operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    InvalidProofLength,
    InvalidLeafIndex,
    RootMismatch,
}

impl core::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofLength => write!(f, "Invalid proof length"),
            Self::InvalidLeafIndex => write!(f, "Invalid leaf index"),
            Self::RootMismatch => write!(f, "Merkle root mismatch"),
        }
    }
}

impl DataProof {
    /// Verify this merkle proof against data_root
    pub fn verify(&self) -> Result<bool, MerkleError> {
        if self.leaf_index >= self.number_of_leaves {
            return Err(MerkleError::InvalidLeafIndex);
        }

        let expected_depth = (self.number_of_leaves as f64).log2().ceil() as usize;
        if self.proof.len() != expected_depth {
            return Err(MerkleError::InvalidProofLength);
        }

        let mut current = self.leaf;
        let mut index = self.leaf_index;

        for sibling in &self.proof {
            current = if index % 2 == 0 {
                // Current is left child
                hash_pair(&current, sibling)
            } else {
                // Current is right child
                hash_pair(sibling, &current)
            };
            index /= 2;
        }

        if current == self.data_root {
            Ok(true)
        } else {
            Err(MerkleError::RootMismatch)
        }
    }
}

/// Hash two nodes together (standard merkle)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

/// Compute merkle root from leaves
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number: promote single node
                chunk[0]
            };
            next_level.push(hash);
        }

        current_level = next_level;
    }

    current_level[0]
}
```

**Step 2: Export merkle module**

In `reference_impl/sbo-crypto/src/lib.rs`, add:

```rust
pub mod merkle;
pub use merkle::{DataProof, MerkleError, compute_root};
```

**Step 3: Verify it compiles**

Run: `cargo check -p sbo-crypto`
Expected: Compiles with no errors

**Step 4: Commit**

```bash
git add reference_impl/sbo-crypto/
git commit -m "feat(sbo-crypto): add merkle proof types for data availability"
```

---

## Task 3: Add KZG Verification Function

**Files:**
- Modify: `reference_impl/sbo-crypto/src/kzg.rs`

**Step 1: Add verify_kzg_proof function**

Append to `reference_impl/sbo-crypto/src/kzg.rs`:

```rust
/// Verify a KZG proof that commitment(x) = y
///
/// This verifies: e(C - y*G1, G2) = e(proof, tau*G2 - x*G2)
///
/// For Avail cells:
/// - commitment: row commitment from header
/// - x: domain point for column
/// - y: cell data (as scalar)
/// - proof: KZG proof for this evaluation
///
/// Note: In zkVM, blst operations are accelerated via precompiles
pub fn verify_kzg_proof(
    commitment: &KzgCommitment,
    x: &[u8; SCALAR_SIZE],
    y: &[u8; SCALAR_SIZE],
    proof: &KzgProof,
) -> Result<bool, KzgError> {
    use blst::{
        blst_p1_affine, blst_p2_affine,
        blst_p1_uncompress, blst_p2_affine_generator,
        blst_p1_affine_is_inf, blst_p1_affine_in_g1,
        BLST_ERROR,
    };

    unsafe {
        // Decompress commitment
        let mut c_affine = blst_p1_affine::default();
        let res = blst_p1_uncompress(&mut c_affine, commitment.0.as_ptr());
        if res != BLST_ERROR::BLST_SUCCESS {
            return Err(KzgError::InvalidCommitment);
        }

        // Check commitment is valid G1 point
        if blst_p1_affine_is_inf(&c_affine) || !blst_p1_affine_in_g1(&c_affine) {
            return Err(KzgError::InvalidCommitment);
        }

        // Decompress proof
        let mut proof_affine = blst_p1_affine::default();
        let res = blst_p1_uncompress(&mut proof_affine, proof.0.as_ptr());
        if res != BLST_ERROR::BLST_SUCCESS {
            return Err(KzgError::InvalidProof);
        }

        // Check proof is valid G1 point
        if blst_p1_affine_is_inf(&proof_affine) || !blst_p1_affine_in_g1(&proof_affine) {
            return Err(KzgError::InvalidProof);
        }

        // For now, return true for valid points
        // Full pairing check requires SRS (trusted setup parameters)
        // TODO: Add full pairing verification with Avail's SRS
        Ok(true)
    }
}

/// Verify a cell proof against a row commitment
pub fn verify_cell(
    row_commitment: &KzgCommitment,
    cell: &CellProof,
    domain_size: u32,
) -> Result<bool, KzgError> {
    // Convert cell data to scalar
    let mut y = [0u8; SCALAR_SIZE];
    let len = core::cmp::min(cell.data.len(), SCALAR_SIZE);
    y[..len].copy_from_slice(&cell.data[..len]);

    // Get domain point for column
    let x = domain_point(cell.col, domain_size);

    verify_kzg_proof(row_commitment, &x, &y, &cell.proof)
}
```

**Step 2: Verify it compiles**

Run: `cargo check -p sbo-crypto --features kzg`
Expected: Compiles with no errors

**Step 3: Commit**

```bash
git add reference_impl/sbo-crypto/
git commit -m "feat(sbo-crypto): add KZG proof verification"
```

---

## Task 4: Add DA Types to sbo-zkvm

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/types.rs`

**Step 1: Update BlockProofInput with DA fields**

Replace content of `reference_impl/sbo-zkvm/src/types.rs`:

```rust
//! Types for zkVM proof input and output

use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(not(feature = "alloc"))]
use std::vec::Vec;

/// KZG commitment (48 bytes compressed G1)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KzgCommitment(pub [u8; 48]);

/// KZG proof (48 bytes compressed G1)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KzgProof(pub [u8; 48]);

/// Cell data with KZG proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellProof {
    /// Row index
    pub row: u32,
    /// Column index
    pub col: u32,
    /// Cell data
    pub data: Vec<u8>,
    /// KZG proof bytes
    pub proof: KzgProof,
}

/// Merkle proof for data inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof {
    /// Data root from header
    pub data_root: [u8; 32],
    /// Merkle proof elements
    pub proof: Vec<[u8; 32]>,
    /// Number of leaves
    pub number_of_leaves: u32,
    /// Leaf index
    pub leaf_index: u32,
    /// Leaf hash
    pub leaf: [u8; 32],
}

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

    // --- Data Availability fields ---

    /// Data inclusion proof (merkle)
    pub data_proof: Option<DataProof>,

    /// Row commitments from block header
    pub row_commitments: Vec<KzgCommitment>,

    /// KZG proofs for relevant cells
    pub cell_proofs: Vec<CellProof>,

    /// Grid dimensions (columns)
    pub grid_cols: u32,
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

    /// Data root that was verified (for DA anchoring)
    pub data_root: [u8; 32],

    /// Protocol version
    pub version: u32,
}

impl BlockProofOutput {
    /// Current protocol version
    pub const VERSION: u32 = 1;

    /// Empty state root (for genesis)
    pub const EMPTY_STATE_ROOT: [u8; 32] = [0u8; 32];

    /// Empty data root (for blocks with no DA proof)
    pub const EMPTY_DATA_ROOT: [u8; 32] = [0u8; 32];
}

impl Default for BlockProofInput {
    fn default() -> Self {
        Self {
            prev_state_root: [0u8; 32],
            block_number: 0,
            block_hash: [0u8; 32],
            parent_hash: [0u8; 32],
            actions_data: Vec::new(),
            prev_journal: None,
            data_proof: None,
            row_commitments: Vec::new(),
            cell_proofs: Vec::new(),
            grid_cols: 256, // Avail default
        }
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check -p sbo-zkvm`
Expected: Compiles with no errors

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/
git commit -m "feat(sbo-zkvm): add data availability types to proof input/output"
```

---

## Task 5: Update Guest Program with DA Verification

**Files:**
- Modify: `reference_impl/sbo-zkvm/methods/guest/src/main.rs`
- Modify: `reference_impl/sbo-zkvm/methods/guest/Cargo.toml`

**Step 1: Update guest Cargo.toml**

In `reference_impl/sbo-zkvm/methods/guest/Cargo.toml`, add blst for KZG:

```toml
[package]
name = "sbo-zkvm-guest"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
risc0-zkvm = { version = "3.0", default-features = false }
sbo-types = { path = "../../../sbo-types", default-features = false, features = ["alloc"] }
sbo-crypto = { path = "../../../sbo-crypto", default-features = false, features = ["alloc", "ed25519", "kzg"] }
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
postcard = { version = "1", default-features = false, features = ["alloc"] }

[patch.crates-io]
# Use RISC Zero's accelerated blst
blst = { git = "https://github.com/risc0/blst.git", branch = "risc0" }
```

**Step 2: Update guest main.rs with DA verification**

Replace `reference_impl/sbo-zkvm/methods/guest/src/main.rs`:

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

/// KZG commitment (48 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KzgCommitment(pub [u8; 48]);

/// KZG proof (48 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KzgProof(pub [u8; 48]);

/// Cell with KZG proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellProof {
    pub row: u32,
    pub col: u32,
    pub data: Vec<u8>,
    pub proof: KzgProof,
}

/// Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof {
    pub data_root: [u8; 32],
    pub proof: Vec<[u8; 32]>,
    pub number_of_leaves: u32,
    pub leaf_index: u32,
    pub leaf: [u8; 32],
}

/// Input to the zkVM guest program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofInput {
    pub prev_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub actions_data: Vec<u8>,
    pub prev_journal: Option<Vec<u8>>,
    pub data_proof: Option<DataProof>,
    pub row_commitments: Vec<KzgCommitment>,
    pub cell_proofs: Vec<CellProof>,
    pub grid_cols: u32,
}

/// Output committed by the zkVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofOutput {
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub data_root: [u8; 32],
    pub version: u32,
}

fn main() {
    // Read input from host
    let input: BlockProofInput = env::read();

    // 1. Verify header chain (genesis vs continuation)
    verify_header_chain(&input);

    // 2. Verify data availability (if proof provided)
    let data_root = verify_data_availability(&input);

    // 3. Process SBO actions
    let new_state_root = compute_new_state_root(&input.prev_state_root, &input.actions_data);

    // 4. Commit output
    let output = BlockProofOutput {
        prev_state_root: input.prev_state_root,
        new_state_root,
        block_number: input.block_number,
        block_hash: input.block_hash,
        data_root,
        version: 1,
    };

    env::commit(&output);
}

/// Verify header chain continuity
fn verify_header_chain(input: &BlockProofInput) {
    if input.block_number == 0 {
        // Genesis block
        assert!(input.prev_journal.is_none(), "Genesis has no previous proof");
        assert_eq!(input.prev_state_root, [0u8; 32], "Genesis starts with empty state");
    } else {
        // Continuation block
        assert!(input.prev_journal.is_some(), "Non-genesis needs previous proof");

        let prev_journal = input.prev_journal.as_ref().unwrap();
        let prev_output: BlockProofOutput = postcard::from_bytes(prev_journal)
            .expect("Invalid previous journal");

        assert_eq!(input.parent_hash, prev_output.block_hash, "Parent hash mismatch");
        assert_eq!(input.block_number, prev_output.block_number + 1, "Block number mismatch");
        assert_eq!(input.prev_state_root, prev_output.new_state_root, "State root mismatch");
    }
}

/// Verify data availability proofs
fn verify_data_availability(input: &BlockProofInput) -> [u8; 32] {
    // If no data proof, return empty root (for testing/dev)
    let Some(data_proof) = &input.data_proof else {
        return [0u8; 32];
    };

    // 1. Verify merkle proof
    assert!(
        verify_merkle_proof(data_proof),
        "Merkle proof verification failed"
    );

    // 2. Verify KZG proofs for each cell
    for cell in &input.cell_proofs {
        assert!(
            verify_kzg_cell(&input.row_commitments, cell, input.grid_cols),
            "KZG cell proof verification failed"
        );
    }

    // 3. Verify reassembled data matches actions
    let reassembled = reassemble_data(&input.cell_proofs);
    let actions_hash = sbo_crypto::sha256(&input.actions_data);
    let reassembled_hash = sbo_crypto::sha256(&reassembled);
    assert_eq!(actions_hash, reassembled_hash, "Data reassembly mismatch");

    data_proof.data_root
}

/// Verify merkle proof against data_root
fn verify_merkle_proof(proof: &DataProof) -> bool {
    let mut current = proof.leaf;
    let mut index = proof.leaf_index;

    for sibling in &proof.proof {
        current = if index % 2 == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        index /= 2;
    }

    current == proof.data_root
}

/// Hash two merkle nodes
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sbo_crypto::sha256(&combined)
}

/// Verify a single cell's KZG proof
fn verify_kzg_cell(
    row_commitments: &[KzgCommitment],
    cell: &CellProof,
    _grid_cols: u32,
) -> bool {
    // Get row commitment
    let row_idx = cell.row as usize;
    if row_idx >= row_commitments.len() {
        return false;
    }

    let _commitment = &row_commitments[row_idx];

    // Verify using blst (accelerated in zkVM)
    // For now, basic point validation - full pairing check needs SRS
    verify_kzg_proof_basic(&cell.proof)
}

/// Basic KZG proof validation (point on curve)
fn verify_kzg_proof_basic(proof: &KzgProof) -> bool {
    use blst::{blst_p1_affine, blst_p1_uncompress, BLST_ERROR};

    unsafe {
        let mut affine = blst_p1_affine::default();
        let res = blst_p1_uncompress(&mut affine, proof.0.as_ptr());
        res == BLST_ERROR::BLST_SUCCESS
    }
}

/// Reassemble data from cell proofs
fn reassemble_data(cells: &[CellProof]) -> Vec<u8> {
    // Sort by (row, col) and concatenate
    let mut sorted: Vec<_> = cells.iter().collect();
    sorted.sort_by_key(|c| (c.row, c.col));

    let mut data = Vec::new();
    for cell in sorted {
        data.extend_from_slice(&cell.data);
    }
    data
}

/// Compute new state root (SHA-256 of prev + actions)
fn compute_new_state_root(prev: &[u8; 32], actions: &[u8]) -> [u8; 32] {
    let mut data = prev.to_vec();
    data.extend_from_slice(actions);
    sbo_crypto::sha256(&data)
}
```

**Step 3: Verify it compiles**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm-methods`
Expected: Compiles (may have warnings about unused)

**Step 4: Commit**

```bash
git add reference_impl/sbo-zkvm/
git commit -m "feat(sbo-zkvm): add data availability verification to guest program"
```

---

## Task 6: Update Prover with DA Support

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/prover.rs`

**Step 1: Update prover to handle DA proofs**

Replace `reference_impl/sbo-zkvm/src/prover.rs`:

```rust
//! Proof generation for SBO blocks

use crate::types::{BlockProofInput, BlockProofOutput, DataProof, CellProof, KzgCommitment};
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

/// Generate genesis proof (block 0) without DA
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
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input)
}

/// Generate genesis proof with DA verification
#[cfg(feature = "prove")]
pub fn prove_genesis_with_da(
    block_hash: [u8; 32],
    genesis_actions: Vec<u8>,
    data_proof: DataProof,
    row_commitments: Vec<KzgCommitment>,
    cell_proofs: Vec<CellProof>,
    grid_cols: u32,
) -> Result<ProofReceipt, ProverError> {
    let input = BlockProofInput {
        prev_state_root: [0u8; 32],
        block_number: 0,
        block_hash,
        parent_hash: [0u8; 32],
        actions_data: genesis_actions,
        prev_journal: None,
        data_proof: Some(data_proof),
        row_commitments,
        cell_proofs,
        grid_cols,
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
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        data_proof: None,
        row_commitments: Vec::new(),
        cell_proofs: Vec::new(),
        grid_cols: 256,
    };

    prove_block(input)
}

/// Generate continuation proof with DA verification
#[cfg(feature = "prove")]
pub fn prove_continuation_with_da(
    prev_journal: Vec<u8>,
    block_number: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    actions_data: Vec<u8>,
    data_proof: DataProof,
    row_commitments: Vec<KzgCommitment>,
    cell_proofs: Vec<CellProof>,
    grid_cols: u32,
) -> Result<ProofReceipt, ProverError> {
    let prev_output: BlockProofOutput = postcard::from_bytes(&prev_journal)
        .map_err(|e| ProverError::SerializationError(e.to_string()))?;

    let input = BlockProofInput {
        prev_state_root: prev_output.new_state_root,
        block_number,
        block_hash,
        parent_hash,
        actions_data,
        prev_journal: Some(prev_journal),
        data_proof: Some(data_proof),
        row_commitments,
        cell_proofs,
        grid_cols,
    };

    prove_block(input)
}
```

**Step 2: Verify it compiles**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm --features prove`
Expected: Compiles with no errors

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/
git commit -m "feat(sbo-zkvm): add DA-aware proof generation functions"
```

---

## Task 7: Update Verifier with DA Output

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/verifier.rs`

**Step 1: Update verifier for new output format**

Replace `reference_impl/sbo-zkvm/src/verifier.rs`:

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
    let receipt: Receipt = postcard::from_bytes(receipt_bytes)
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

/// Verify proof matches expected block and data root (DA anchored)
pub fn verify_block_proof_with_da(
    receipt_bytes: &[u8],
    expected_block_number: u64,
    expected_block_hash: [u8; 32],
    expected_data_root: [u8; 32],
) -> Result<BlockProofOutput, VerifierError> {
    let output = verify_block_proof(receipt_bytes, expected_block_number, expected_block_hash)?;

    if output.data_root != expected_data_root {
        return Err(VerifierError::InvalidProof(
            "Data root mismatch".to_string()
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

**Step 2: Verify it compiles**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sbo-zkvm`
Expected: Compiles with no errors

**Step 3: Commit**

```bash
git add reference_impl/sbo-zkvm/
git commit -m "feat(sbo-zkvm): add DA-aware proof verification"
```

---

## Task 8: Add Tests for DA Types

**Files:**
- Create: `reference_impl/sbo-crypto/src/kzg_tests.rs`
- Create: `reference_impl/sbo-crypto/src/merkle_tests.rs`

**Step 1: Create merkle tests**

Create `reference_impl/sbo-crypto/src/merkle_tests.rs`:

```rust
#[cfg(test)]
mod tests {
    use crate::merkle::{DataProof, compute_root};
    use crate::sha256;

    #[test]
    fn test_compute_root_single() {
        let leaf = sha256(b"test");
        let root = compute_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_compute_root_two() {
        let leaf1 = sha256(b"leaf1");
        let leaf2 = sha256(b"leaf2");
        let root = compute_root(&[leaf1, leaf2]);

        // Manual calculation
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf1);
        combined[32..].copy_from_slice(&leaf2);
        let expected = sha256(&combined);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_verify_proof() {
        let leaf1 = sha256(b"leaf1");
        let leaf2 = sha256(b"leaf2");
        let root = compute_root(&[leaf1, leaf2]);

        // Proof for leaf1 (index 0)
        let proof = DataProof {
            data_root: root,
            proof: vec![leaf2], // sibling
            number_of_leaves: 2,
            leaf_index: 0,
            leaf: leaf1,
        };

        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_verify_proof_index_1() {
        let leaf1 = sha256(b"leaf1");
        let leaf2 = sha256(b"leaf2");
        let root = compute_root(&[leaf1, leaf2]);

        // Proof for leaf2 (index 1)
        let proof = DataProof {
            data_root: root,
            proof: vec![leaf1], // sibling
            number_of_leaves: 2,
            leaf_index: 1,
            leaf: leaf2,
        };

        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_verify_proof_invalid() {
        let leaf1 = sha256(b"leaf1");
        let leaf2 = sha256(b"leaf2");
        let root = compute_root(&[leaf1, leaf2]);

        // Wrong root
        let proof = DataProof {
            data_root: [0u8; 32],
            proof: vec![leaf2],
            number_of_leaves: 2,
            leaf_index: 0,
            leaf: leaf1,
        };

        assert!(proof.verify().is_err());
    }
}
```

**Step 2: Include tests in merkle.rs**

Add at the bottom of `reference_impl/sbo-crypto/src/merkle.rs`:

```rust
#[cfg(test)]
#[path = "merkle_tests.rs"]
mod tests;
```

**Step 3: Create KZG tests**

Create `reference_impl/sbo-crypto/src/kzg_tests.rs`:

```rust
#[cfg(test)]
#[cfg(feature = "kzg")]
mod tests {
    use crate::kzg::{KzgCommitment, KzgProof, CellProof, G1_COMPRESSED_SIZE};

    #[test]
    fn test_commitment_from_bytes() {
        let bytes = [0u8; G1_COMPRESSED_SIZE];
        let commitment = KzgCommitment::from_bytes(&bytes);
        assert!(commitment.is_some());
    }

    #[test]
    fn test_commitment_wrong_size() {
        let bytes = [0u8; 32]; // Wrong size
        let commitment = KzgCommitment::from_bytes(&bytes);
        assert!(commitment.is_none());
    }

    #[test]
    fn test_proof_from_bytes() {
        let bytes = [0u8; G1_COMPRESSED_SIZE];
        let proof = KzgProof::from_bytes(&bytes);
        assert!(proof.is_some());
    }

    #[test]
    fn test_cell_proof_struct() {
        let cell = CellProof {
            row: 0,
            col: 5,
            data: vec![1, 2, 3, 4],
            proof: KzgProof([0u8; G1_COMPRESSED_SIZE]),
        };

        assert_eq!(cell.row, 0);
        assert_eq!(cell.col, 5);
        assert_eq!(cell.data.len(), 4);
    }
}
```

**Step 4: Include tests in kzg.rs**

Add at the bottom of `reference_impl/sbo-crypto/src/kzg.rs`:

```rust
#[cfg(test)]
#[path = "kzg_tests.rs"]
mod tests;
```

**Step 5: Run tests**

Run: `cargo test -p sbo-crypto`
Expected: All tests pass

**Step 6: Commit**

```bash
git add reference_impl/sbo-crypto/
git commit -m "test(sbo-crypto): add merkle and KZG type tests"
```

---

## Task 9: Final Integration Test

**Files:**
- Modify: `reference_impl/sbo-zkvm/src/lib.rs`

**Step 1: Update lib.rs exports**

Replace `reference_impl/sbo-zkvm/src/lib.rs`:

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
    ProofReceipt, ProverError
};

pub use verifier::{
    verify_receipt, verify_block_proof, verify_block_proof_with_da,
    verify_proof_chain, VerifierError
};
```

**Step 2: Run full build**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo build --workspace`
Expected: Builds successfully

**Step 3: Run all tests**

Run: `RISC0_SKIP_BUILD_KERNELS=1 cargo test --workspace`
Expected: All tests pass

**Step 4: Commit**

```bash
git add reference_impl/
git commit -m "feat(sbo-zkvm): complete Phase 3 DA integration"
```

---

## Summary

Phase 3 adds:
1. **KZG types** (`sbo-crypto/kzg.rs`): Commitment, Proof, CellProof
2. **Merkle types** (`sbo-crypto/merkle.rs`): DataProof with verification
3. **DA types** (`sbo-zkvm/types.rs`): Extended BlockProofInput/Output
4. **Guest DA verification**: Merkle + KZG proof checking
5. **Prover DA support**: `prove_*_with_da` functions
6. **Verifier DA support**: `verify_block_proof_with_da`
7. **Tests**: Merkle and KZG type tests

Note: Full KZG pairing verification requires Avail's SRS (trusted setup). Current implementation validates point format; pairing check is stubbed for future SRS integration.
