//! SBO ZK Validity Proofs
//!
//! This crate provides proof generation and verification for SBO.
//!
//! # Experimental — no validity claim
//!
//! This crate is feature-gated (`zkvm`) and experimental. Its receipts do
//! **not** currently attest SBO validity: the guest discards the actions hash
//! it computes, takes the trie witness as an independent input that is never
//! derived from the block's `actions_data`, returns a zero data root when
//! `header_data` is absent, and trusts any `prev_state_root` on the first
//! proof of a chain (2026-11 audit D8/D49, decision Q19; real remediation is
//! tracked by `sbo-5rww`). A verified receipt means "some trie transition
//! happened over some data", nothing more. Do not build a trust decision on
//! it. See `docs/plans/ZK-Validity-Proofs-Design.md`.

pub mod types;

#[cfg(feature = "prove")]
pub mod prover;

pub mod verifier;

pub use types::{
    BlockProofInput, BlockProofOutput,
    DataProof, CellProof, KzgCommitment, KzgProof,
    AppLookupEntry, AppLookup, HeaderData, RowData,
    ReceiptKind,
};

#[cfg(feature = "prove")]
pub use prover::{
    prove_block, prove_genesis, prove_genesis_with_da,
    prove_continuation, prove_continuation_with_da,
    prove_chain, prove_block_groth16, compress_receipt,
    ProofReceipt, ProverError
};

pub use verifier::{
    verify_receipt, verify_block_proof, verify_block_proof_with_da,
    verify_proof_chain, get_receipt_kind, VerifierError
};

/// This build's guest image id — the identity a verifier checks every proof (and,
/// via the recursion binding, the whole chain) against.
pub use sbo_zkvm_methods::SBO_ZKVM_GUEST_ID;
