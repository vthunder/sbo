//! End-to-end validation of the self-recursion image-id binding (mingo-ikvs).
//!
//! These run REAL proofs (no dev mode), so they are slow (minutes on CPU) and
//! `#[ignore]`d — run explicitly with the risc0 toolchain on PATH:
//!
//!   cargo test -p sbo-zkvm --features prove --test recursion -- --ignored --nocapture
//!
//! IMPORTANT — cannot run on macOS without full Xcode: risc0's prove backend
//! links the CPU circuit kernels and, on macOS, unconditionally compiles Metal
//! GPU kernels, which need the `metal` compiler from a full Xcode install (not
//! just Command Line Tools). `RISC0_SKIP_BUILD_KERNELS=1` skips the CPU kernels
//! too, leaving undefined `_risc0_circuit_*_cpu_*` symbols at link time. Run
//! these on the Linux prover node / CI (no Metal), which is where proving runs
//! in production anyway (mingo-ikvs: separate prover node).
#![cfg(feature = "prove")]

use sbo_zkvm::{prove_continuation, prove_genesis, verify_receipt, SBO_ZKVM_GUEST_ID};

/// A genesis proof verifies, and its journal commits THIS guest's image id — the
/// field the external verifier binds against.
#[test]
#[ignore = "real proving; slow"]
fn genesis_proof_commits_guest_image_id() {
    let genesis = prove_genesis([9u8; 32], vec![]).expect("genesis proof");
    let journal = verify_receipt(&genesis.receipt_bytes).expect("verify genesis");

    assert_eq!(journal.block_number, 0);
    assert_eq!(journal.prev_state_root, [0u8; 32]);
    assert_eq!(journal.new_state_root, [0u8; 32]); // empty witness → unchanged
    // The crux: the verifier already enforces this equality, but assert it plainly.
    assert_eq!(journal.verified_with_image_id, SBO_ZKVM_GUEST_ID);
}

/// A continuation recursively verifies the genesis proof (env::verify against the
/// passed guest image id) and itself commits that id. verify_receipt accepting it
/// proves the whole chain is bound to the genuine guest — the fix for the former
/// all-zeros placeholder that made recursion unusable.
#[test]
#[ignore = "real proving; slow (recursive)"]
fn continuation_recursively_binds_to_guest() {
    let genesis = prove_genesis([9u8; 32], vec![]).expect("genesis proof");

    // block 1: parent_hash must equal the genesis block hash; empty witness keeps
    // the state root unchanged ([0;32]).
    let cont = prove_continuation(&genesis.receipt_bytes, 1, [10u8; 32], [9u8; 32], vec![])
        .expect("continuation proof");

    let journal = verify_receipt(&cont.receipt_bytes).expect("verify continuation");
    assert_eq!(journal.block_number, 1);
    assert_eq!(journal.verified_with_image_id, SBO_ZKVM_GUEST_ID);
}
