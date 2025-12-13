# SBO ZK Validity Proofs Design

**Status:** Draft
**Date:** 2024-12-13

## Problem Statement

SBO light clients currently face a fundamental challenge: to verify the state of a single object, they must either:
1. Trust a full node to provide correct state
2. Download and replay the entire chain history
3. Use optimistic/fraud proof approaches (which require challenge periods and liveness assumptions)

This document proposes a **ZK validity proof** system where a single cryptographic proof attests that the entire SBO state was correctly computed from genesis. Light clients can verify state by checking only:
1. The latest ZK proof
2. The latest Avail block header (via Avail's existing light client)

## Design Goals

1. **Trustless**: No reliance on honest majority, watchtowers, or challenge periods
2. **Permissionless Proving**: Anyone can generate proofs; no dedicated prover infrastructure needed
3. **Recursive**: Each proof verifies the previous proof, creating a chain back to genesis
4. **DA-Anchored**: Proofs are anchored to Avail block headers, ensuring completeness (no skipped actions)
5. **Light Client Friendly**: O(1) verification regardless of chain history length

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Light Client                             │
│                                                                  │
│   1. Get latest Avail header (from Avail LC)                    │
│   2. Get latest SBO proof                                       │
│   3. Verify: proof.block_hash == avail_header.hash              │
│   4. Verify: ZK proof is valid                                  │
│   5. Query state against proof.state_root                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        ZK Proof Chain                            │
│                                                                  │
│   Block 0 ──proof──▶ Block 1 ──proof──▶ ... ──proof──▶ Block N  │
│      │                   │                                │      │
│   genesis             recursive                        latest    │
│   proof               verification                     proof     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Proof Structure

### Per-Block Proof

Each block proof verifies:
1. **Header Chain**: `block_header.parent_hash == prev_proof.block_hash`
2. **Data Inclusion**: App data is correctly included in the block (KZG verification)
3. **SBO Validation**: All actions are valid (signatures, policies, state transitions)
4. **Previous Proof**: The previous block's proof was valid (recursion)

```rust
/// Input to the zkVM guest program
struct BlockProofInput {
    // Previous proof's committed output (for recursion)
    prev_proof_journal: Option<Vec<u8>>,
    prev_proof: Option<Proof>,  // RISC Zero proof to verify

    // Current block data
    block_header: AvailHeader,
    app_data: Vec<u8>,          // Raw app data from Avail

    // Data inclusion proof
    data_proof: DataProof,      // Merkle proof for app data
    row_commitments: Vec<G1>,   // KZG commitments for relevant rows
    cell_proofs: Vec<CellProof>, // KZG proofs for data cells

    // Previous state (hashed, not full)
    prev_state_root: Hash,
}

/// Output committed by the zkVM (the "journal")
struct BlockProofOutput {
    // For recursive verification
    prev_state_root: Hash,
    new_state_root: Hash,
    block_number: u64,
    block_hash: Hash,           // Committed for next proof's verification

    // Protocol version for upgrades
    version: u32,
}
```

### Genesis Proof

The first proof has no previous proof to verify. It:
1. Verifies the genesis block format
2. Initializes state from genesis actions
3. Commits the initial state root

```rust
fn prove_genesis(genesis_block: AvailHeader, genesis_data: Vec<u8>) -> BlockProofOutput {
    // Verify this is block 0
    assert_eq!(genesis_block.number, 0);

    // Process genesis actions (root policy, sys identity, etc.)
    let state = apply_genesis_actions(&genesis_data);

    BlockProofOutput {
        prev_state_root: EMPTY_STATE_ROOT,
        new_state_root: state.root(),
        block_number: 0,
        block_hash: genesis_block.hash(),
        version: 1,
    }
}
```

## Data Inclusion Verification

Avail uses a 2D matrix structure for data availability:

```
┌──────────────────────────────────────────┐
│            Avail Block Header             │
│  ┌────────────────────────────────────┐  │
│  │ extension.commitment.data_root     │  │  ← Merkle root of all app data
│  │ extension.commitment.commitments[] │  │  ← KZG commitments per row
│  │ extension.commitment.rows, cols    │  │  ← Grid dimensions
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Data Matrix                                │
│                                                                  │
│   Row 0: [cell_0, cell_1, ..., cell_n]  ← commitment_0          │
│   Row 1: [cell_0, cell_1, ..., cell_n]  ← commitment_1          │
│   ...                                                            │
│   Row m: [cell_0, cell_1, ..., cell_n]  ← commitment_m          │
│                                                                  │
│   App data spans consecutive cells starting at app_index        │
│   (app_index = row * row_width + col)                           │
└─────────────────────────────────────────────────────────────────┘
```

### Verification Steps

1. **Merkle Verification**: Verify `DataProof` against `data_root` to prove app data location
2. **KZG Verification**: For each row containing our app data:
   - Verify cell proofs against row commitment
   - Proves the actual data matches what's committed in the header

```rust
fn verify_data_inclusion(
    header: &AvailHeader,
    app_data: &[u8],
    data_proof: &DataProof,
    row_commitments: &[G1],
    cell_proofs: &[CellProof],
) -> Result<()> {
    // 1. Verify Merkle proof against data_root
    let data_root = header.extension.commitment.data_root;
    verify_merkle_proof(&data_proof, data_root)?;

    // 2. Verify KZG proofs for each cell
    for (i, cell_proof) in cell_proofs.iter().enumerate() {
        let row_idx = cell_proof.row;
        let commitment = &header.extension.commitment.commitments[row_idx];

        // Verify cell data matches commitment
        verify_kzg_proof(
            commitment,
            cell_proof.col,
            &cell_proof.data,
            &cell_proof.proof,
        )?;
    }

    // 3. Verify reassembled data matches app_data
    let reassembled = reassemble_app_data(&cell_proofs);
    assert_eq!(reassembled, app_data);

    Ok(())
}
```

## SBO State Validation

Once data inclusion is verified, the zkVM processes each SBO action:

```rust
fn process_sbo_actions(
    actions: Vec<SboAction>,
    state: &mut SboState,
) -> Result<()> {
    for action in actions {
        // 1. Verify BLS signature
        let signing_key = action.signing_key();
        verify_bls_signature(signing_key, &action.message(), &action.signature)?;

        // 2. Resolve identity (if named)
        let identity = resolve_identity(state, &action.creator)?;

        // 3. Check policy authorization
        let policy = get_effective_policy(state, &action.path)?;
        check_policy_allows(&policy, &identity, &action)?;

        // 4. Apply state transition
        apply_action(state, &action)?;
    }
    Ok(())
}
```

## Recursive Proof Verification

Each proof (except genesis) verifies the previous proof inside the zkVM:

```rust
fn main() {
    let input: BlockProofInput = env::read();

    // 1. Verify previous proof (recursive step)
    if let Some(prev_proof) = input.prev_proof {
        // RISC Zero's verify() syscall
        env::verify(PROGRAM_ID, &input.prev_proof_journal, &prev_proof)?;

        // Decode previous output
        let prev_output: BlockProofOutput = decode(&input.prev_proof_journal);

        // Verify header chain continuity
        assert_eq!(input.block_header.parent_hash, prev_output.block_hash);
        assert_eq!(input.block_header.number, prev_output.block_number + 1);
        assert_eq!(input.prev_state_root, prev_output.new_state_root);
    } else {
        // Genesis case
        assert_eq!(input.block_header.number, 0);
        assert_eq!(input.prev_state_root, EMPTY_STATE_ROOT);
    }

    // 2. Verify data inclusion (KZG + Merkle)
    verify_data_inclusion(
        &input.block_header,
        &input.app_data,
        &input.data_proof,
        &input.row_commitments,
        &input.cell_proofs,
    )?;

    // 3. Process SBO actions
    let mut state = SboState::with_root(input.prev_state_root);
    let actions = parse_sbo_actions(&input.app_data);
    process_sbo_actions(actions, &mut state)?;

    // 4. Commit output
    let output = BlockProofOutput {
        prev_state_root: input.prev_state_root,
        new_state_root: state.root(),
        block_number: input.block_header.number,
        block_hash: input.block_header.hash(),
        version: 1,
    };
    env::commit(&output);
}
```

## State Management

The zkVM cannot store the full state; it only works with state roots. State is managed outside the zkVM:

```rust
/// State witness for zkVM
struct StateWitness {
    /// Merkle proofs for all paths accessed during this block
    path_proofs: HashMap<Path, MerkleProof>,

    /// Current values at those paths
    values: HashMap<Path, Option<SboObject>>,
}

impl SboState {
    fn get(&self, path: &Path) -> Option<&SboObject> {
        // Verify Merkle proof from witness
        let proof = self.witness.path_proofs.get(path)?;
        verify_merkle_proof(proof, self.root, path)?;
        self.witness.values.get(path).flatten()
    }

    fn set(&mut self, path: &Path, value: SboObject) {
        // Update Merkle tree and recompute root
        self.witness.values.insert(path.clone(), Some(value));
        self.root = compute_new_root(&self.witness);
    }
}
```

## Cryptographic Choices

### Signatures: BLS12-381

SBO will support BLS12-381 signatures for zkVM efficiency:
- RISC Zero has accelerated BLS12-381 precompiles (13x cost reduction)
- Signature aggregation possible (batch verify multiple sigs)
- Same curve as Avail's KZG commitments

```
Signing-Key: bls12-381:<hex-pubkey>
Signature: <hex-signature>
```

Ed25519 remains supported for backwards compatibility but will be slower in proofs.

### Hash: SHA-256

SHA-256 for all Merkle trees:
- RISC Zero has accelerated SHA-256 precompile (68 cycles per block)
- Well-audited, widely used

### KZG: BLS12-381 with Avail's SRS

KZG proofs use:
- Avail's Structured Reference String (derived from Filecoin's Powers of Tau)
- Accelerated via RISC Zero's `blst` fork

## Crate Architecture

To support zkVM compilation, SBO code must be split into `no_std` compatible crates:

```
reference_impl/
├── sbo-common/          # Types, wire format, merkle (no_std)
│   ├── types.rs         # Path, Uri, Action, etc.
│   ├── wire.rs          # Message parsing
│   └── merkle.rs        # SHA-256 merkle tree
│
├── sbo-crypto/          # BLS + ed25519 (no_std)
│   ├── bls.rs           # BLS12-381 signatures
│   ├── ed25519.rs       # Ed25519 signatures
│   └── hash.rs          # SHA-256
│
├── sbo-policy/          # Policy evaluation (no_std)
│   ├── types.rs         # Policy, Rule types
│   ├── evaluate.rs      # Policy checking
│   └── path.rs          # Path matching
│
├── sbo-db/              # RocksDB storage (std only)
│   └── db.rs            # State persistence
│
├── sbo-zkvm/            # RISC Zero guest program
│   ├── guest/
│   │   └── main.rs      # zkVM entry point
│   └── host/
│       └── prover.rs    # Proof generation
│
├── sbo-core/            # Facade (re-exports)
│   └── lib.rs
│
└── sbo-daemon/          # Full node + prover
    └── main.rs
```

## Light Client Protocol

A light client verifies state with:

```rust
struct LightClientState {
    /// Latest verified Avail header
    avail_header: AvailHeader,

    /// Latest verified SBO proof output
    sbo_proof_output: BlockProofOutput,

    /// Verified SBO state root
    state_root: Hash,
}

impl LightClient {
    /// Update to a new proof
    fn update(&mut self,
              new_header: AvailHeader,
              new_proof: Proof,
              new_journal: Vec<u8>) -> Result<()> {
        // 1. Verify header against Avail LC
        self.verify_avail_header(&new_header)?;

        // 2. Verify ZK proof
        verify_groth16_proof(VERIFIER_KEY, &new_journal, &new_proof)?;

        // 3. Decode journal
        let output: BlockProofOutput = decode(&new_journal);

        // 4. Check proof is for this header
        assert_eq!(output.block_hash, new_header.hash());

        // 5. Update state
        self.avail_header = new_header;
        self.sbo_proof_output = output;
        self.state_root = output.new_state_root;

        Ok(())
    }

    /// Query an object with proof
    fn get_object(&self, path: &Path) -> Result<(Option<SboObject>, MerkleProof)> {
        // Fetch from any node, verify Merkle proof against state_root
        let (obj, proof) = fetch_with_proof(path)?;
        verify_merkle_proof(&proof, self.state_root, path)?;
        Ok((obj, proof))
    }
}
```

## Proof Generation

Proofs can be generated by anyone with the chain data:

```rust
async fn generate_proof(
    prev_proof: Option<(Proof, Vec<u8>)>,
    block_number: u64,
) -> Result<(Proof, Vec<u8>)> {
    // 1. Fetch block header and data from Avail
    let header = avail_client.get_header(block_number).await?;
    let app_data = avail_client.get_app_data(APP_ID, block_number).await?;

    // 2. Fetch data inclusion proofs
    let data_proof = avail_client.get_data_proof(APP_ID, block_number).await?;
    let cell_proofs = avail_client.get_cell_proofs(APP_ID, block_number).await?;

    // 3. Fetch state witness from full node
    let state_witness = full_node.get_state_witness(block_number).await?;

    // 4. Construct zkVM input
    let input = BlockProofInput {
        prev_proof_journal: prev_proof.as_ref().map(|(_, j)| j.clone()),
        prev_proof: prev_proof.map(|(p, _)| p),
        block_header: header,
        app_data,
        data_proof,
        row_commitments: extract_row_commitments(&header, APP_ID),
        cell_proofs,
        prev_state_root: state_witness.root,
    };

    // 5. Generate proof
    let env = ExecutorEnv::builder()
        .write(&input)?
        .build()?;

    let prover = default_prover();
    let receipt = prover.prove(env, GUEST_ELF)?;

    Ok((receipt.inner.groth16()?, receipt.journal.bytes))
}
```

## Performance Estimates

Based on RISC Zero R0VM 2.0 benchmarks:

| Operation | Estimated Cycles | Notes |
|-----------|-----------------|-------|
| BLS sig verify | ~10K | Accelerated precompile |
| SHA-256 (64B) | 68 | Accelerated precompile |
| KZG verify | ~50K | BLS12-381 pairing |
| Merkle verify (32 hashes) | ~2K | 32 * 68 cycles |
| Policy evaluation | ~5K | Depends on complexity |
| Recursive proof verify | ~500K | One verify per block |

For a typical block with 10 actions:
- ~100K cycles for BLS signatures
- ~50K cycles for KZG verification
- ~10K cycles for Merkle proofs
- ~500K cycles for recursion
- **Total: ~700K cycles**

Proving time: ~10-30 seconds on modern hardware with GPU acceleration.

## Open Questions

1. **Proof Aggregation**: Can we batch multiple block proofs? RISC Zero supports proof aggregation which could amortize recursion overhead.

2. **Prover Incentives**: Who generates proofs? Options:
   - App developers run provers for their app IDs
   - Users generate proofs client-side (slower)
   - Decentralized prover market (Boundless)

3. **State Witness Distribution**: Full nodes must provide state witnesses. Protocol for this?

4. **Proof Freshness**: How often should proofs be generated? Per-block? Periodic batches?

5. **Backward Compatibility**: How to handle pre-ZK data? Re-prove from genesis?

## Implementation Phases

### Phase 1: Foundation
- Split sbo-core into no_std crates
- Add BLS12-381 signature support
- Implement Merkle state tree

### Phase 2: zkVM Guest
- Create RISC Zero guest program skeleton
- Implement header chain verification
- Implement SBO action processing (without KZG)

### Phase 3: Full DA Integration
- Add KZG verification using accelerated blst
- Implement data inclusion proofs
- Test with Avail testnet data

### Phase 4: Recursion
- Enable recursive proof verification
- Genesis proof generation
- Full chain proving

### Phase 5: Light Client
- Light client library
- State query protocol
- Proof distribution

## References

- [RISC Zero Precompiles](https://dev.risczero.com/api/zkvm/precompiles)
- [Avail Light Client](https://github.com/availproject/avail-light)
- [Avail Core (kate)](https://github.com/availproject/avail-core)
- [RISC Zero R0VM 2.0](https://risczero.com/blog/introducing-R0VM-2.0)
