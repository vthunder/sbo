# ZK Proof Testing Infrastructure Design

## Overview

This document describes the infrastructure for testing ZK validity proofs in SBO, enabling light clients to sync by verifying proofs instead of re-executing all actions.

**Primary use case**: Light client sync - clients verify proofs cryptographically, trusting the proven state without re-execution.

**Architecture**: Prover daemon mode extends sbo-daemon to generate and publish proofs. Light client mode verifies proofs and can verify individual object inclusion.

## Message Types

All message types share the same Avail app_id per repository. Messages are distinguished by their version header prefix.

### SBOP - Block Proof Message

Published by prover after generating proof for a block range.

```
SBOP-Version: 0.1
Block-From: 1
Block-To: 100
Receipt-Kind: succinct
Receipt-Length: 45678
Content-Encoding: base64

<base64 encoded receipt bytes>
```

**Headers**:
- `SBOP-Version`: Protocol version
- `Block-From`: First block covered by this proof
- `Block-To`: Last block covered by this proof
- `Receipt-Kind`: One of `composite`, `succinct`, `groth16`
- `Receipt-Length`: Decoded byte length of receipt
- `Content-Encoding`: Always `base64` for now

**Payload**: Base64-encoded RISC Zero receipt containing the journal with:
- `prev_state_root`: State root before Block-From
- `new_state_root`: State root after Block-To
- `block_number`: Same as Block-To
- `block_hash`: Hash of Block-To
- `data_root`: Avail data root (for DA verification)
- `version`: Protocol version

### SBOQ - Object Query/Proof Message

Response to object query with merkle proof against state root.

```
SBOQ-Version: 0.1
Block: 100
Path: /alice/identity
State-Root: a1b2c3d4...
Object-Length: 1234
Proof-Length: 512
Content-Encoding: base64

<base64 object data>

<base64 merkle proof>
```

**Headers**:
- `SBOQ-Version`: Protocol version
- `Block`: Block number this proof applies to
- `Path`: Full SBO path (e.g., `/alice/identity`)
- `State-Root`: Hex-encoded state root (must match proven root)
- `Object-Length`: Decoded byte length of object
- `Proof-Length`: Decoded byte length of merkle proof
- `Content-Encoding`: Always `base64` for now

**Payload**: Two sections separated by blank line:
1. Base64-encoded object data
2. Base64-encoded merkle inclusion proof

## Daemon Modes

### Full Node Mode (default)

```bash
sbo daemon start
```

- Syncs blocks from Avail
- Re-executes all actions
- Updates StateDb with computed state
- **New**: Verifies any SBOP messages against historical state roots
- Alerts on discrepancy between proven and computed state

### Prover Mode

```bash
sbo daemon start --prover
```

Everything from full node mode, plus:
- Generates proofs after processing blocks
- Submits SBOP messages to Avail
- Stores proofs locally in `~/.sbo/proofs/<repo>/<block>.proof`
- Configurable batch size (blocks per proof)

### Light Client Mode

```bash
sbo daemon start --light
```

- Scans for SBOP messages on app_id
- Verifies proofs cryptographically
- Trusts proven state roots
- Re-executes only blocks after last proof
- Can request SBOQ proofs for specific objects

## State Root Design

### Current (Transition Root)

```
state_root = sha256(prev_state_root || actions_data)
```

Commits to the transition, not the state. Cannot prove individual objects.

### Required (Merkle State Root)

```
state_root = merkle_root({
    sha256(path1 || object1_data),
    sha256(path2 || object2_data),
    ...
})
```

Commits to actual state. Enables O(log n) inclusion proofs for any object.

**Tradeoff**: Only full nodes can compute (need all objects), but provers are full nodes anyway.

## Testing Architecture

### Path A: Full Node Proof Verification

Full node processes blocks AND verifies proofs, checking for discrepancies.

**StateDb additions**:
```rust
// Track state root per block
fn record_block_state_root(block: u64, state_root: [u8; 32]);
fn get_state_root_at_block(block: u64) -> Option<[u8; 32]>;
```

**Sync engine addition**:
```rust
// After processing block, check for proof
if let Some(proof_msg) = find_proof_covering_block(block_data) {
    let journal = verify_receipt(&proof_msg.receipt_bytes)?;
    let our_state_root = get_state_root_at_block(journal.block_number)?;

    if journal.new_state_root != our_state_root {
        error!("DISCREPANCY at block {}: proof={} computed={}",
               journal.block_number,
               hex(&journal.new_state_root),
               hex(&our_state_root));
    } else {
        info!("Block {} proof verified", journal.block_number);
    }
}
```

**What this tests**: Prover correctness - same inputs produce same state root.

### Path B: Light Client + Object Proofs

Light client verifies block proofs, then verifies object inclusion.

**CLI commands**:
```bash
# Prover generates object proof
sbo zkvm prove-object /alice/identity --block 100 --output alice.sboq

# Light client verifies
sbo zkvm verify-object alice.sboq
```

**Verification flow**:
1. Parse SBOQ message
2. Check `State-Root` matches a proven state root from SBOP
3. Verify merkle proof: `verify_proof(path, object, proof, state_root)`
4. Return object if valid

**What this tests**: Full light client flow - proof verification + object inclusion.

## Configuration

### Config file additions (`~/.sbo/config.toml`)

```toml
[prover]
enabled = false           # or use --prover flag
batch_size = 1            # blocks per proof (1 = every block)
receipt_kind = "succinct" # composite, succinct, groth16
dev_mode = true           # RISC0_DEV_MODE for testing

[light]
enabled = false           # or use --light flag
verify_objects = true     # verify object proofs when requested
```

## CLI Commands

### Proof Generation

```bash
# Generate proof for specific block (manual)
sbo zkvm prove --block 100

# Generate proof for block range
sbo zkvm prove --from 1 --to 100

# Compress existing proof
sbo zkvm compress proof.sbop --kind groth16
```

### Proof Verification

```bash
# Verify a block proof
sbo zkvm verify proof.sbop

# Verify object inclusion
sbo zkvm verify-object alice.sboq
```

### Object Proofs

```bash
# Generate object proof (requires full state)
sbo zkvm prove-object /alice/identity --block 100

# Query and verify object from light client
sbo get /alice/identity --with-proof
```

## Implementation Phases

### Phase 1: Core Infrastructure
- SBOP message format (parse/serialize)
- StateDb: track state roots per block
- zkVM: BlockProofInput from actual block data

### Phase 2: Prover Daemon
- `--prover` flag for daemon
- Proof generation after block processing
- SBOP submission to Avail
- Local proof storage

### Phase 3: Full Node Verification
- Detect SBOP messages in sync
- Verify against historical state roots
- Log discrepancies

### Phase 4: Merkle State Root
- Change state root computation to merkle tree
- Incremental tree updates
- Store tree structure or recompute

### Phase 5: Light Client Mode
- `--light` flag for daemon
- Proof-only sync
- Re-execute post-proof blocks

### Phase 6: Object Proofs
- SBOQ message format
- Merkle inclusion proofs
- CLI commands for prove/verify objects

## Deferred

- **Snapshots**: Full state dumps aligned with proofs (SBOS messages)
- **On-chain verification**: Groth16 proofs for Ethereum bridges
- **Proof aggregation**: Combine multiple proofs into one
