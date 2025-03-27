
# SBO Bridge Specification (v0.1)

## Status
Draft

## Overview

This document defines the behavior and conventions of a canonical SBO bridge mechanism. It enables SBO objects (such as NFTs) to be transferred into a special path (e.g. `/bridge`) and locked while being represented on a remote chain (e.g. as an ERC-721 token). Objects may only be unlocked and returned via presentation of a verifiable proof of burn on the remote chain.

---

## Bridge Workflow

### 1. **Bridge In (Lock)**

- A user moves (transfers) an SBO object from their namespace into the `/bridge` path, e.g.:
  ```
  sbo://Avail:13/bridge/userA/punk-001
  ```
- The object is governed by a policy under `/bridge` which:
  - Locks the object (no updates allowed)
  - Prevents further transfers except via authorized bridge logic

### 2. **Remote Mint**

- A wrapped version of the SBO object is minted as an ERC-721 on the remote chain
- Token metadata includes:
  - Original SBO URI
  - Content hash
  - Optional bridge object reference

### 3. **Bridge Out (Unlock)**

- The user provides a **proof of burn** (or transfer to a burn address) on the remote chain
- The proof is submitted (as a separate SBO object with schema `proof.v1`)
- A helper or user transfers the locked object out of `/bridge/...` and back to a user-owned namespace
- The `/bridge` policy must:
  - Validate the proof
  - Prevent reuse (replay protection)
  - Allow the unlock only if valid

---

## Path Convention

Bridge objects must reside under a well-known namespace (default: `/bridge`). This may be extended for multi-chain bridges, e.g.:

```
/bridge/Ethereum/userA/punk-001
/bridge/Polygon/userB/digital-sword
```

---

## Policy Requirements

The policy object for `/bridge` must:
- Deny any posts or updates to objects under `/bridge/**`
- Deny any `transfer` actions unless:
  - A valid `proof.v1` object is presented and verified
- Optionally log all accepted proofs under:
  ```
  /bridge/proofs-used/{proof_hash}
  ```

---

## Proof Format (`proof.v1`)

The format of a `proof.v1` object is to be defined, but should include:

```json
{
  "schema": "proof.v1",
  "chain": "Ethereum",
  "block": 12345678,
  "tx_hash": "0xabc...",
  "burned_token_id": "0xdef...",
  "target_object": "sbo://Avail:13/userA/punk-001",
  "signature": "..."
}
```

Validation is policy-specific but may include:
- Verifying inclusion of `tx_hash` in Ethereum block `block`
- Matching `burned_token_id` with the object’s URI hash
- Signature validation from bridge contract or authorized relay

---

## Replay Protection

Policies must track previously accepted proofs (e.g., by tx hash or proof hash) and reject duplicates. Accepted proofs may be stored under `/bridge/proofs-used`.

---

## URI Conventions

While in the bridge:
- The object’s SBO URI becomes `/bridge/...`
- A `related` field may record:
  ```yaml
  - relation: "origin"
    target: "sbo://Avail:13/userA/punk-001"
  - relation: "remote_replica"
    target: "eth://0xabc123/token/0xdef456"
  ```

On return:
- The object is moved back to a user-controlled namespace
- Optionally annotated with return metadata (e.g., round-trip count)

---

## SDK Responsibilities

- Validate `/bridge` policy logic before allowing posts, transfers, or proof submissions
- Enforce content immutability of bridged objects
- Support lookup of bridge status for a given SBO object
- Provide tools to validate or construct `proof.v1` objects off-chain

---

## Future Extensions

- ZK-proof-based bridge unlocks
- Automatic bridge agents (bots or DAOs)
- Royalties or cross-chain fees
- Notifications of state change via side channels

---
