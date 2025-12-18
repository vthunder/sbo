---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Bridge Specification (v0.2)

## Status
Draft

## Overview

This document defines the bridge mechanism for transferring assets between SBO and external blockchains (e.g., Ethereum). It covers two directions:

1. **Export (SBO → External):** Lock an SBO object, mint a wrapped token on the external chain
2. **Import (External → SBO):** Lock a token on the external chain, create an SBO object

The design uses trusted oracle attestations for cross-chain verification, with a pluggable architecture to support future verification methods (light clients, ZK proofs).

---

## Bridge Architecture

### Components

| Component | Role |
|-----------|------|
| Bridge policy | Governs `/sys/bridge/**` paths, enforces proof requirements |
| Oracle(s) | Trusted parties that attest to cross-chain events |
| Verifier | Policy-referenced object defining how to validate proofs |
| Registry | Tracks imported origins at `/sys/bridge/imported/**` |

### Trust Model

Oracles are trusted to accurately attest to events on external chains. The bridge policy specifies which oracle keys are trusted. Future versions may support trustless verification via light clients or ZK proofs.

---

## Export Flow (SBO → External → SBO)

### Step 1: Lock on SBO

User transfers their object to the bridge namespace:

```
SBO-Version: 0.5
Action: transfer
Path: /alice/
ID: punk-001
New-Owner: sys
New-Path: /sys/bridge/ethereum/alice/
Public-Key: secp256k1:...
Signature: ...
```

The object is now locked under `/sys/bridge/ethereum/`. The bridge policy prevents modifications and unauthorized transfers.

### Step 2: Mint on External Chain

Off-chain process:
1. Indexer observes the lock transaction
2. Bridge contract on Ethereum mints a wrapped ERC-721
3. Token metadata includes SBO origin and content hash

### Step 3: Burn on External Chain

When user wants to return the asset:
1. User calls burn function on the bridge contract
2. Burn event emitted with token details

### Step 4: Unlock on SBO

User transfers the object back with a burn proof:

```
SBO-Version: 0.5
Action: transfer
Path: /sys/bridge/ethereum/alice/
ID: punk-001
New-Owner: alice
New-Path: /alice/
Proof-Type: burn
Proof: <base64-encoded proof>
Public-Key: secp256k1:...
Signature: ...
```

The bridge policy verifies the proof before allowing the transfer.

---

## Import Flow (External → SBO)

### Step 1: Lock on External Chain

User deposits their token (e.g., ERC-721) into the bridge vault contract on the external chain.

### Step 2: Obtain Attestation

User requests an attestation from a trusted oracle:
- Oracle verifies the deposit transaction
- Oracle signs an attestation of the lock

### Step 3: Atomic Import

User submits an `import` action that atomically creates both the registry entry and the NFT object:

```
SBO-Version: 0.5
Action: import
Origin: ethereum:0xbc4ca:1234
Registry-Path: /sys/bridge/imported/eth-0xbc4ca-1234
Object-Path: /alice/imported/punk-1234
Attestation: <base64-encoded attestation>
Content-Type: application/json
Content-Schema: nft.v1
Content-Length: 456
Content-Hash: sha256:...
Public-Key: secp256k1:...
Signature: ...

{
  "name": "CryptoPunk #1234",
  "description": "Imported from Ethereum",
  "media": { ... },
  "origin": {
    "chain": "ethereum",
    "contract": "0xbc4ca...",
    "token_id": "1234"
  }
}
```

### Import Action Semantics

The `import` action performs these steps atomically:

1. **Verify attestation** — Check oracle signature is valid and trusted
2. **Check registry** — Verify `/sys/bridge/imported/{origin-hash}` doesn't exist
3. **Create registry entry** — Record the import at the registry path
4. **Create object** — Create the NFT at the user-specified path

If any step fails, the entire action fails and nothing is created.

### Registry Entry

The registry entry is auto-generated:

```json
{
  "origin": "ethereum:0xbc4ca:1234",
  "imported_by": "secp256k1:02abc...",
  "object_path": "/alice/imported/punk-1234",
  "attestation_hash": "sha256:...",
  "imported_at_block": 12345
}
```

The registry entry:
- Is owned by `sys` (immutable after creation)
- Serves as the uniqueness marker for this origin
- Records where the object was initially created (for provenance)
- Does NOT need updating when the object moves

---

## Proof Formats

### Lock Attestation (for imports)

Oracle attests that a token was locked in the vault:

```json
{
  "type": "lock",
  "origin": {
    "chain": "ethereum",
    "contract": "0xbc4ca...",
    "token_id": "1234"
  },
  "depositor": "0xabc...",
  "deposit_tx": "0xdef...",
  "deposit_block": 19000000,
  "oracle_key": "secp256k1:02xyz...",
  "signature": "..."
}
```

### Burn Attestation (for unlocks)

Oracle attests that a wrapped token was burned:

```json
{
  "type": "burn",
  "bridge_path": "/sys/bridge/ethereum/alice/punk-001",
  "content_hash": "sha256:abc...",
  "wrapped_token": {
    "chain": "ethereum",
    "contract": "0x1234...",
    "token_id": "5678"
  },
  "burn_tx": "0xdef...",
  "burn_block": 19500000,
  "oracle_key": "secp256k1:02xyz...",
  "signature": "..."
}
```

---

## Verifier Objects

Policies reference verifier objects that define trusted oracles:

```
Path: /sys/bridge/verifiers/ethereum
Content-Schema: verifier.v1

{
  "type": "trusted-signer",
  "chain": "ethereum",
  "trusted_keys": [
    "secp256k1:02abc...",
    "secp256k1:02def..."
  ],
  "quorum": 1
}
```

### Verifier Fields

| Field | Description |
|-------|-------------|
| `type` | Verification method (`trusted-signer`, `light-client`, `zk-proof`) |
| `chain` | Which external chain this verifier handles |
| `trusted_keys` | List of oracle public keys (for `trusted-signer` type) |
| `quorum` | Number of signatures required (default: 1) |

### Future Verifier Types

| Type | Description |
|------|-------------|
| `trusted-signer` | One or more trusted oracles sign attestations |
| `light-client` | Verify block headers and inclusion proofs |
| `zk-proof` | Cryptographic proof of chain state |

---

## Bridge Policy

The policy for `/sys/bridge/**` must:

1. **Deny updates** to locked objects
2. **Require valid proof** for transfers out of `/sys/bridge/**`
3. **Reference verifier** for proof validation

Example policy:

```json
{
  "deny": [],
  "grants": [
    {"to": "*", "can": ["transfer"], "on": "/sys/bridge/**"}
  ],
  "restrictions": [
    {
      "on": "/sys/bridge/ethereum/**",
      "require": {
        "verifier": "/sys/bridge/verifiers/ethereum",
        "proof_type": "burn"
      }
    }
  ]
}
```

---

## Path Conventions

```
/sys/bridge/
├── imported/                    # Registry of imported origins
│   ├── eth-0xbc4ca-1234        # Origin claim (immutable)
│   └── eth-0xdef0-5678
├── ethereum/                    # Objects locked for Ethereum bridge
│   └── alice/
│       └── punk-001            # Locked SBO object
├── polygon/                     # Objects locked for Polygon bridge
│   └── ...
└── verifiers/                   # Verifier configurations
    ├── ethereum
    └── polygon
```

---

## Replay Protection

### For Imports

- Registry path is derived from origin: `/sys/bridge/imported/{origin-hash}`
- Path can only be created once
- Atomic `import` action ensures registry + object created together
- Same origin cannot be imported twice

### For Unlocks

- Proof is bound to specific `content_hash` (can't use for different object)
- Proof is bound to specific `burn_tx` (can't forge new burns)
- After unlock, source path is empty (object moved)
- Creating new object at same bridge path would have different content hash

---

## Lite Client Verification

Lite clients can verify bridge operations using state proofs:

**For imports:**
- Prove `/sys/bridge/imported/{origin-hash}` exists or doesn't exist
- Standard inclusion/non-existence proof from state trie

**For locked objects:**
- Prove object exists at `/sys/bridge/{chain}/{path}`
- Verify content hash matches expected value

**For verifier trust:**
- Prove verifier object at `/sys/bridge/verifiers/{chain}`
- Check trusted keys match expected oracles

---

## Compatibility

- Export/unlock uses the existing `transfer` action with `Proof` header
- Import uses the new `import` action (atomic registry + object creation)
- Verifier objects use `verifier.v1` schema
- Registry entries use `origin-claim.v1` schema
- All proofs attached to actions, not stored as separate objects

---

## Migration from v0.1

| v0.1 | v0.2 |
|------|------|
| Separate `proof.v1` objects | Proofs attached to actions via `Proof` header |
| Unspecified proof validation | Verifier objects define validation rules |
| `/bridge/**` path | `/sys/bridge/**` path (under sys control) |
| No import flow | Atomic `import` action for external → SBO |

---
