
# SBO Genesis Specification (v0.1)

## Status
Draft

## Overview

This document defines how an SBO database is bootstrapped from an empty state. It addresses the circular dependency problem (validating objects requires policies, but policies are objects) by specifying special genesis rules and establishing the `sys` identity as the system administrator.

---

## Genesis Block Requirements

A valid genesis block must contain exactly two objects, signed by the same key:

```
POST /sys/names/sys         → system identity claim
POST /sys/policies/root     → root policy
```

**Order in block:**
1. `/sys/names/sys` first — establishes the `sys` identity
2. `/sys/policies/root` second — establishes governance rules

Both objects must be signed by the same key. This key becomes the initial system administrator.

---

## Genesis Objects

### System Identity (`/sys/names/sys`)

```
SBO-Version: 1
Action: Create
Path: /sys/names/
Id: sys
Content-Type: application/json
Content-Schema: identity.v1
Public-Key: ed25519:abc123...
Signature: <signature>

{
  "public_key": "ed25519:abc123...",
  "display_name": "System"
}
```

**Validation:**
- Must be valid `identity.v1` schema (see [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md))
- Must be self-signed (`Signing-Key` header == `public_key` in payload)

### Root Policy (`/sys/policies/root`)

```
SBO-Version: 1
Action: Create
Path: /sys/policies/
Id: root
Content-Type: application/json
Content-Schema: policy.v2
Public-Key: ed25519:abc123...
Signature: <signature>

{
  "grants": [
    {"to": "*", "can": ["create"], "on": "/sys/names/*"},
    {"to": "owner", "can": ["update", "delete"], "on": "/sys/names/*"},
    {"to": "owner", "can": ["*"], "on": "/$owner/**"}
  ]
}
```

**Validation:**
- Must be valid `policy.v2` schema
- Must be signed by the same key as `/sys/names/sys`

---

## Default Root Policy

The recommended default root policy establishes:

| Rule | Effect |
|------|--------|
| `{"to": "*", "can": ["create"], "on": "/sys/names/*"}` | Anyone can claim a new identity (first-come-first-served) |
| `{"to": "owner", "can": ["update", "delete"], "on": "/sys/names/*"}` | Only the signer can modify their identity |
| `{"to": "owner", "can": ["*"], "on": "/$owner/**"}` | Users control their own namespace |

This policy is recommended but not required. Deployers may use different policies for different governance models.

---

## Genesis Validation

Genesis objects are validated with special rules since no prior state exists:

```
1. Both objects must be present in the same block
2. Both must be signed by the same key
3. /sys/names/sys:
   - Valid identity.v1 schema
   - Self-signed (Signing-Key matches public_key)
4. /sys/policies/root:
   - Valid policy.v2 schema
   - Signed by sys key
5. Signatures must be cryptographically valid
```

After genesis validation succeeds, all subsequent objects are validated using normal policy rules.

---

## Genesis Detection

Clients identify genesis as follows:

```
1. Start at block 0 (or first block with data for this appId)
2. Scan for /sys/names/sys and /sys/policies/root
3. If both present and valid → genesis found
4. If missing or invalid → database is invalid
```

**Conflict resolution:**
- If multiple genesis attempts exist in the same block, first in block order wins
- Genesis objects in different blocks are invalid
- Later attempts to post genesis objects are rejected by normal policy rules

---

## Database Identity

The canonical identity of an SBO database is:

```
{chain}:{appId}:{genesis_hash}
```

Where:
- `chain` is a CAIP-2 chain identifier (e.g., `avail:mainnet`)
- `appId` is the application ID on that chain
- `genesis_hash` is `sha256(sys_identity_bytes || root_policy_bytes)`

**Example:**
```
avail:mainnet:13:sha256:abc123def456...
```

The genesis hash ensures that two databases with the same chain:appId but different genesis content are distinguishable.

---

## URI Schemes

SBO supports two URI schemes for addressing objects:

### DNS-Resolved (`sbo://`)

```
sbo://myapp.com/dan/foo
```

Resolution:
1. DNS TXT lookup for `_sbo.myapp.com`
2. Record contains: `chain=avail:mainnet appId=13 genesis=sha256:abc123 checkpoint=https://...`
3. Client resolves to canonical database identity

**DNS TXT record format:**
```
_sbo.myapp.com TXT "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc123... checkpoint=https://myapp.com/sbo/checkpoint.json"
```

### Direct Chain Reference (`sbo+raw://`)

```
sbo+raw://avail:mainnet:13/dan/foo
```

With explicit genesis (for full disambiguation):
```
sbo+raw://avail:mainnet:13/dan/foo?genesis=sha256:abc123...
```

**Components:**
- `avail:mainnet` — CAIP-2 chain identifier
- `13` — appId
- `genesis=sha256:abc123...` — optional genesis hash

---

## Chain Identifiers

Chain names use CAIP-2 format (Chain Agnostic Improvement Proposals):

| Chain | CAIP-2 Identifier |
|-------|-------------------|
| Avail mainnet | `avail:mainnet` |
| Avail testnet | `avail:testnet` |
| Celestia mainnet | `celestia:mainnet` |
| Ethereum mainnet | `eip155:1` |

New chains should be registered in the CAIP-2 namespace.

---

## Bootstrapping

### Via DNS

```
1. Client sees sbo://myapp.com/dan/foo
2. DNS TXT lookup _sbo.myapp.com
   → chain, appId, genesis_hash, checkpoint_url
3. Fetch checkpoint from URL
4. Verify checkpoint references expected genesis_hash
5. Sync from checkpoint state
```

### Via Direct URI

```
1. Client sees sbo+raw://avail:mainnet:13/dan/foo?genesis=sha256:abc123
2. Parse chain, appId, genesis_hash
3. Connect to DA layer
4. If genesis block available:
   → Validate genesis objects
   → Verify hash matches expected
   → Sync from genesis
5. If genesis pruned:
   → Fetch checkpoint from known source
   → Verify checkpoint references genesis_hash
   → Sync from checkpoint
```

### Genesis Pruning

DA layers may prune old blocks. When genesis block is unavailable:
- Clients must bootstrap from a trusted checkpoint
- Checkpoints include `genesis_hash` for verification
- Trust in checkpoint transitively establishes trust in genesis

---

## Path Structure

After genesis, the path structure is:

```
/sys/names/sys              → system identity
/sys/names/alice            → user identity
/sys/names/bob              → user identity
/sys/policies/root          → root policy
/sys/policies/...           → additional policies
/sys/checkpoints/...        → state checkpoints

/alice/...                  → alice's namespace
/bob/...                    → bob's namespace
```

All identities live under `/sys/names/`. User namespaces are top-level paths matching their identity name.

---

## Post-Genesis Identity Claims

After genesis, users claim identities by posting to `/sys/names/*`:

```
SBO-Version: 1
Action: Create
Path: /sys/names/
Id: alice
Content-Type: application/json
Content-Schema: identity.v1
Public-Key: ed25519:def456...
Signature: <signature>

{
  "public_key": "ed25519:def456...",
  "display_name": "Alice"
}
```

**Validation:**
1. Policy check: root policy allows `create` on `/sys/names/*` for anyone
2. Schema check: `identity.v1` requires self-signing
3. Path check: `/sys/names/alice` must not already exist

After claiming:
- Alice can post to `/alice/**` (owner rule)
- Alice can update `/sys/names/alice` (owner of that object)
- No one else can modify `/sys/names/alice`

---

## Action Types (Updated)

The `post` action is split into `create` and `update`:

| Action | Meaning |
|--------|---------|
| `create` | Post to a path that doesn't exist |
| `update` | Modify an existing object |
| `post` | Shorthand for create + update |
| `delete` | Remove an object |
| `transfer` | Move, rename, and/or change ownership |
| `import` | Create object from cross-chain import |

This distinction allows policies to grant `create` without `update` (e.g., first-come-first-served naming).

---

## Compatibility

- Genesis validation is a one-time operation at database initialization
- After genesis, standard SBO validation rules apply
- Existing specs (Wire Format, Policy, State Commitment) apply unchanged
- URI schemes extend the existing URI specification

---
