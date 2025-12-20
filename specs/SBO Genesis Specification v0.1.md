---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Genesis Specification (v0.1)

## Status
Draft

## Overview

This document defines how an SBO database is bootstrapped from an empty state. It addresses the circular dependency problem (validating objects requires policies, but policies are objects) by specifying special genesis rules.

Genesis supports two modes based on the desired trust model:
- **Mode A: Self-signed sys** - sys is the root of trust (personal repos, sovereign users)
- **Mode B: Domain-certified sys** - domain is the root of trust (organizations, enterprises)

---

## Genesis Modes

### Mode A: Self-signed sys

The sys identity is self-signed and serves as the root of trust.

**Genesis block contains (in order):**
```
1. POST /sys/names/sys         → self-signed system identity
2. POST /sys/policies/root     → root policy (signed by sys)
```

**Use cases:** Personal repos, sovereign users, development environments.

### Mode B: Domain-certified sys

A domain is established first, then sys is certified by that domain.

**Genesis block contains (in order):**
```
1. POST /sys/domains/<domain>  → self-signed domain identity
2. POST /sys/names/sys         → domain-certified system identity
3. POST /sys/policies/root     → root policy (signed by sys)
```

**Use cases:** Organizations, enterprises, multi-tenant platforms.

---

## Genesis Objects

All identity and domain objects use JWT format as defined in [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md).

### Domain Object (Mode B only)

```
SBO-Version: 0.5
Action: post
Path: /sys/domains/
ID: example.com
Type: object
Content-Type: application/jwt
Content-Schema: domain.v1
Public-Key: ed25519:<DOMAIN_KEY>
Signature: <signature>

<JWT>
```

**JWT Payload:**
```json
{
  "iss": "self",
  "sub": "example.com",
  "public_key": "ed25519:<DOMAIN_KEY>",
  "iat": 1703001234
}
```

**Validation:**
- `iss` MUST be `"self"`
- JWT MUST be signed by `public_key` in payload
- `Public-Key` header MUST match `public_key` in payload

### System Identity (`/sys/names/sys`)

**Mode A (self-signed):**
```
SBO-Version: 0.5
Action: post
Path: /sys/names/
ID: sys
Type: object
Content-Type: application/jwt
Content-Schema: identity.v1
Public-Key: ed25519:<SYS_KEY>
Signature: <signature>

<JWT>
```

**JWT Payload (Mode A):**
```json
{
  "iss": "self",
  "sub": "sys",
  "public_key": "ed25519:<SYS_KEY>",
  "iat": 1703001234
}
```

**Mode B (domain-certified):**

**JWT Payload (Mode B):**
```json
{
  "iss": "domain:example.com",
  "sub": "sys@example.com",
  "public_key": "ed25519:<SYS_KEY>",
  "iat": 1703001234
}
```
JWT is signed by the domain key from `/sys/domains/example.com`.

**Validation:**
- If `iss: "self"` → JWT signed by `public_key` in payload
- If `iss: "domain:<domain>"` → JWT signed by domain key from `/sys/domains/<domain>`
- `Public-Key` header MUST match `public_key` in payload

### Root Policy (`/sys/policies/root`)

```
SBO-Version: 0.5
Action: post
Path: /sys/policies/
ID: root
Type: object
Content-Type: application/json
Content-Schema: policy.v2
Public-Key: ed25519:<SYS_KEY>
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
- Must be signed by the sys key (from `/sys/names/sys`)

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

### Mode A Validation

```
1. /sys/names/sys and /sys/policies/root must be present in same block
2. /sys/names/sys:
   - Valid identity.v1 JWT with iss: "self"
   - Self-signed (JWT signature matches public_key in payload)
   - Public-Key header matches public_key in payload
3. /sys/policies/root:
   - Valid policy.v2 schema
   - Signed by sys key
4. All signatures must be cryptographically valid
```

### Mode B Validation

```
1. /sys/domains/<domain>, /sys/names/sys, and /sys/policies/root in same block
2. /sys/domains/<domain>:
   - Valid domain.v1 JWT with iss: "self"
   - Self-signed (JWT signature matches public_key in payload)
   - Must appear FIRST in block order
3. /sys/names/sys:
   - Valid identity.v1 JWT with iss: "domain:<domain>"
   - Signed by domain key from step 2
   - Public-Key header matches public_key in payload
4. /sys/policies/root:
   - Valid policy.v2 schema
   - Signed by sys key
5. All signatures must be cryptographically valid
```

After genesis validation succeeds, all subsequent objects are validated using normal policy rules.

---

## Genesis Detection

Clients identify genesis mode as follows:

```
1. Start at block 0 (or first block with data for this appId)
2. Scan for /sys/domains/*, /sys/names/sys, and /sys/policies/root
3. If /sys/domains/* present → Mode B
4. If only /sys/names/sys and /sys/policies/root → Mode A
5. Validate according to detected mode
6. If validation fails → database is invalid
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
- `genesis_hash` is `sha256(all_genesis_objects_bytes)`

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
/sys/domains/example.com    → domain identity (Mode B, or added post-genesis)
/sys/names/sys              → system identity
/sys/names/alice            → user identity
/sys/names/bob              → user identity
/sys/policies/root          → root policy
/sys/policies/...           → additional policies
/sys/checkpoints/...        → state checkpoints

/alice/...                  → alice's namespace
/bob/...                    → bob's namespace
```

All identities live under `/sys/names/`. Domains live under `/sys/domains/`. User namespaces are top-level paths matching their identity name.

---

## Post-Genesis Operations

### Adding Domains

After genesis, sys (or authorized identities per policy) can create additional domains:

```
POST /sys/domains/other.com
```

See [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md) for domain schema.

### User Identity Claims

Users claim identities by posting to `/sys/names/*`. Identities may be:
- **Self-signed** (`iss: "self"`) - for sovereign users
- **Domain-certified** (`iss: "domain:<domain>"`) - for email-verified users

See [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md) for identity schema and validation rules.

After claiming an identity:
- User can post to `/{name}/**` (owner rule)
- User can update `/sys/names/{name}` (owner of that object)
- No one else can modify `/sys/names/{name}`

---

## Action Types

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

## References

- [SBO Identity Specification v0.1](./SBO%20Identity%20Specification%20v0.1.md)
- [SBO Specification v0.4](./SBO%20Specification%20v0.4.md)
- [SBO Policy Specification v0.2](./SBO%20Policy%20Specification%20v0.2.md)
