---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Genesis Specification

**Part of SBO Protocol v0.5**

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

All identity and domain objects use JWT format as defined in [SBO Identity Specification](./SBO%20Identity%20Specification.md).

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

## Trust Anchors

To authorize **email-rooted** identities (the default — see the [Identity Specification](./SBO%20Identity%20Specification.md)), a repository establishes two governance-maintained trust objects, defined in the [Authorization Specification](./SBO%20Authorization%20Specification.md):

- `/sys/trust/dns-root` (`dns-root.v1`) — the pinned DNS root KSK history; the single anchor for DNSSEC attribution.
- `/sys/trust/brokers` (`brokers.v1`) — recognized fallback brokers (optional; only needed to accept emails whose domain runs no provider).

These are ordinary `sys`-signed objects (authorized by the `sys` key under the root policy), not specially-validated genesis objects. They SHOULD be established at genesis or immediately after, so email-rooted writes can be authorized from the start. A repository that uses only key-rooted identities does not require them.

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

The canonical identity of an SBO database is the 4-tuple:

```
{chain}:{appId}:{firstBlock}:{genesisHash}
```

Where:
- `chain` is a CAIP-2 chain identifier (e.g., `avail:mainnet`)
- `appId` is the application ID on that chain
- `firstBlock` is the block the genesis lives at — the **locator** (makes the database scannable; disambiguates the same genesis replayed at two heights)
- `genesisHash` is `sha256(all_genesis_objects_bytes)` — the content-derived **verifying** identity

**Example:**
```
avail:mainnet:13:1000:sha256:abc123def456...
```

See the [URI Specification — Database Identity](./SBO%20URI%20Specification.md#database-identity) for the reference-vs-identity rules (a reference may carry the anchor, the hash, or both; an ambiguous anchor-only reference MUST error rather than guess).

---

## URI Schemes

SBO supports two URI schemes for addressing objects:

### DNS-Resolved (`sbo://`)

```
sbo://myapp.com/dan/foo
```

Resolution:
1. DNS TXT lookup for `_sbo.myapp.com`
2. Record's `repo=` carries chain, appId, and the `@firstBlock` anchor; `genesis=` carries the hash
3. Client resolves to canonical database identity

**DNS TXT record format** (see the [URI Specification](./SBO%20URI%20Specification.md#dns-txt-record-format) for the full field list):
```
_sbo.myapp.com TXT "v=sbo1 repo=sbo+raw://avail:mainnet:13@1000/ genesis=sha256:abc123... node=https://sbo.myapp.com checkpoint=https://myapp.com/sbo/checkpoint.json"
```

### Direct Chain Reference (`sbo+raw://`)

```
sbo+raw://avail:mainnet:13@1000/dan/foo
```

With explicit genesis hash (verify / disambiguate a multi-genesis height):
```
sbo+raw://avail:mainnet:13@1000/dan/foo?genesis=sha256:abc123...
```

**Components:**
- `avail:mainnet` — CAIP-2 chain identifier
- `13` — appId
- `@1000` — genesis anchor (`firstBlock`); database-level, inherited by all paths
- `genesis=sha256:abc123...` — optional genesis hash (verify/disambiguate)

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
   → repo (chain, appId, @firstBlock), genesis hash, node/checkpoint URLs
3. Begin sync at @firstBlock (or fetch checkpoint for a mature DB)
4. Reconstruct genesis; if a genesis hash is known, verify it matches
5. Resolve the path against the synced state
```

### Via Direct URI

```
1. Client sees sbo+raw://avail:mainnet:13@1000/dan/foo?genesis=sha256:abc123
2. Parse chain, appId, @firstBlock anchor, genesis hash
3. Connect to DA layer
4. Begin sync at @firstBlock:
   → Validate genesis objects
   → If genesis hash present, verify it matches (else: require a single genesis at the anchor)
   → Sync forward from genesis
5. If genesis pruned:
   → Fetch checkpoint from node/known source
   → Verify checkpoint references the genesis hash
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

`/sys/domains/*` objects are **repository root-of-trust domains** (used to certify repository-internal identities such as `sys`). They are distinct from users' email-provider domains, which are attributed via DNSSEC and never stored on chain — see the two-senses-of-domain note in the [SBO Identity Specification](./SBO%20Identity%20Specification.md#domain-objects-domainv1).

### User Identity Claims

Users claim identities by posting to `/sys/names/*`. The default kind is **email-rooted**: a name record (`identity.email.v1`) whose `Owner` is the controlling email, authorized by DNSSEC-anchored attribution. **Key-rooted** identities (`identity.v1`, self-signed) remain available for self-sovereign users. A bare email may also own objects directly, without registering a name.

See the [SBO Identity Specification](./SBO%20Identity%20Specification.md) for identity kinds, schemas, and resolution, and the [SBO Authorization Specification](./SBO%20Authorization%20Specification.md) for how writes are authorized.

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

- [SBO Identity Specification](./SBO%20Identity%20Specification.md)
- [SBO Specification](./SBO%20Specification.md)
- [SBO Policy Specification](./SBO%20Policy%20Specification.md)
