---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Genesis Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v0.5 (2026-11, audit)**: Strict bootstrap rule (Q7): the only writes valid before a root policy exists are the mode objects of the genesis submission at the anchor, in order; everything after the root policy is validated normally (Q33). Self-certification is REQUIRED for Mode B (Q8). `genesisHash` is over the bytes as included on chain (Q35). `brokers.v1` is the object form `{ "brokers": [...] }` (Q2). More than one genesis at the anchor, or a `genesisHash` mismatch, halts sync (S19). The bootstrap window is defined precisely (S8).

## Overview

This document defines how an SBO database is bootstrapped from an empty state. It addresses the circular dependency problem (validating objects requires policies, but policies are objects) by specifying special genesis rules.

The rules are **fail-closed**: before a root policy exists, nothing is valid except the small, structurally checked set of genesis objects defined here, and only in the genesis submission at the anchor block. There is no "genesis mode" in which a repository accepts arbitrary writes until a root policy appears (see [Bootstrap Window](#bootstrap-window)).

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
1. POST /sys/dnssec/<domain>   → dnssec.v1 proof (REQUIRED)
2. POST /sys/domains/<domain>  → self-certified domain identity
3. POST /sys/names/sys         → domain-certified system identity
4. POST /sys/policies/root     → root policy (signed by sys)
```

**Mode B is self-certifying (REQUIRED).** Set the `domain.v1` key to the domain's
`_browserid` provider key, and seed a `dnssec.v1` object at `/sys/dnssec/<domain>`
(ordered **before** the domain object) carrying the `_browserid.<domain>` DNSSEC
chain captured at genesis-authoring time — its RRSIG windows must bracket the
genesis block time. The domain then certifies `sys` **and** is itself
DNSSEC-verifiable from state (see [Domain Objects](./SBO%20Identity%20Specification.md#domain-objects-domainv1), Validation Rule 4).
A Mode B genesis without step 1, or whose `dnssec.v1` evidence does not prove the
`domain.v1` key under `_browserid.<domain>` at the genesis block time, is **invalid**.
A domain that cannot be DNSSEC-proven is a plain self-signed key, and a repository
rooted in one is Mode A (the key, not the domain name, is the root of trust).

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
- `/sys/trust/brokers` (`brokers.v1`) — recognized fallback brokers (optional; only needed to accept emails whose domain runs no provider). The payload is the **object form** `{ "brokers": ["broker.example"] }`, matching `dns-root.v1`, so per-broker fields can be added later; a bare JSON array is not a valid `brokers.v1` payload and parses to no brokers (fail closed).

These are ordinary `sys`-signed objects (authorized by the `sys` key under the root policy), not specially-validated genesis objects. They SHOULD be established at genesis or immediately after, so email-rooted writes can be authorized from the start. In the genesis submission they MUST appear **after** `/sys/policies/root`, because they are validated by ordinary policy evaluation (see [Bootstrap Window](#bootstrap-window)). A repository that uses only key-rooted identities does not require them.

---

## Genesis Validation

### Bootstrap Window

The **bootstrap window** is the span during which no root policy exists, and it is exactly the **mode objects of the genesis submission**. Precisely:

1. The genesis lives in **one DA submission** (one batch, see [Batch Submissions](./SBO%20Wire%20Format%20Specification.md#batch-submissions)) in the **anchor block** `@firstBlock`. Objects spread across submissions or blocks are not a genesis.
2. The **mode objects** come **first** in the submission, in the relative order given for their mode (Mode A: `sys`, `root`; Mode B: `dnssec`, `domain`, `sys`, `root`). They are validated **structurally** by the rules below (schema, signatures, chain of certification, same submission), **not** by policy evaluation, because no policy exists yet. Nothing else is accepted on this basis.
3. `/sys/policies/root` closes the window. **Every message after it** — in the genesis submission and in every later submission — is validated by the ordinary rules (signature, attribution, policy evaluation against the state the preceding messages left; see the [Wire Format](./SBO%20Wire%20Format%20Specification.md#per-message-validation-and-ordering) per-message rules). The root policy therefore governs the rest of the genesis submission: community policies, trust anchors, checkpointer names and so on are ordinary writes that the root policy MUST grant.
4. **Before** the root policy is applied, any message that is not the next expected mode object is **invalid**: a message from a stranger's key, an object at any other path, a mode object out of order, or a second copy of a mode object. There is no lenient period. A repository whose anchor submission does not contain a complete, valid mode-object prefix has **no genesis**, and no message on that `(chain, appId)` at or after the anchor is ever valid.
5. The genesis submission is **not** an atomic exception: per-message semantics apply after the root policy as everywhere else, and a rejected post-root message does not invalidate the genesis. The fail-closed property comes from rules 2–4, not from atomicity.

This is the only place in the protocol where an object is accepted without a policy, and it is bounded to the mode-object prefix of one submission.

### Mode A Validation

```
1. /sys/names/sys and /sys/policies/root are messages 1 and 2 of the genesis submission
2. /sys/names/sys:
   - Valid identity.v1 JWT with iss: "self"
   - Self-signed (JWT signature matches public_key in payload)
   - Public-Key header matches public_key in payload
   - Owner (explicit or implied) is sys itself: this is the one self-certifying name
     (see the Identity Specification; no other write may name a bare key as owner)
3. /sys/policies/root:
   - Valid policy.v2 schema
   - Signed by sys key
4. All signatures must be cryptographically valid
5. Messages 3.. of the submission are validated normally against the state left by 1 and 2
```

### Mode B Validation

```
1. /sys/dnssec/<domain>, /sys/domains/<domain>, /sys/names/sys, and /sys/policies/root
   are messages 1 to 4 of the genesis submission, in that order
2. /sys/dnssec/<domain>:
   - Valid dnssec.v1 evidence for _browserid.<domain>, verified against the pinned
     DNS root KSK, with RRSIG windows that bracket the anchor block's inclusion time
   - Proves the key named in step 3
3. /sys/domains/<domain>:
   - Valid domain.v1 JWT with iss: "self"
   - Self-signed (JWT signature matches public_key in payload)
   - public_key equals the _browserid provider key proven in step 2 (self-certified);
     a mismatch or missing proof is INVALID (REQUIRED, not optional)
4. /sys/names/sys:
   - Valid identity.v1 JWT with iss: "domain:<domain>"
   - Signed by domain key from step 3
   - Public-Key header matches public_key in payload
5. /sys/policies/root:
   - Valid policy.v2 schema
   - Signed by sys key
6. All signatures must be cryptographically valid
7. Messages 5.. of the submission are validated normally against the state left by 1 to 4
```

### Failure

Genesis validation is **halting**, not advisory:

- If the mode-object prefix is absent or invalid, the repository has no genesis; a node MUST NOT apply any message and MUST report the failure.
- If an expected `genesisHash` is known (from a URI, a DNS record, or configuration) and the computed hash differs, the node MUST **halt sync** and report the mismatch. Logging and continuing is not conforming.
- If **more than one** valid genesis submission exists at the anchor block for the same `appId` and no `genesisHash` is known, the anchor is ambiguous and the node MUST **halt** rather than guess (the URI specification's rule). With a known hash, the matching submission is the genesis and the others are ordinary submissions validated under its root policy (where they fail, since their mode objects collide with occupied slots).
- A repository followed without an anchor or hash scans forward from the first block with data for the `appId` and takes the first submission that validates as a genesis; a client doing so SHOULD then record the resulting `(firstBlock, genesisHash)`.

After genesis validation succeeds, all subsequent objects are validated using normal policy rules.

---

## Genesis Detection

Clients identify genesis mode as follows:

```
1. Start at @firstBlock (or, with no anchor, the first block with data for this appId)
2. For each submission in the block, look at its first message:
   - Path /sys/dnssec/ → Mode B candidate (expect dnssec, domain, sys, root)
   - Path /sys/names/ ID sys → Mode A candidate (expect sys, root)
   - anything else → not a genesis submission
3. Validate the candidate according to its mode (structural rules above)
4. If a genesisHash is known, select the candidate whose hash matches; otherwise
   exactly one valid candidate must exist at the anchor
5. If validation fails, or the anchor is ambiguous → halt; the database is invalid
```

**Conflict resolution:**
- With a known `genesisHash`, the matching submission is the genesis; every other submission at the anchor is an ordinary submission validated under that root policy (and its mode objects fail as occupied slots).
- With no known hash, more than one valid genesis submission at the anchor is an error: the node MUST halt, never pick one.
- Genesis objects spread over different submissions or blocks are not a genesis.
- Later attempts to post genesis objects are rejected by normal policy rules (`(path, id)` is globally unique and the slots are occupied).

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

### `genesisHash` bytes

`all_genesis_objects_bytes` is the **genesis submission exactly as included on chain**: the
bytes of the whole DA submission that carries the genesis, every message of it in order
(mode objects and whatever follows the root policy in that submission), concatenated with no
separators, where each message's framing (its `Content-Length`) makes the batch
self-delimiting. `genesisHash = sha256` of those bytes. This is the same hashing rule as
`object_hash` in the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md#object-hash):
hash what was included, never a reconstruction.

Because a message that is not in canonical form is invalid (the [Wire Format](./SBO%20Wire%20Format%20Specification.md)
signing rule: the signer commits to the bytes it sent, and consumers never reserialize), the
bytes as included are, for a valid genesis, **equal to the canonical serialization** the
genesis builder emitted (e.g. the `genesis.wire` batch). A builder therefore computes the
hash over the batch it is about to submit, and a chain reader computes it over the submission
bytes it reads; the two coincide without any reserialization step, and a reader MUST NOT
reserialize to obtain the hash. If the submission is gzip-wrapped on the DA layer, the hash
is over the inflated SBO bytes.

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
   → Validate the genesis submission (mode-object prefix, then normal rules)
   → If genesis hash present, verify it matches, else halt
     (no hash: require exactly one valid genesis at the anchor, else halt)
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
/sys/checkpoints/...        → state checkpoints (see State Commitment spec)

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

`/sys/domains/*` objects are **repository root-of-trust domains** (used to certify repository-internal identities such as `sys`). They are distinct from users' email-provider domains, which are attributed via DNSSEC. A domain's `_browserid` proof MAY be mirrored on chain **once**, as a `dnssec.v1` object under `/sys/dnssec/<domain>`, to **self-certify the repository root-of-trust domain** at genesis (see [Domain Objects](./SBO%20Identity%20Specification.md#domain-objects-domainv1)); per-message user-attribution evidence is otherwise not required to be stored on chain. See the two-senses-of-domain note in the [SBO Identity Specification](./SBO%20Identity%20Specification.md#domain-objects-domainv1).

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

- Genesis validation is a one-time operation at database initialization, and it is halting: a failed or ambiguous genesis stops the node
- After the root policy, standard SBO validation rules apply, including to the rest of the genesis submission
- Existing specs (Wire Format, Policy, State Commitment) apply unchanged; batches are per-message everywhere, genesis included
- URI schemes extend the existing URI specification

---

## References

- [SBO Identity Specification](./SBO%20Identity%20Specification.md)
- [SBO Specification](./SBO%20Specification.md)
- [SBO Policy Specification](./SBO%20Policy%20Specification.md)
