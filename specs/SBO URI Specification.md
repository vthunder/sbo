---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO URI Specification

**Part of SBO Protocol v0.5**

## Overview

SBO URIs provide a uniform way to reference objects across chains, applications, and ownership scopes. This version introduces two URI schemes for different resolution methods and adopts CAIP-2 for chain identifiers.

---

## URI Schemes

SBO supports two URI schemes:

| Scheme | Resolution | Use Case |
|--------|------------|----------|
| `sbo://` | DNS lookup | Human-friendly, discoverable |
| `sbo+raw://` | Direct chain reference | Self-contained, no external lookup |

---

## DNS-Resolved URIs (`sbo://`)

```
sbo://[domain]/[path/][id][?query]
```

Because `(path, id)` is globally unique, an object reference needs only its path and id; `creator` is an object **attribute**, not an addressing element. Verifying authorship is done by resolving the object and comparing its `creator` attribute to expectation — not through the URI grammar.

### Components

| Part | Description |
|------|-------------|
| `domain` | DNS domain name (e.g., `myapp.com`) |
| `path` | Path within the SBO database |
| `id` | Object identifier |
| `query` | Optional filters and disambiguation |

### Resolution

1. DNS TXT lookup for `_sbo.{domain}`
2. Parse the record's `repo=` URI (chain, appId, and the genesis anchor `@firstBlock`) plus the optional `genesis=` hash
3. Compose the requested path onto the `repo=` URI and resolve within the identified database

The `_sbo` record is **purely a data-discovery record**: it locates the database and how to reach it. It carries **no identity or trust root** — identity is on-chain (the genesis-pinned browserid broker and `/sys/names/...`; see the [Identity Specification](./SBO%20Identity%20Specification.md)), and `node`/`checkpoint` are conveniences whose outputs are always verified against on-chain truth (see [Resolution Semantics](#resolution-semantics)).

### DNS TXT Record Format

```
_sbo.myapp.com TXT "v=sbo1 repo=sbo+raw://avail:mainnet:13@1000/ genesis=sha256:abc123... node=https://sbo.myapp.com checkpoint=https://myapp.com/sbo/checkpoint.json"
```

Fields are space-separated `key=value` pairs. Unknown keys are ignored (forward-compat).

| Field | Required | Description |
|-------|----------|-------------|
| `v` | Yes | Record version (`sbo1`) |
| `repo` | Yes | The canonical `sbo+raw://` database address, including the `@firstBlock` genesis anchor. MUST be a **bare repository URI** — see [Bare `repo=` rule](#bare-repo-rule). |
| `genesis` | No | Genesis **hash** for database identity/verification (`sha256:...`). The block lives in `repo`'s `@firstBlock`; this field is hash-only. |
| `node` | No | URL of a full node serving the `/v1/*` data API (read without running a local sync daemon). |
| `checkpoint` | No | URL for a bootstrap checkpoint (preferred for mature databases; verified, never trusted blindly). |

> <a id="bare-repo-rule"></a>**Bare `repo=` rule.** The `repo=` value MUST be a bare repository address — `sbo+raw://chain:appId[@firstBlock]/`. A `path`, `creator`, `id`, or query (`?genesis`, `?as_of`, `?content_hash`, …) in `repo=` is **ignored**; resolvers SHOULD treat a non-bare `repo=` as malformed. Per-object selectors are supplied by the caller's path/query at resolution time, **not** baked into the discovery record. (Database-level facts — the anchor and identity — are carried by `@firstBlock` and `genesis=` precisely so they apply to the whole database without being inherited as per-read selectors.)
>
> **Identity is not a DNS field.** There is no `h=`/auth-host field and no `_sbo-id` record. Resolving a person → identity is on-chain (browserid broker pinned in genesis + `/sys/names/...`).

### Examples

| Use Case | URI |
|----------|-----|
| Object on myapp.com | `sbo://myapp.com/alice/nft-123` |
| System identity | `sbo://myapp.com/sys/names/alice` |
| With content hash | `sbo://myapp.com/alice/foo?content_hash=sha256:abc123` |

---

## Direct Chain URIs (`sbo+raw://`)

```
sbo+raw://[chain]:[appId][@firstBlock]/[path/][id][?query]
```

### Components

| Part | Description |
|------|-------------|
| `chain` | CAIP-2 chain identifier (e.g., `avail:mainnet`). Exactly `namespace:reference`. |
| `appId` | Application ID on the chain. The authority is exactly `chain:appId` (CAIP-2 + appId); it never grows further, so an opaque/non-numeric `appId` stays unambiguous. |
| `@firstBlock` | Optional **genesis anchor** — the block where this database's genesis lives. A **database-level** locator: it identifies *which* database (and where to begin sync), and applies uniformly to every path composed under the authority. It is **not** a snapshot selector (for that, see `as_of`). |
| `path` | Path within the SBO database |
| `id` | Object identifier |
| `query` | Optional selectors and disambiguation (see below) |

The `@firstBlock` anchor is **inherited by composition**: appending a path to an anchored authority (`sbo+raw://avail:mainnet:13@1000/` + `/alice/nft` → `sbo+raw://avail:mainnet:13@1000/alice/nft`) keeps the same database anchor for every object — which is the intended behavior, because the anchor is a property of the database, not of any one read.

### Query Parameters

| Parameter | Description |
|-----------|-------------|
| `genesis` | Genesis **hash** for database identity/verification (e.g., `sha256:abc123...`). Disambiguates/verifies *which* database when the anchor alone is insufficient. |
| `as_of` | **Historical snapshot** — resolve object state *as of* the given block. A per-read selector (distinct from the `@firstBlock` anchor). |
| `content_hash` | Exact content version (e.g., `sha256:a1b2c3...`) |
| `content_type` | MIME type filter (e.g., `application/json`) |
| `content_schema` | Schema filter (e.g., `nft.v1`) |
| `encoding` | Transport encoding (e.g., `utf-8`, `gzip`) |
| `size` | Payload size filter (e.g., `>1024`) |

### Examples

| Use Case | URI |
|----------|-----|
| Object on Avail mainnet | `sbo+raw://avail:mainnet:13@1000/alice/nft-123` |
| Anchor only (single genesis at height) | `sbo+raw://avail:mainnet:13@1000/alice/nft-123` |
| Anchor + hash (disambiguate/verify) | `sbo+raw://avail:mainnet:13@1000/alice/nft-123?genesis=sha256:abc123` |
| Hash only (locate by scan/checkpoint) | `sbo+raw://avail:mainnet:13/alice/nft-123?genesis=sha256:abc123` |
| Historical snapshot | `sbo+raw://avail:mainnet:13@1000/alice/nft-123?as_of=12345` |
| Cross-chain reference | `sbo+raw://celestia:mainnet:42@500/bob/certificate-xyz` |
| Versioned object | `sbo+raw://avail:mainnet:13@1000/alice/foo?content_hash=sha256:def456` |
| Full disambiguation | `sbo+raw://avail:mainnet:13@1000/bob/alice:art-7?genesis=sha256:abc123&as_of=8765` |

---

## Chain Identifiers (CAIP-2)

Chain names use CAIP-2 format (Chain Agnostic Improvement Proposals):

```
namespace:reference
```

| Chain | CAIP-2 Identifier |
|-------|-------------------|
| Avail mainnet | `avail:mainnet` |
| Avail testnet | `avail:testnet` |
| Celestia mainnet | `celestia:mainnet` |
| Ethereum mainnet | `eip155:1` |
| Polygon mainnet | `eip155:137` |

New chains should be registered in the CAIP-2 namespace. See [CAIP-2 specification](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md).

---

## Database Identity

The canonical identity of an SBO database is the 4-tuple:

```
{chain}:{appId}:{firstBlock}:{genesisHash}
```

**Example:**
```
avail:mainnet:13:1000:sha256:abc123def456...
```

Where:
- `genesisHash` = `sha256(all_genesis_objects_bytes)` — the content-derived, **verifying** identity (reproducible offline by rebuilding the genesis batch).
- `firstBlock` = the block the genesis lives at — the **locator** that makes the database practically scannable, and that disambiguates the same genesis batch replayed at two different heights on one `appId`.

### Reference vs. identity

A **reference** is how a URI/record *points at* a database; the **identity** is its canonical 4-tuple. A reference need not be complete:

| Reference carries | Meaning | Resolves? |
|-------------------|---------|-----------|
| `@firstBlock` only | locator; identity = whatever genesis is at that height | ✅ — but **MUST error if >1 genesis exists at `(chain, appId, firstBlock)`** (ambiguous), never guess |
| `?genesis=hash` only | identity known; locate by scanning / a checkpoint | ✅ |
| both | locator + verify | ✅ |
| neither | bare repo; locator supplied by `_sbo` record / context | ✅ |

Reading the real DA layer at `@firstBlock` is authoritative (the block content is what it is); the hash only adds verification and resolves the multi-genesis-per-block ambiguity. After resolving *any* reference, a client computes/confirms the `genesisHash` to obtain the canonical identity.

---

## Resolution Semantics

- `@firstBlock` selects the **database** (where its genesis lives); it is inherited by all paths and does **not** snapshot reads. With no `genesis` hash, resolution MUST error if the anchor is ambiguous (>1 genesis at that height).
- If `genesis` is present → the resolved database's genesis hash MUST match (verify; disambiguate).
- If `as_of` is present → resolve object state **as of** that block (historical snapshot).
- If `content_hash` is present → payload must match specified hash.
- Without `as_of`, resolves to the latest version (LWW).
- If `id` is omitted, URI references the collection at that path.

Authorship is **not** an addressing element: `(path, id)` is globally unique, so a reference never carries a `creator`. To verify authorship, resolve the object and compare its immutable `creator` attribute to expectation.
- `node`/`checkpoint` (from the `_sbo` record) MAY be used for performance, but their outputs are always verified against on-chain truth — they are never trust roots.

---

## Usage in Envelopes

URIs can be used in the `Related` header:

```
Related: [{"rel":"collection","ref":"sbo://myapp.com/creator123/punks-v1"},{"rel":"policy","ref":"sbo+raw://avail:mainnet:13@1000/sys/policies/nft-rules?content_hash=sha256:abc123"}]
```

Or in the `Policy-Ref` header:

```
Policy-Ref: sbo+raw://avail:mainnet:13/sys/policies/default
```

---

## Compatibility

- `sbo://` URIs require DNS resolution and are suitable for user-facing applications
- `sbo+raw://` URIs are self-contained and suitable for on-chain references
- Both schemes can reference the same underlying objects
- Implementations should support both schemes

---
