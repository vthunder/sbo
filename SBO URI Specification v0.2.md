
# SBO URI Format (v0.2)

## Overview

SBO URIs provide a uniform way to reference objects across and within chains, applications, and ownership scopes. In conjunction with the SBO envelope format, they support versioning, provenance tracking, and cross-chain references — allowing systems to deterministically resolve and verify object state, even in complex or historical contexts.

---

## URI Syntax

```
sbo://[chain][:appId][@block]/[path/][creator:][id][?query]
```

### Components

| Part | Description |
|------|-------------|
| `chain` | Optional chain name (e.g. `Avail`). |
| `appId` | Optional application ID or namespace within the chain (e.g. Avail's App ID, or a contract address). |
| `block` | Optional block number. Specifies historical resolution point. |
| `path` | Reserved for future use. |
| `creator` | Optional. The original creator of the object. |
| `id` | Optional when referencing a collection. Required for single-object URIs. The object's logical identifier (e.g. `nft-123`). |
| `query` | Optional disambiguation or versioning info (e.g. content hash). |

---

## Query Parameters

| Parameter        | Description |
|------------------|-------------|
| `content_hash`   | Specifies the exact content version being referenced. |
| `content_type`   | MIME type of the object payload. (e.g. `application/json`). |
| `content_schema` | Optional schema filter (e.g. `nft.v1`). |
| `encoding`       | Transport encoding (e.g. `utf-8`, `gzip`). |
| `size`           | Payload size in bytes, optionally prefixed with a comparison operator (e.g. `>1024`). |
---

## Resolution Semantics

- If `block` is present → resolve the object’s state as of that block (if resolvable).
  - `@block` anchors the intended resolution point, but clients must be aware that historical blocks may not be available in pruned DA layers. If the block is unavailable, clients may fall back to content-based or historical resolution strategies.
- If `content_hash` is present → the payload must match the specified hash.
  - When a URI contains ?content_hash=..., clients must attempt to resolve the object by walking its update history (in reverse block order) until a matching content hash is found. This ensures durable and deterministic references to historical object versions, even if they are no longer the latest.
- Unless a specific block height is specified, the URI resolves to the latest version by LWW policy.
- If `creator` is present, the object must have been originally minted by that creator
- If `creator` is not present, the object must have been created by the current owner path segment
- If `id` is omitted, the URI references the collection at the specified path
- Collection URIs may by filtered by owner, creator, and query arguments if specified.

---

## Examples

| Use Case | URI |
|----------|-----|
| Current object on Avail app 13 | `sbo://Avail:13/user1/nft-123` |
| Historical snapshot at block 12345 on the current chain and app | `sbo://@12345/user1/nft-123` |
| Cross-chain reference | `sbo://Ethereum:0x123...@5555/user2/certificate-xyz` |
| Versioned object | `sbo://Avail:13/user2/foo?content_hash=0xabc` |
| Transfer-aware reference | `sbo://Avail:13/user2/larvalabs:punk-001` |
| Full disambiguation | `sbo://Avail:42@8765/userB/userA:art-7?content_hash=0xdeadbeef` |
| All JSON-encoded objects larger than 1024 bytes | `sbo://Avail:13/user1/?content_type=application/json&size=>1024` |
| All NFTs belonging to user1 | `sbo://Avail:13/user1/?content_schema=nft.v1` |
| All NFTs belonging to user1 and created by larvalabs | `sbo://Avail:13/user1/larvalabs:?content_schema=nft.v1` |
---

## Usage in Envelopes

```yaml
related:
  - relation: "collection"
    target: "sbo://Avail:13/creator123/punks-v1"
  - relation: "policy"
    target: "sbo://Avail:13@12345/legaldao/policy-xyz?content_hash=0xabc"
```

```yaml
depends_on:
  - target: "sbo://Avail:13/oracleA/market-state?content_hash=0xfeedface"
```

---

## Notes

- This format is forward-compatible with future proof systems (e.g., `zk_proof`, `witness` query arguments, etc).
- URI parsing and resolution are generally handled by off-chain SDK or application logic, but to the extent that URIs are embedded in objects, they must be resolvable on-chain.
- Future extensions may include wildcards (e.g., `*` for any owner, `**` for any path).
- This spec assumes an identity layer that allows resolution of public keys to owner shorthands. As a fallback in its absence, the full public key may be used.

---
