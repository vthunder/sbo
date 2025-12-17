
# SBO URI Format (v0.3)

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
sbo://[domain]/[path/][creator:][id][?query]
```

### Components

| Part | Description |
|------|-------------|
| `domain` | DNS domain name (e.g., `myapp.com`) |
| `path` | Path within the SBO database |
| `creator` | Optional. Original creator of the object |
| `id` | Object identifier |
| `query` | Optional filters and disambiguation |

### Resolution

1. DNS TXT lookup for `_sbo.{domain}`
2. Parse record for chain, appId, genesis hash, checkpoint URL
3. Resolve path within the identified database

### DNS TXT Record Format

```
_sbo.myapp.com TXT "sbo=v1 chain=avail:mainnet appId=13 genesis=sha256:abc123... firstBlock=1000 checkpoint=https://myapp.com/sbo/checkpoint.json node=https://sbo.myapp.com"
```

| Field | Required | Description |
|-------|----------|-------------|
| `sbo` | Yes | Version identifier (v1) |
| `chain` | Yes | CAIP-2 chain identifier |
| `appId` | Yes | Application ID on the chain |
| `genesis` | No | Genesis hash for database identity |
| `firstBlock` | No | Block number containing genesis (for sync-from-start) |
| `checkpoint` | No | URL for bootstrap checkpoint (preferred for mature databases) |
| `node` | No | URL of full node for data fetching |

### Examples

| Use Case | URI |
|----------|-----|
| Object on myapp.com | `sbo://myapp.com/alice/nft-123` |
| System identity | `sbo://myapp.com/sys/names/alice` |
| With content hash | `sbo://myapp.com/alice/foo?content_hash=sha256:abc123` |

---

## Direct Chain URIs (`sbo+raw://`)

```
sbo+raw://[chain]:[appId][@block]/[path/][creator:][id][?query]
```

### Components

| Part | Description |
|------|-------------|
| `chain` | CAIP-2 chain identifier (e.g., `avail:mainnet`) |
| `appId` | Application ID on the chain |
| `block` | Optional block number for historical resolution |
| `path` | Path within the SBO database |
| `creator` | Optional. Original creator of the object |
| `id` | Object identifier |
| `query` | Optional filters and disambiguation |

### Query Parameters

| Parameter | Description |
|-----------|-------------|
| `genesis` | Genesis hash for database identity (e.g., `sha256:abc123...`) |
| `content_hash` | Exact content version (e.g., `sha256:a1b2c3...`) |
| `content_type` | MIME type filter (e.g., `application/json`) |
| `content_schema` | Schema filter (e.g., `nft.v1`) |
| `encoding` | Transport encoding (e.g., `utf-8`, `gzip`) |
| `size` | Payload size filter (e.g., `>1024`) |

### Examples

| Use Case | URI |
|----------|-----|
| Object on Avail mainnet | `sbo+raw://avail:mainnet:13/alice/nft-123` |
| With genesis hash | `sbo+raw://avail:mainnet:13/alice/nft-123?genesis=sha256:abc123` |
| Historical snapshot | `sbo+raw://avail:mainnet:13@12345/alice/nft-123` |
| Cross-chain reference | `sbo+raw://celestia:mainnet:42/bob/certificate-xyz` |
| Versioned object | `sbo+raw://avail:mainnet:13/alice/foo?content_hash=sha256:def456` |
| Full disambiguation | `sbo+raw://avail:mainnet:13@8765/bob/alice:art-7?genesis=sha256:abc123` |

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

The canonical identity of an SBO database is:

```
{chain}:{appId}:{genesis_hash}
```

**Example:**
```
avail:mainnet:13:sha256:abc123def456...
```

Both URI schemes resolve to this canonical identity. The genesis hash ensures databases with the same chain:appId but different genesis content are distinguishable.

---

## Resolution Semantics

- If `block` is present → resolve object state as of that block
- If `content_hash` is present → payload must match specified hash
- If `genesis` is present → database must have matching genesis hash
- Without block specifier, resolves to latest version (LWW)
- If `creator` is present, object must have been minted by that creator
- If `id` is omitted, URI references the collection at that path

---

## Usage in Envelopes

URIs can be used in the `Related` header:

```
Related: [{"rel":"collection","ref":"sbo://myapp.com/creator123/punks-v1"},{"rel":"policy","ref":"sbo+raw://avail:mainnet:13@12345/sys/policies/nft-rules?content_hash=sha256:abc123"}]
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

## Migration from v0.2

The v0.2 `sbo://chain:appId/...` format is deprecated. Migrate as follows:

| v0.2 | v0.3 |
|------|------|
| `sbo://Avail:13/alice/foo` | `sbo+raw://avail:mainnet:13/alice/foo` |
| `sbo://Ethereum:0x123/bob/bar` | `sbo+raw://eip155:1:0x123/bob/bar` |

Note: Chain names are now lowercase CAIP-2 identifiers.

---
