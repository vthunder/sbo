
# SBO Identity & Name Resolution Spec (v0.1)

## Status
Draft

## Overview

This document defines a naming and identity resolution system for SBO (Simple Blockchain Objects) that allows human-readable names (e.g., `userA`) to be mapped to public keys (or full SBO URIs) via a decentralized, SBO-native registry. It enables users to refer to objects and owners using clean identifiers while preserving cryptographic verifiability and support for cross-chain or cross-app resolution.

---

## Naming Model

- Each SBO database (chain + appId) contains a `/sys/names/` namespace.
- Objects posted under `/sys/names/<local_name>` declare a mapping from a human-readable name to:
  - A public key (for signature validation)
  - Optionally, a fully qualified SBO URI pointing to another identity claim
- Each name is scoped to the chain + appId in which it is defined.
- The `/sys/names/` path is controlled by the `sys` identity established at genesis (see [Genesis Specification](./SBO%20Genesis%20Specification%20v0.1.md)).

---

## Object Schema: `identity.v1`

Identity objects use the `identity.v1` schema. See the [SBO Identity Specification](./SBO%20Identity%20Specification%20v0.1.md) for the complete schema definition.

```
SBO-Version: 1
Action: Create
Path: /sys/names/
Id: userA
Content-Type: application/json
Content-Schema: identity.v1
Public-Key: ed25519:abc123...
Signature: <signature>

{
  "public_key": "ed25519:abc123...",
  "display_name": "User A",
  "description": "Main handle for User A",
  "binding": "sbo+raw://avail:mainnet:18/sys/names/actualUserA"
}
```

### Fields

| Field         | Type     | Description |
|---------------|----------|-------------|
| `public_key`  | string   | Public key with algorithm prefix (e.g., `ed25519:abc...`) |
| `display_name`| string   | Optional human-friendly label |
| `description` | string   | Optional text description |
| `avatar`      | string   | Optional SBO path or URL to avatar image |
| `links`       | object   | Optional key-value pairs of named links |
| `binding`     | string   | Optional SBO URI to a canonical identity object on another chain/app |

Either `public_key` or `binding` must be present, but not both.

---

## Resolution Semantics

### Direct resolution:
To resolve `userA` in the context of `sbo://myapp.com` (which resolves to `avail:mainnet:17`):
1. Load the object at `/sys/names/userA`
2. Verify the signature on the object matches the declared `public_key`
3. Use `public_key` as the identity of `userA` for validation

### Cross-chain resolution (via binding):
1. Resolve `names/userA` as above
2. If the object contains a `binding` field:
   - Resolve the target URI
   - Use the identity found at the target as authoritative
3. This allows mapping local handles to canonical cross-chain or cross-app identities

---

## Rules

- Only one valid name claim is active per `id` at a time (Last-Write-Wins)
- Name claims must be signed by the `public_key` they declare
- Name claims can be updated, renamed, or deleted like any other SBO object
- Bindings are optional, and must point to objects of schema `identity.v1`

---

## Best Practices for Identity Bindings

- When binding to an identity on another chain or app, always include a snapshot in the URI:
  - Use `@block` to lock in the timing of the identity state
  - Use `?content_hash=` to lock in the exact version
- Do not rely on the “latest” version of a remote identity unless you’re okay with non-deterministic resolution
- SDKs should warn or error if bindings without `@block` or `?content_hash` are encountered

## Example: Using Names in URIs

Given this object:
```
sbo://myapp.com/userA/nft-123
```

If its envelope contains:

```
Creator: userA
```

The `Creator` header is resolved via the `/sys/names/` namespace in the current SBO database (e.g., `/sys/names/userA`). This object contains a public key (or a binding) that is used to verify that the `userA/nft-123` object was signed by the specified key.

Another example: referencing an identity as a profile link:

```
Related: [{"rel":"profile","ref":"sbo://myapp.com/sys/names/userA"}]
```

This reference provides an identity as a "profile" for the object (an application-specific usage of the identity with no prescribed meaning or usage in this spec).

---
