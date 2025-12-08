
# SBO Identity & Name Resolution Spec (v0.1)

## Status
Draft

## Overview

This document defines a naming and identity resolution system for SBO (Simple Blockchain Objects) that allows human-readable names (e.g., `userA`) to be mapped to public keys (or full SBO URIs) via a decentralized, SBO-native registry. It enables users to refer to objects and owners using clean identifiers while preserving cryptographic verifiability and support for cross-chain or cross-app resolution.

---

## Naming Model

- Each SBO database (chain + appId) may contain a `names/` namespace.
- Objects posted under `names/<local_name>` declare a mapping from a human-readable name to:
  - A public key (for signature validation)
  - Optionally, a fully qualified SBO URI pointing to another identity claim
- Each name is scoped to the chain + appId + path (`names/`) in which it is defined.

---

## Object Schema: `identity.claim`

```
SBO-Version: 0.5
Action: post
Path: /names/
ID: userA
Type: object
Content-Type: application/json
Content-Schema: identity.claim
Content-Length: 156
Content-Hash: sha256:a1b2c3d4e5f6...
Signing-Key: secp256k1:02123abc...
Signature: a1b2c3d4e5f6...

{
  "public_key": "secp256k1:02123abc...",
  "display_name": "User A",
  "description": "Main handle for User A",
  "binding": "sbo://Avail:18/names/actualUserA"
}
```

### Fields

| Field         | Type     | Description |
|---------------|----------|-------------|
| `public_key`  | string   | Public key with algorithm prefix (e.g., `secp256k1:02abc...` or `ed25519:abc...`) |
| `display_name`| string   | Optional human-friendly label |
| `description` | string   | Optional text description |
| `binding`     | string   | Optional SBO URI to a canonical identity object on another chain/app |

Either `public_key` or `binding` must be present, but not both.

---

## Resolution Semantics

### Direct resolution:
To resolve `userA` in the context of `sbo://Avail:17`:
1. Load the object at `sbo://Avail:17/names/userA`
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
- Bindings are optional, and must point to objects of schema `identity.claim`

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
sbo://Avail:17/userA/nft-123
```

If its envelope contains:

```
Creator: userA
```

The `Creator` header is resolved via the `names/` namespace in the current SBO database (e.g., `sbo://Avail:17/names/userA`). This object contains a public key (or a binding) that is used to verify that the `userA/nft-123` object was signed by the specified key.

Another example: referencing an identity as a profile link:

```
Related: [{"rel":"profile","ref":"sbo://Avail:17/names/userA"}]
```

This reference provides an identity as a "profile" for the object (an application-specific usage of the identity with no prescribed meaning or usage in this spec).

---
