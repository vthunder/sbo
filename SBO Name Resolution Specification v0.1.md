
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

```yaml
schema: SBO-v0.3
id: names/userA
action: post
content_schema: identity.claim
content_type: application/json
content_hash: 0x...
signing_key: 0x123abc...
signature: 0xsigneddata
---
{
  "public_key": "0x123abc...",
  "display_name": "User A",
  "description": "Main handle for User A",
  "binding": "sbo://Avail:18/names/actualUserA"
}
```

### Fields

| Field         | Type     | Description |
|---------------|----------|-------------|
| `public_key`  | string   | Optional public key for this name |
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
- SDKs should warn or error if bindings are dereferenced without any snapshot metadata

## Example: Using Names in URIs

Given this object:
```
sbo://Avail:17/userA/nft-123
```

If it contains in its envelope:

```yaml
creator: "userA"
```

The creator field is resolved via the names/ namespace in the current SBO database (e.g., sbo://Avail:17/names/userA). This object might contain a public key (or a binding) that could be used to verify that the userA/nft-123 object was signed by the specified key.

Another example: referencing an identity as a profile link:

```yaml
related:
  - relation: "profile"
    target: "sbo://Avail:17/names/userA"
```

This reference would provide an identity as a "profile" for the object (an application-specific usage of the identity with no prescribed meaning or usage in this spec)

---
