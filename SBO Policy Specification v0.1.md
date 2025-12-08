
# SBO Policy Specification (v0.1)

## Status
Draft

## Overview

This document defines the specification for SBO policy objects (`policy.v1`), which govern permissions and behavior for posting, renaming, and deleting SBO objects and path metadata.

Policies are executable, sandboxed programs written in JavaScript. Each function evaluates a single authorization decision (e.g., can this user post to this path?) based on the object, user identity, and context.

---

## Policy Object Format

### Envelope

```
SBO-Version: 0.5
Action: post
Path: /policies/
ID: default
Type: object
Content-Type: application/json
Content-Schema: policy.v1
Content-Length: 245
Content-Hash: sha256:a1b2c3...
Signing-Key: secp256k1:02abc...
Signature: 1a2b3c...
```

### Payload

```json
{
  "canPost": "function(path, user, object, context) { return true; }",
  "canCreate": "function(path, user, context) { return true; }",
  "canRename": "function(path, user, from, to, context) { return true; }",
  "canTransfer": "function(path, user, to_user, context) { return false; }"
}
```

---

## Evaluation Model

Each policy function receives:
- `path`: the path of the object or collection being acted on relative to the collection with the policy reference (e.g. `users/alice`)
- `user`: a structured identity object resolved from `names/` namespace
- `object`: the SBO object being posted (if applicable)
- `context`: current environment metadata (e.g., block, chain, parent path info)
- `from`: the original owner of the object (for rename)
- `to`: the new owner of the object (for rename)
- `to_user`: the identity object of the new owner (for transfer)

Return value must be a boolean (`true` = allow, `false` = deny). Any exceptions or non-boolean values are treated as denial.

---

## Function Signatures

### `canCreate(path, user, context)`
Determines whether the user may create a new path or object at the given path.

### `canPost(path, user, object, context)`
Determines whether the user may post or update the given object at the path.

### `canRename(path, user, from, to, context)`
Determines whether the user may rename a path or object.

### `canTransfer(path, user, context)`
Determines whether the user may transfer ownership of a path or object.

---

## Security and Execution

- Policy functions must be executed in a deterministic, sandboxed JavaScript VM (e.g., using `vm2`, SES, or equivalent)
- Functions may not perform I/O, network access, or introduce nondeterminism
- Maximum execution time and depth must be bounded by the SDK

---

## Context Object

SDKs must provide the following fields in the `context` object:

```json
{
  "chain": "Avail",
  "appId": 13,
  "block": 123456,
  "timestamp": 1700000000,
  "parentPolicy": { ... }, // if inherited
  "resolvedBindings": { ... }, // for identities
  "pathPolicyRef": "sbo://.../policies/default"
}
```

---

## Example Policy

Allow only the identity `names/userA` to post to paths under `/userA`:

```json
{
  "canCreate": "function(path, user, context) {
    return path.startsWith('/' + user.name);
  }",
  "canPost": "function(path, user, object, context) {
    return path.startsWith('/' + user.name);
  }"
}
```

---

## Validation and Fallback

- If no applicable policy can be resolved for a path, the SDK must reject the post as invalid.
- If the policy exists but a required function is missing, the SDK must deny the action by default.

---

## Future Extensions

- Support for linking to external code objects (`code_ref`)
- WASM-based policies
- Signed policy attestations or audit hashes
- Declarative policies as an alternative to JavaScript policies

---
