---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Policy Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Overview

This document defines the specification for SBO policy objects (`policy.v2`), which govern permissions for creating, posting, deleting, and transferring SBO objects.

Policies are declarative JSON documents that specify grants (who can do what, where) and restrictions (conditions on allowed actions). This design ensures deterministic evaluation across all implementations without requiring embedded scripting engines.

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
Content-Schema: policy.v2
Content-Length: 412
Content-Hash: sha256:a1b2c3...
Public-Key: secp256k1:02abc...
Signature: 1a2b3c...
```

### Payload Structure

```json
{
  "roles": { ... },
  "deny": [ ... ],
  "grants": [ ... ],
  "restrictions": [ ... ]
}
```

All sections are optional. Missing sections are treated as empty.

---

## Evaluation Order

1. **Deny check** — if path matches any deny pattern, action is denied
2. **Grant check** — if user matches a grant for this action and path, proceed
3. **Restriction check** — if restrictions exist for this path, verify conditions
4. **Default** — if no matching grant, deny

---

## Sections

### `deny`

An array of path patterns where all actions are blocked. No grants can override a deny.

```json
{
  "deny": [
    "/bridge/**",
    "/system/**"
  ]
}
```

Use cases:
- Lock bridged objects (no modifications while bridged)
- Reserve system paths
- Prevent overwrites of critical objects

### `grants`

An array of grant objects specifying who can perform which actions on which paths.

```json
{
  "grants": [
    {"to": "owner", "can": ["post", "transfer"], "on": "/$owner/**"},
    {"to": {"role": "admin"}, "can": ["post", "delete"], "on": "/**"},
    {"to": "*", "can": ["post"], "on": "/public/**"}
  ]
}
```

#### Grant fields

| Field | Type | Description |
|-------|------|-------------|
| `to` | identity | Who this grant applies to |
| `can` | array | Actions permitted |
| `on` | string | Path pattern where grant applies |

### `restrictions`

An array of conditions that apply to granted actions. Even if a grant allows an action, restrictions can block it.

```json
{
  "restrictions": [
    {"on": "/**", "require": {"max_size": 1048576}},
    {"on": "/nfts/**", "require": {"schema": "nft.v1"}}
  ]
}
```

#### Restriction fields

| Field | Type | Description |
|-------|------|-------------|
| `on` | string | Path pattern where restriction applies |
| `require` | object | Conditions that must be met |

### `roles`

A map of role names to arrays of members. Roles group identities for reuse in grants.

```json
{
  "roles": {
    "admin": ["alice", "bob"],
    "moderator": ["charlie", {"role": "admin"}]
  }
}
```

### Attestation-Defined Roles

A role member may be an **attestation source** instead of a literal identity. This binds the role to on-chain attestations (see the [Attestation Specification](./SBO%20Attestation%20Specification.md)) rather than a static list, so role membership changes by *issuing* or *expiring* an attestation — no policy edit required. This is the mechanism by which a community grants roles (e.g. an admin appoints a moderator) without amending its root policy.

```json
{
  "roles": {
    "moderator": [{"attested": {"type": "role:moderator", "by": "cooks@example.org"}}],
    "member": [{"attested": {"type": "membership"}}]
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Attestation `type` to match |
| `by` | No | Issuer identity (the attestation's `Owner`) whose attestations count. Omit to accept **any** issuer, including the subject's own self-attestation. |

A requester matches an `attested` source when an `attestation.v1` exists whose `type` equals `type`, whose issuer matches `by` (when given), whose `subject` resolves to the **same controller** as the requester, and which is **in force** at the message's inclusion time (`issued_at` ≤ inclusion time, and `expires` absent or > inclusion time). Expiry of the attestation removes the role automatically. An `attested` source references data objects, not roles, so it cannot participate in a role cycle.

---

## Identity Syntax

The `to` field in grants accepts these forms:

| Value | Meaning |
|-------|---------|
| `"owner"` | Owner of the path (from path segment) |
| `"*"` | Anyone (public access) |
| `"alice@example.com"` | A specific email-rooted identity |
| `"alice"` | A specific name (from the `/sys/names/` namespace) |
| `{"key": "secp256k1:02..."}` | A specific public key (key-rooted identity) |
| `{"role": "admin"}` | Anyone with this role |
| `{"any": ["alice@example.com", "bob"]}` | Any of these identities |

A requesting message matches an identity reference when its signer **resolves** to that identity (see [Authorization](./SBO%20Identity%20Specification.md#authorization)): an email or name reference matches when the signer is attributed to that email-rooted controller; a `{"key": ...}` reference matches a direct signature by that key. Because a name and the email that controls it resolve to the same controller, both forms identify the same party — a policy MAY grant to either.

---

## Action Types

| Action | Meaning |
|--------|---------|
| `"create"` | Post to a path that doesn't exist (new object) |
| `"update"` | Modify an existing object |
| `"post"` | Shorthand for create + update |
| `"delete"` | Delete an object |
| `"transfer"` | Move, rename, and/or change ownership |
| `"import"` | Create object from cross-chain import |
| `"*"` | All actions |

**Note:** The distinction between `create` and `update` allows policies to grant first-come-first-served creation (e.g., identity claims) without granting update rights. Use `post` when both should be allowed.

---

## Path Patterns

| Pattern | Matches |
|---------|---------|
| `"/users/alice"` | Exact path only |
| `"/users/*"` | Any single segment under `/users/` |
| `"/users/**"` | Any depth under `/users/` |
| `"/$owner/**"` | Dynamic: the object owner's namespace |
| `"/$user/**"` | Dynamic: the acting signer's namespace |
| `"/u/$email/**"` | Dynamic: restricted to email-rooted signers |
| `"/u/$name/**"` | Dynamic: restricted to locally-named signers |

### Policy variables

Patterns may interpolate **literal identity references** — the strings as written
in headers / claimed by the signer, *not* resolved controllers. (Authorization —
whether the signer actually controls a reference — is a separate step; see the
[Authorization Specification](./SBO%20Authorization%20Specification.md).)

| Variable | Value |
|----------|-------|
| `$owner` | The object's owner reference: the declared `Owner` header on create, the stored owner reference on update. **Not** derived from the path. |
| `$user` | The acting signer's canonical identity. |
| `$email` | The signer's email form, if any. |
| `$name` | The signer's local name form, if any. |

**Fail-closed:** if a variable is undefined for a message (e.g. `$email` for a
key-only signer), any pattern referencing it matches nothing — the pattern is
left with the literal `$var` token, which equals no real path segment. So
`$owner`/`$user` are identity-agnostic (use them by default; they work for key-
and email-rooted signers alike), while `$email`/`$name` deliberately *restrict* a
namespace to one credential form.

Because `$owner` is the declared owner (not the path's first segment), a
container layout like `/u/$owner/**` works: a write to `/u/alice@example.com/…`
declaring `Owner: alice@example.com` matches, and a forged `Owner` is still
caught by the independent `to: owner` control check.

---

## Requirement Conditions

Used in the `require` field of restrictions:

| Condition | Description |
|-----------|-------------|
| `{"max_size": 1048576}` | Object payload must be ≤ specified bytes |
| `{"schema": "nft.v1"}` | Object must use specified content schema |
| `{"schema": {"any": ["a.v1", "b.v1"]}}` | Object must use one of specified schemas |
| `{"content_type": "application/json"}` | Object must have specified content type |
| `{"attested": {"type": "membership", "by": "cooks@example.org"}}` | The acting user (`$user`) must be the **in-force subject** of such an attestation |
| `{"not_attested": {"type": "ban", "by": "cooks@example.org"}}` | The acting user must **not** be the in-force subject of such an attestation |

`attested` / `not_attested` use the same matching rules as an [attestation-defined role](#attestation-defined-roles) (`type`, optional `by`, subject resolves to the acting user's controller, in force at inclusion time). They let a policy gate actions on a positive claim (membership, a credential) or a negative one (a ban) without listing identities.

---

## Role Resolution

- Role members can be identity names, public keys, or other roles
- Role membership is resolved at evaluation time
- Circular role references are invalid (policy must be rejected)
- Unknown identity names result in no match (not an error)

Example with inheritance:
```json
{
  "roles": {
    "admin": ["alice"],
    "moderator": ["charlie", {"role": "admin"}]
  }
}
```

Here, `alice` is both an admin and a moderator (admins are members of the moderator role).

---

## Complete Example

A namespace policy with NFT collection:

```json
{
  "roles": {
    "admin": ["alice"],
    "delegate": ["bob"]
  },
  "deny": [
    "/bridge/**"
  ],
  "grants": [
    {"to": "owner", "can": ["*"], "on": "/$owner/**"},
    {"to": {"role": "admin"}, "can": ["post", "delete"], "on": "/**"},
    {"to": {"role": "delegate"}, "can": ["post"], "on": "/$owner/nfts/**"},
    {"to": "*", "can": ["post"], "on": "/public/**"}
  ],
  "restrictions": [
    {"on": "/**/nfts/**", "require": {"schema": "nft.v1"}},
    {"on": "/**", "require": {"max_size": 1048576}}
  ]
}
```

This policy:
- Locks bridge paths (no actions allowed)
- Gives owners full control of their namespace
- Allows alice (admin) to post/delete anywhere
- Allows bob (delegate) to post NFTs on behalf of the owner
- Allows anyone to post to `/public/**`
- Requires NFT paths to use `nft.v1` schema
- Caps all objects at 1MB

---

## Validation Rules

SDKs must enforce:

1. Policy must be valid JSON
2. All path patterns must be syntactically valid
3. Role references must not be circular
4. Identity references in roles must be valid syntax
5. Actions must be from the defined set (or `"*"`)
6. Requirement conditions must use known condition types

Invalid policies must be rejected. Objects posted under an invalid policy are themselves invalid.

---

## Compatibility

- `policy.v2` requires no scripting engine, enabling lightweight client implementations
- Evaluation is fully deterministic across all conforming implementations
- Lite clients can evaluate policies without trusting external indexers
- Attestation-defined roles and `attested`/`not_attested` conditions read on-chain attestation objects and the message's inclusion time. Evaluation stays deterministic (a pure function of on-chain state and inclusion time, no external scoring), but reads more state than a self-contained policy: an evaluator must follow the referenced attestation paths. This is a deliberate trade — dynamic, expiry-aware governance in exchange for a larger evaluation footprint.

---
