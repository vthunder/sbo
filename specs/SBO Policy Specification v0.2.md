---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Policy Specification (v0.2)

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

---

## Identity Syntax

The `to` field in grants accepts these forms:

| Value | Meaning |
|-------|---------|
| `"owner"` | Owner of the path (from path segment) |
| `"*"` | Anyone (public access) |
| `"alice"` | Specific identity name (from `names/` namespace) |
| `{"key": "secp256k1:02..."}` | Specific public key |
| `{"role": "admin"}` | Anyone with this role |
| `{"any": ["alice", "bob"]}` | Any of these identities |

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
| `"/$owner/**"` | Dynamic: current owner's namespace |
| `"/$user/**"` | Dynamic: acting user's namespace |

---

## Requirement Conditions

Used in the `require` field of restrictions:

| Condition | Description |
|-----------|-------------|
| `{"max_size": 1048576}` | Object payload must be ≤ specified bytes |
| `{"schema": "nft.v1"}` | Object must use specified content schema |
| `{"schema": {"any": ["a.v1", "b.v1"]}}` | Object must use one of specified schemas |
| `{"content_type": "application/json"}` | Object must have specified content type |

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

## Migration from policy.v1

The JavaScript-based `policy.v1` schema is deprecated. New policies should use `policy.v2`.

| JS pattern | Declarative equivalent |
|------------|----------------------|
| `path.startsWith(user.name)` | `{"to": "owner", "on": "/$owner/**"}` |
| `user.name === 'admin'` | `{"to": "admin", ...}` |
| `user.roles.includes('mod')` | `{"to": {"role": "mod"}, ...}` |
| `object.schema === 'nft.v1'` | `{"require": {"schema": "nft.v1"}}` |
| `object.size < 1024` | `{"require": {"max_size": 1024}}` |

Complex logic (proof validation, stateful workflows) is out of scope for `policy.v2` and will be addressed in future specifications.

---

## Compatibility

- `policy.v2` requires no scripting engine, enabling lightweight client implementations
- Evaluation is fully deterministic across all conforming implementations
- Lite clients can evaluate policies without trusting external indexers

---
