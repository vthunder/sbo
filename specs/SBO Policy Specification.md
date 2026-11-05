---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO Policy Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v0.5 (2026-11, audit)**: Documented the shipped delegation model (S12): the `govern` action, `pin`, `descendant_constraint` (`allowed_grants`, `mandated_restrictions`, `forbid_pinning`), and the `dnssec_proof` and `require_payload_signed_by` conditions. Validation on write is normative: role cycles reject, unknown keys anywhere in the document reject (Q39), pattern syntax is checked, and the wildcard cap of 32 applies (Q38); role resolution is bounded at evaluation (Q17). Owner is a principal like any other (Q13).

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
Public-Key: ed25519:a1b2c3...
Signature: 1a2b3c...
```

### Payload Structure

```json
{
  "roles": { ... },
  "deny": [ ... ],
  "grants": [ ... ],
  "restrictions": [ ... ],
  "pin": { ... },
  "descendant_constraint": { ... }
}
```

All sections are optional. Missing sections are treated as empty. **No other keys are permitted**: a policy document, a grant, a restriction, a `require` object, a `pin` or a `descendant_constraint` that carries a key not defined in this specification is **invalid** (see [Validation Rules](#validation-rules)). A misspelled condition (`max_sise`) is therefore a rejected policy, never an empty requirement that fails open.

### Where a policy lives and what it governs

A `policy.v2` object posted at container path `P` (any id) is the **governing policy of `P`**: it governs every write whose container path is `P` or a descendant of `P`, until a nearer governing policy intervenes. Resolution for a write to container `C` walks `C`, then each ancestor of `C`, and uses the first governing policy found; the root policy at `/sys/policies/` is the default when no ancestor has one. The policy that governs a write to the **policy object itself** is its **parent**'s governing policy (the nearest governing policy strictly above `P`), never the object being written; see [`govern`](#govern-installing-a-policy).

Evaluation is pure: a function of the message, the chain state at the message's inclusion point, and the inclusion time. It consults no network and no clock other than the block's.

---

## Evaluation Order

1. **Deny check** — if path matches any deny pattern, action is denied
2. **Grant check** — if user matches a grant for this action and path, proceed
3. **Restriction check** — if restrictions exist for this path, verify conditions
4. **Default** — if no matching grant, deny

**The owner is a principal like any other.** Nothing bypasses this order: an object's owner updating, transferring or deleting it is evaluated by the same four steps, matching grants as `to: "owner"`. A policy that carries no `owner` grant for an action denies the owner that action, and `deny` and `restrictions` apply to the owner exactly as to anyone else. The implicit owner permission of earlier drafts is now an explicit grant that the default root policy and the genesis presets carry (`{"to": "owner", "can": ["update", "transfer", "delete"], "on": "/**"}` or narrower); a community policy inherits it from its ancestor rather than from a special case in the evaluator. The two exceptions are not owner privileges: a name-claim update is controller-only (Identity spec anti-hijack rule), and a write to a policy object is a [`govern`](#govern-installing-a-policy) action evaluated against the parent policy.

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
| `id` | string | *Optional.* Object-id pattern. Absent ⇒ **any id**. See [Object-Id Patterns](#object-id-patterns). |

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
| `id` | string | *Optional.* Object-id pattern. Absent ⇒ **any id**. See [Object-Id Patterns](#object-id-patterns). |
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

### `pin`

A policy MAY freeze the delegation terms it was installed under to one historical version of its ancestor (the P2 *sovereignty* property):

```json
{
  "pin": {
    "ancestor": "/sys/policies/",
    "hash": "sha256:<content-hash of the ancestor policy object>",
    "block": 1234
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `ancestor` | Yes | Container path of the pinned ancestor policy (the direct parent's governing policy) |
| `hash` | Yes | `Content-Hash` of the ancestor policy object version pinned; authoritative and reorg-safe |
| `block` | No | Locator hint only; carries no meaning in evaluation |

Semantics:

- **Governance resolves against the pinned version.** Who may `govern` (amend, replace, delete) a pinned policy is evaluated against the ancestor version named by `hash`, not the ancestor's current version. A later amendment of the ancestor therefore cannot reach into a pinned subtree. An **unpinned** policy *tracks* its ancestor: the current latest version governs it (the revocable / eminent-domain regime).
- **Forward-only.** On create, `hash` MUST equal the content hash of the ancestor's current version. On update, the policy either keeps its existing pin verbatim or advances it to the ancestor's current version; any other value is invalid. A pin can never point backwards.
- **Only ordinary evaluation is affected through governance.** Grants, restrictions and `deny` of a write under the pinned policy are evaluated against the pinned policy itself as usual; the pin changes only which ancestor version decides *who may change the pinned policy*.
- Implementations MUST retain every policy version that some live pin references (keyed by content hash) so that governance of a pinned policy is reproducible on replay.

### `descendant_constraint`

A policy MAY impose a ceiling and a template on its **direct child policies** (P3/P4). Each level re-delegates its own template downward, so every check is local to one parent–child pair:

```json
{
  "descendant_constraint": {
    "allowed_grants": [
      {"to": "owner", "can": ["post", "delete"], "on": "/$owner/**"},
      {"to": "*", "can": ["create"], "on": "/public/**"}
    ],
    "mandated_restrictions": [
      {"on": "/**", "require": {"max_size": 1048576}}
    ],
    "forbid_pinning": false
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `allowed_grants` | `[]` | The grants a direct child MAY make. Every child grant MUST be covered by one template grant: `to`, `on` and (when the template sets it) `id` byte-equal, and every child action covered by a template action (`post` covers `create`/`update`, `*` covers all). An absent template `id` covers any child id; an `id` on the template MUST be reproduced exactly. An **empty list forbids the child from granting anything**. |
| `mandated_restrictions` | `[]` | Restrictions every direct child MUST carry verbatim (byte-equal after canonical serialization). |
| `forbid_pinning` | `false` | When true, a direct child MUST NOT carry a `pin`: children always track the latest ancestor (the strict top-down regime). Evaluated against the parent's **current** version, so a parent can retighten at any time. |

Coverage is deliberately conservative: a child cannot broaden the recipient or the path of a template grant, only narrow its action set. Pattern subsumption is not decided; the comparison is byte-exact. A child policy that violates its parent's constraint is invalid at write time, and the constraint is re-checked on every update of the child.

---

## Identity Syntax

The `to` field in grants accepts these forms:

| Value | Meaning |
|-------|---------|
| `"owner"` | Owner of the path (from path segment) |
| `"*"` | Anyone (public access) |
| `"alice@example.com"` | A specific email-rooted identity |
| `"alice"` | A specific name (from the `/sys/names/` namespace) |
| `{"key": "ed25519:a1b2..."}` | A specific public key (key-rooted identity) |
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
| `"govern"` | Install, replace or delete a `policy.v2` object at a path (see below). **Not** covered by `"*"`, `"post"` or `"create"`. |
| `"*"` | All ordinary actions (everything above except `govern`) |

**Note:** The distinction between `create` and `update` allows policies to grant first-come-first-served creation (e.g., identity claims) without granting update rights. Use `post` when both should be allowed.

### `govern` — installing a policy

Writing a `policy.v2` object is **meta-authority** over a subtree, so it is its own action:

- A `post`, `delete` or `transfer` whose object carries `Content-Schema: policy.v2` is evaluated as `govern` on the **target container path**, against the **parent policy** (the nearest governing policy strictly above the target), never against the policy being written or replaced and never via an owner shortcut. Owning the slot a policy sits in confers nothing.
- `govern` is granted only by an explicit `"govern"` in `can`. `"*"`, `"post"` and `"create"` do not include it, so an ordinary create grant on a subtree cannot be used to plant a shadowing policy and capture the subtree.
- Because an ancestor with `govern` evaluates against *its* parent, an ancestor can always reclaim or delete a delegated policy, unless that policy is [pinned](#pin) to a version that does not grant it.
- After the `govern` check, the new document is validated ([Validation Rules](#validation-rules)) and checked against the parent's [`descendant_constraint`](#descendant_constraint) and pin rules. All three must pass.

Example: a root policy that lets an admin role install community policies anywhere, and lets each community's own moderators govern only beneath their community:

```json
{
  "grants": [
    {"to": {"role": "admin"}, "can": ["govern"], "on": "/**"},
    {"to": {"role": "moderator"}, "can": ["govern"], "on": "/communities/$user/**"}
  ]
}
```

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

### Wildcard cap

A path pattern (`on`, `deny`) MUST contain at most **32 wildcard segments** (each `*` or `**` segment counts as one), and an id pattern (`id`) at most **32 `*` characters**. Path patterns MUST be absolute (start with `/`). A pattern with more is a syntax error and the policy is rejected at write time (Validation Rule 2). The bound exists so that matching cost is a stated size limit, like the 256-character id limit: a conforming matcher MUST run in time polynomial in the pattern and path lengths (a memoised, O(wildcards × segments) matcher is the reference; a backtracking matcher is exponential in the number of wildcards and is not conforming even under the cap). The same cap applies to warrant `path:` scopes (see the [Authorization Specification](./SBO%20Authorization%20Specification.md#wildcard-cap)).

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

## Object-Id Patterns

`on` matches an object's **container path**; it never sees the object's **id**.
An object at path `/agreements/a1/` with id `proposal` matches the pattern
`/agreements/*/` — and so does its sibling with id `acceptance`. Path patterns
alone therefore cannot express a rule about one kind of object inside a shared
container.

The optional `id` field, valid on both **grants** and **restrictions**, supplies
that discriminator. The matching language is deliberately identical in both
places.

| Pattern | Matches |
|---------|---------|
| `"proposal"` | Exactly that id |
| `"*"` | Any id (same as omitting the field) |
| `"ev_*"` | Any id with that prefix; `*` stands for any run of characters |
| `"$user"` | Dynamic: the acting signer's canonical identity |

**Absent ⇒ any id.** A policy written before this field existed keeps its exact
meaning, and an unset `id` is omitted from the serialized policy.

**Why a separate field, not a longer path pattern.** `/agreements/*/proposal` is
ambiguous: it could mean the container `/agreements/x/proposal/` or the object
with id `proposal` at `/agreements/x/`. Keeping the id out of the path pattern
removes the ambiguity.

Policy variables (`$owner`, `$user`, `$email`, `$name`) interpolate exactly as in
path patterns, and an undefined variable fails closed the same way.

**Delegation.** In a `descendant_constraint` template, an absent `id` on the
template covers any child `id`; an `id` **on** the template must be reproduced
exactly by the child grant. Otherwise a child omitting `id` (meaning *any* id)
would escape a template that had narrowed it to one.

```json
{
  "restrictions": [
    {"on": "/agreements/*/", "id": "proposal", "require": {"schema": "agreement.proposal.v1"}}
  ]
}
```

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
| `{"fields": [{"pointer": "/a/b", "min": 1}]}` | Values inside the JSON payload, addressed by pointer. See [Payload-field conditions](#payload-field-conditions). |
| `{"dnssec_proof": true}` | The payload must be a valid DNSSEC proof for the domain the object is named after. See [Self-authorizing DNSSEC objects](#self-authorizing-dnssec-objects-dnssec_proof). |
| `{"require_payload_signed_by": {"path": "/sys/domains/"}}` | The payload is a JWT whose issuer is an object under `path` and whose signature verifies under that object's key. See [Payload signed by an on-chain key](#payload-signed-by-an-on-chain-key-require_payload_signed_by). |

Condition keys are a closed set. A `require` object carrying any key not in this table is invalid (Validation Rule 6); it never degrades to an empty requirement.

### Self-authorizing DNSSEC objects (`dnssec_proof`)

`{"dnssec_proof": true}` makes the write **self-authorizing**: the payload itself proves write authority, so the restriction is safe to pair with an unprivileged grant (`"to": "*"`). The condition holds when:

1. the write's container is `/sys/dnssec/` and its id is a domain name `<domain>` (the object is named after the domain it proves);
2. the payload is a `dnssec.v1` object carrying an RFC 9102 DNSSEC chain that validates offline against the pinned DNS root KSK history at `/sys/trust/dns-root` (the anchor in force at the message's inclusion time; see the [Authorization Specification](./SBO%20Authorization%20Specification.md));
3. the validated chain carries a `_browserid.<domain>` record for **exactly** this `<domain>`, which binds the proof to the path: a valid proof for a different domain fails; and
4. the chain's RRSIG windows bracket the inclusion time, and, when the slot is already occupied, the new evidence satisfies the monotonic-freshness rule of the [Attribution Specification](./SBO%20Attribution%20Specification.md) (it may not lower the occupant's RRSIG expiration or carry an older DNSKEY set).

Anything else (no payload, a proof that does not validate, a proof for another name, a stale window, a rollback) is a denial.

### Payload signed by an on-chain key (`require_payload_signed_by`)

`{"require_payload_signed_by": {"path": "<pattern>"}}` requires that the payload be a JWT whose **issuer object** lives at a path matching `path`, and that the JWT's signature **verifies under that object's public key** as stored on chain at the message's inclusion point. The issuer is taken from the JWT's `iss` claim mapped to an object reference (`domain:<d>` ⇒ `/sys/domains/` id `<d>`; a name ⇒ `/sys/names/` id `<name>`). Matching the issuer **string** against the pattern is not sufficient: an implementation MUST load the issuer object and verify the signature, otherwise any signer satisfies the restriction by writing the expected `iss`. A missing issuer object, a path outside the pattern, a payload that is not a JWT, or a signature that does not verify is a denial. Typical use: a repository that only accepts `identity.v1` records certified by one of its root-of-trust domains.

### Payload-field conditions

`fields` conditions read **inside** the payload, addressing values by
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON pointer. Every condition
in the array must hold; they are AND-ed with each other and with the rest of
`require`.

| Key | Meaning |
|-----|---------|
| `pointer` | JSON pointer into the payload, e.g. `/contribution/percentage` |
| `eq` | The value must equal this exactly (any JSON type) |
| `min` | The value, read as a number, must be ≥ this |
| `max` | The value, read as a number, must be ≤ this |

**Numbers may be strings.** Money is carried as a decimal string in several
schemas, so `"0.01"` compares as `0.01`. Non-finite values (NaN, infinity) never
satisfy a comparison.

**Fail-closed.** A message with no payload, a payload that is not JSON, a pointer
that resolves to nothing, or a value that is not readable as the compared type is
a **denial** — never a skipped check.

**Deliberately scalar.** A condition compares one addressed value against a
constant; the policy language has no expression evaluator and no parser. Where a
payload carries something formula-shaped, express it as *structure* and pin it
with several conditions. For example, a contribution declared as
`{"fn": "max", "amount": "0.01", "percentage": 0.01}` is floored by pinning the
function and flooring each operand:

```json
{"on": "/agreements/*/", "id": "proposal", "require": {"fields": [
  {"pointer": "/contribution/fn", "eq": "max"},
  {"pointer": "/contribution/amount", "min": 0.01},
  {"pointer": "/contribution/percentage", "min": 0.01}
]}}
```

Pinning `fn` is not optional: without it, a writer picks `min` and pays the
smaller operand.

Because conditions are AND-ed, componentwise comparison is **exact** for a floor
on `min(a,b)` and a cap on `max(a,b)`, and **conservative** (stricter than
strictly necessary) the other way round — a floor on `max(a,b)` requires both
operands to clear it, where the result alone would need only one. This is sound;
the exact form would need a disjunction the language does not have.

`attested` / `not_attested` use the same matching rules as an [attestation-defined role](#attestation-defined-roles) (`type`, optional `by`, subject resolves to the acting user's controller, in force at inclusion time). They let a policy gate actions on a positive claim (membership, a credential) or a negative one (a ban) without listing identities.

---

## Role Resolution

- Role members can be identity names, public keys, attestation sources, `any` lists, or other roles
- Role membership is resolved at evaluation time
- Circular role references are invalid (policy must be rejected at write time, Validation Rule 3)
- Unknown identity names result in no match (not an error)
- A reference to a role that the policy does not define is rejected at write time (Validation Rule 3)

**Bounded resolution.** Rejecting cycles on write is necessary but not sufficient (a policy admitted by an older implementation, or a very long acyclic chain, must not crash an evaluator). Evaluation therefore MUST also be bounded on its own: an evaluator keeps a visited set of roles along the current resolution path and stops at a **maximum nesting depth of 32** (`{"role": …}` inside `{"role": …}`, with each `any` list counting as a level). A role reference that would revisit a role already on the path, or exceed the depth, resolves to **no match** (fail closed), never to a panic or an unbounded loop. The write-time rule rejects any policy whose role graph has a cycle or a nesting depth greater than 32, or references a role it does not define, so a valid policy never reaches the evaluation guard.

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

A `policy.v2` document is validated **when it is written** (after the [`govern`](#govern-installing-a-policy) check and before it is applied), by every node, as part of consensus. The write is invalid, and the policy never becomes a governing policy, if any rule fails:

1. Policy must be valid JSON, and a JSON object
2. All path patterns and id patterns must be syntactically valid, including the [wildcard cap](#wildcard-cap) (at most 32 wildcard segments per path pattern, 32 `*` per id pattern; absolute paths)
3. Role references must not be circular, and every referenced role must be defined, and role nesting must not exceed depth 32 (see [Role Resolution](#role-resolution))
4. Identity references in roles, `to` fields and `any` lists must be valid syntax, of a known kind (`"owner"`, `"*"`, name, email, `{"key"}`, `{"role"}`, `{"any"}`, `{"attested"}`)
5. Actions must be from the defined set (or `"*"`); `govern` must be spelled explicitly
6. Requirement conditions must use known condition types, and every `fields` condition must carry a `pointer` and at least one comparison
7. **No unknown keys.** The policy object, each grant, each restriction, each `require` object, each `fields` condition, each `attested` source, the `pin` and the `descendant_constraint` MUST contain only the keys defined here. An unknown key anywhere is a rejection (strict parsing). Forward-compatible additions to the policy language are versioned by the `Content-Schema` (`policy.v3`), not by ignoring keys.
8. `pin`, when present, must satisfy the forward-only rule and the parent's `forbid_pinning`; the document must satisfy the parent's `descendant_constraint`

Invalid policies must be rejected. A policy write that fails validation leaves the previously governing policy in force (per-message semantics: the rejected message is invisible). Because validation is part of consensus, these rules are **consensus-changing**: a chain created before strict parsing (rule 7) was in force cannot adopt it on a client upgrade alone; the reference deployment adopts it at its `state-commitment/v2` regenesis, after surveying every existing policy for stray keys.

A second implementation may be held to all of the above by the conformance vectors (`conformance/` suites `policy`): a cyclic policy, a `max_sise` restriction, a 33-wildcard pattern and an unknown grant key are each a rejected write.

---

## Compatibility

- `policy.v2` requires no scripting engine, enabling lightweight client implementations
- Evaluation is fully deterministic across all conforming implementations
- Lite clients can evaluate policies without trusting external indexers
- Attestation-defined roles and `attested`/`not_attested` conditions read on-chain attestation objects and the message's inclusion time. Evaluation stays deterministic (a pure function of on-chain state and inclusion time, no external scoring), but reads more state than a self-contained policy: an evaluator must follow the referenced attestation paths. This is a deliberate trade — dynamic, expiry-aware governance in exchange for a larger evaluation footprint.

---
