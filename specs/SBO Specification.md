---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO — Simple Blockchain Objects

**Part of SBO Protocol v0.5**

## Status
Draft

## Overview
The Simple Blockchain Object (SBO) is a minimal data model and envelope format for posting and updating structured objects to a blockchain or data availability layer in a way that supports replication, verification, and mutability. This version assumes a simple base layer with ordered transaction inclusion and no smart contract logic.

SBO defines:
- A human- and machine-readable object envelope
- Rules for posting, updating, transferring, and deleting objects
- A canonical serialization and signature model
- A conflict resolution strategy based on chain order

## Object Identity

Each object in the system is identified by an ID, a creator, and a path. The fully qualified ID of an object is as follows, but not all elements are required to be specified when being referenced, depending on the context:

```
[path/][creator:]id
```

- `path` is a hierarchical namespace. See [Paths](#paths).
- `creator` is the account identifier of the original creator of the object. See [Creators](#creators).
- `id` is a string that is the logical identifier of the object.

### Identifier Syntax

IDs, path segments, and creator names share the same syntax rules:

**Allowed characters:** `A-Z a-z 0-9 - _ . ~` (the "unreserved" character set from [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-2.3)), plus `@` and `:`. `@` carries email-rooted identity references (`alice@gmail.com`; see the [Identity Specification](./SBO%20Identity%20Specification.md)). `:` carries namespaced identifiers — attestation type IDs (`role:moderator`; see the [Attestation Specification](./SBO%20Attestation%20Specification.md)) and algorithm-prefixed key references (`ed25519:…`). Both are unambiguous because the canonical state-key delimiter is the ASCII Unit Separator (`0x1F`), not `:`.

**Length:** 1-256 characters

**Case sensitivity:** IDs are case-sensitive. `Foo` and `foo` are different.

**Unicode:** Not allowed directly. Use percent-encoding for non-ASCII characters (e.g., `café` → `caf%C3%A9`).

**Grammar (ABNF):**
```
id       = 1*256id_char
id_char  = ALPHA / DIGIT / "-" / "_" / "." / "~" / "@" / ":"
segment  = id
path     = "/" *(segment "/")
creator  = id
```

**Parsing object references:**
```
object_ref = [path] [creator ":"] id

Examples:
  "punk-001"              → id only
  "alice:punk-001"        → creator:id
  "/nfts/punk-001"        → path + id
  "/nfts/alice:punk-001"  → path + creator:id
```

To parse an object reference:
1. If the string contains `/`, split at the last `/`. Left part (including `/`) is `path`, right part is `remainder`. Otherwise, `remainder` is the whole string.
2. If `remainder` contains `:`, split at the first `:`. Left part is `creator`, right part is `id`. Otherwise, `id` is the whole remainder.

## Paths

Paths are collections, and are hierarchical. They may be nested (e.g. `nfts/animals/`), similar to file system paths.

Paths are themselves objects in the system with `Type: collection`, and may be created, updated, transferred, or deleted like any other object. Collections may optionally include a metadata payload (e.g., name, description, icon), but are primarily used to set access control rules for the objects they contain. Deep paths can be used without explicitly creating the intermediate paths.

SBO does not define a hard-coded (assumed) ownership semantics for paths, but through the policy system, it is possible to define such semantics. For example, an SBO database may define /users/<user_id> paths where the owner of each collection is the user with the specified ID, and they can create and control objects within that scope.

Object references may be relative to the path of the object they are in, or absolute. For example, given two objects in the same collection, one object may refer to the other without a path.

Note that some references (owner, creator in particular) refer to identity objects in the names/ namespace as specified in the [Identity Specification](./SBO%20Identity%20Specification.md).

## Creators

SBO includes an identity name resolution system that allows users to map human-readable names to public keys or other identity objects. See the [Identity Specification](./SBO%20Identity%20Specification.md) for details.

When an object is owned by the same identity as the collection it is in, references to the object may omit the creator's identity (e.g. `abc` instead of `userA:abc`). Otherwise, the creator's identity must be specified to prevent collisions and ambiguity.

## URIs

SBO objects may be referenced using SBO URIs, which provide a more complete way to identify objects including cross-chain references and historical states. See the [SBO URI Specification](./SBO%20URI%20Specification.md) for details.

## On-Chain Messages

Objects are defined and manipulated via messages posted on chain. These messages represent specific actions (post, transfer, delete, etc.).

Each message contains a header envelope and (where appropriate) a payload. The canonical wire format is defined in the [SBO Wire Format Specification](./SBO%20Wire%20Format%20Specification.md).

### Envelope Format

The envelope consists of line-based headers (similar to HTTP) followed by a blank line and the payload:

```
Header-Name: value
Another-Header: value

<payload bytes>
```

### Required Headers

| Header | Description |
|--------|-------------|
| `SBO-Version` | Must be `0.5` |
| `Action` | One of `post`, `transfer`, `delete`, or `import` |
| `Path` | Collection path with trailing slash, e.g. `/nfts/` |
| `ID` | Object ID string, e.g. `nft-123` |
| `Type` | Either `object` or `collection` |
| `Content-Type` | MIME type of payload (required if payload present) |
| `Content-Length` | Size of the payload in bytes (required if payload present) |
| `Content-Hash` | Hash of payload with algorithm prefix (required if payload present) |
| `Public-Key` | Public key with algorithm prefix, e.g. `secp256k1:02a1b2...` |
| `Signature` | Signature bytes in lowercase hex |

**Note:** Content headers (`Content-Type`, `Content-Length`, `Content-Hash`) are required when a payload is present. For `Type: object`, payload is always required. For `Type: collection`, payload is optional (used for metadata like name, description).

### Optional Headers

| Header | Description |
|--------|-------------|
| `Owner` | Owner of the object (identity reference) |
| `Creator` | Original creator (defaults to signer) |
| `Content-Encoding` | Transport encoding (`utf-8`, `gzip`, `base64`) |
| `Content-Schema` | Payload schema (e.g. `nft.v1`) |
| `New-ID` | New object ID for `transfer` action |
| `New-Path` | New path for `transfer` action |
| `New-Owner` | New owner for `transfer` action |
| `Policy-Ref` | Reference to a policy object (SBO URI) |
| `Related` | JSON array of related object references |
| `Proof-Type` | Type of proof attached (`burn` for unlocks) |
| `Proof` | Base64-encoded proof for `transfer` actions |
| `Origin` | External origin identifier for `import` action |
| `Registry-Path` | Registry path for `import` action |
| `Object-Path` | Destination path for `import` action |
| `Attestation` | Base64-encoded attestation for `import` action |

See the [Wire Format Specification](./SBO%20Wire%20Format%20Specification.md) for complete details on header ordering, cryptographic formats, and signature computation.

### ID, Path, and Type

- `ID`, `Path`, and `Type` are all required headers.
- The object or collection is defined by its ID at the path specified by `Path`.
- If `Type` is `collection`, the entry defines a collection (path). Payload is optional (metadata).
- If `Type` is `object`, the entry defines an object. Payload is required.

**Path conventions:**
- `Path` header: Always ends with `/` (it's the container). Examples: `/`, `/alice/`, `/alice/nfts/`
- `ID` header: Never contains `/`. Examples: `alice`, `nft-123`
- Full path to an object or collection: `Path` + `ID`, no trailing slash. Examples: `/alice`, `/alice/nfts/punk-001`

The same ID in the same collection may only refer to one object (or collection), unless the objects (or collections) have different creators.

### Actions

Valid values for `action` are:

- `post`: Create a new object or post an updated version. This is the only action used to create or mutate object content or headers.
- `transfer`: Move, rename, and/or change ownership of an object. Requires at least one of `New-Owner`, `New-Path`, or `New-ID`. For bridge unlocks, requires `Proof-Type` and `Proof` headers with oracle attestation.
- `delete`: Mark an object as removed. Modeled as a transfer to a null owner (`null:`).
- `import`: Atomically create a registry entry and object for cross-chain imports. Requires `Origin`, `Registry-Path`, `Object-Path`, and `Attestation` headers. See [Bridge Specification](./SBO%20Bridge%20Specification.md).

### Related Objects

The `Related` header contains a JSON array of relationship objects. Each entry has:
- `rel`: the type of relation (e.g., `license`, `collection`, `policy`)
- `ref`: a reference (SBO URI or relative path) to the target object

Example: `Related: [{"rel":"license","ref":"sbo+raw://avail:mainnet:13/licenses/cc-by"}]`

### Signature Scope

The signature covers all header bytes (in canonical order) plus the trailing blank line, **excluding the `Signature` header entirely**. The payload is protected indirectly via `Content-Hash`.

See the [Wire Format Specification](./SBO%20Wire%20Format%20Specification.md) for the exact signature computation algorithm.

**Note:** `Content-Hash` covers only the payload. Separately, the [State Commitment Specification](./SBO%20State%20Commitment%20Specification.md) defines an `object_hash` over the complete wire-format message (headers + payload); that hash, not `Content-Hash`, is what the state trie commits to.

## Rules

- Messages are processed in blockchain order.
- Invalid messages must be rejected (skipped by all clients).
- Validity is determined by:
  - Adherence to the SBO specification (envelope format, fields, ownership, signature, etc.)
  - Conformance to applicable policy constraints
  - Other specific rules as defined below
- Unless otherwise specified or constrained by a policy object, the canonical state of an object is determined using a Last-Write-Wins (LWW) policy.

### Validity Layers

SBO distinguishes two layers of validity, because they have fundamentally different verification properties:

- **Envelope validity (Layer 1)** is self-contained and deterministic. It depends only on the message bytes and on prior on-chain state: well-formedness (see the [Wire Format Specification](./SBO%20Wire%20Format%20Specification.md)), a correct `Signature` over the canonical headers, a matching `Content-Hash`, and conformance to the applicable policy evaluated over keys and objects already on chain. Layer 1 is therefore *objective*: every client that replays the chain computes the same result, from genesis, forever. SBO is a based design — writers post directly to the data-availability layer and nothing SBO-aware gatekeeps inclusion — so Layer 1 is established by clients on replay, not enforced by a privileged operator. Its objectivity comes from determinism, not from a sequencer.

- **Attribution (Layer 2)** binds a signing key to an *identity* — for example, an email address controlled through an external identity provider. Attribution concerns data that originates outside the chain (the provider's keys), so it does not become objective for free. SBO makes it objective by requiring that the evidence be **self-authenticating against a single on-chain anchor** and carried in (or referenced from) the replayable record — see [Attribution Capture](#attribution-capture). Until that evidence is present a message's attribution is unverifiable, and clients MUST NOT assume any inclusion-time party verified it; each reader establishes attribution itself from the captured evidence. With the evidence present, attribution too is a deterministic function of on-chain data, and all correct clients converge.

#### Attribution Capture

Because attribution originates outside the chain, any authorization that depends on it MUST carry **self-authenticating evidence** — verifiable against an on-chain anchor without any network access or trusted intermediary — in the message, or reference such evidence already recorded on chain. Email-rooted identities achieve this by anchoring attribution to the global DNS hierarchy. Two pieces of evidence establish that a signing key speaks for an email address:

1. An **authentication certificate** (`Auth-Cert` header) — a browserid certificate, signed by an identity provider's key, binding the signing key (`Public-Key`) to an email address.
2. **DNSSEC evidence** — the DNSSEC chain proving the provider's key was published at `_browserid.<provider-domain>`, with signature-validity windows covering the message's inclusion time, terminating at the **DNS root key-signing key (KSK)**.

The protocol pins exactly one global anchor on chain: the **DNS root KSK**, as a short, governance-maintained history that spans root-key rollovers. Given that anchor and the message's inclusion timestamp, verifying attribution — certificate signature, DNSSEC chain, and validity windows — is a **deterministic function of on-chain data**. Consequently:

- **All correct clients converge** on the same attribution; no sequencer, checkpoint, or trusted recorder is required.
- **A from-scratch replayer can verify any past message** with no network access: the captured DNSSEC evidence proves the provider's key *as of the inclusion time*, independent of any later key rotation.

Because DNSSEC is required end to end — a domain that does not run its own provider is served by a recognized broker that itself enforces DNSSEC — every attribution chains to the root KSK. There is no coverage gap and no need to mirror provider keys on chain. Trust reduces to exactly what email identity already implies: the DNS root and DNSSEC correctness, plus the deployment's designation of recognized broker(s).

See the [SBO Authorization Specification](./SBO%20Authorization%20Specification.md) for the certificate and evidence formats, evidence reuse (large DNSSEC evidence may be posted once as a self-authenticating on-chain object and referenced by later writes), the required DNSSEC algorithms, and the inclusion-time clock. A zero-knowledge proof of this verification is a later optimization that shrinks evidence size and can additionally conceal the provider domain and email (enabling pseudonymous identities); it does not change the trust model.

### Object Ownership and Authorization

Ownership of an object is determined by the `Owner` header, which references an identity record as specified in the [Identity Specification](./SBO%20Identity%20Specification.md). If `Owner` is absent, the owner is the creator.

A message is **authorized** to act on an object when its signer resolves to the object's owner. Resolution proceeds in two steps:

1. **Attribution (Layer 2):** the signing key (`Public-Key`) is bound to an identity via the evidence carried in the message (see [Attribution Capture](#attribution-capture)). For email-rooted identities the `Auth-Cert` certificate binds the signing key to an email address.
2. **Ownership resolution (Layer 1 over on-chain state):** the resolved identity is matched against the object's `Owner`. Ownership references may be indirect — an owner naming an identity (e.g. `alice@community.org`) resolves through that identity's record under `/sys/names/` to its controlling identity, and so on, until it grounds in a directly-controlled identity. An object is writable by whoever controls the identity at the end of this chain. See the [Identity Specification](./SBO%20Identity%20Specification.md) for resolution and grounding rules.

Both steps are deterministic given the message and on-chain state (including the captured attribution evidence and the pinned DNS root KSK), so all correct clients reach the same authorization decision. As with all validity in a based design, the decision is established by each reader on replay rather than gatekept at inclusion: a message whose signer does not resolve to the owner is disregarded, not rejected by the base layer. Ownership may be transferred to another identity via a transfer message.

### Action Specific Rules

In the rules below, "the current owner" means a signer authorized per [Object Ownership and Authorization](#object-ownership-and-authorization) — that is, a signer whose key resolves, through attribution and ownership resolution, to the object's owner.

#### post
- Object creation is idempotent: it may create a new object or update an existing one.
- Object creation is governed by the policy of the nearest ancestor collection object with a policy reference.
- Object updates are governed by the policy of the object itself.
- May only set or update `Policy-Ref` if the object is owned by the creator of the object.
- Only the current owner may post updates to the object, unless forbidden by the object's policy.

#### transfer
- Transfer may modify `owner`, `path`, and/or `id` (at least one required).
- Only the current owner may transfer the object, unless allowed by the object's policy.
- Transfers are governed by the policy of the object itself.
- If `New-Path` or `New-ID` is specified:
  - Only valid if the destination does not exist by the same creator at the destination path.
  - Both source and destination path policies apply:
    - Source path: Must allow moving the object out of the collection.
    - Destination path: Must allow receiving the object.

#### delete
- Modeled as transfers to a null owner (`null:`).
- Message must be signed by the current owner of the object.

### Policies

A policy object may be used to constrain the behavior of an object or (in the case of paths) its hierarchical descendants. Policies are themselves objects in the system, and are referenced by the `Policy-Ref` header.

Policies are resolved by following the path hierarchy. Objects and paths inherit policy enforcement from the nearest ancestor collection object with a policy reference. Nonexistent intermediate collection objects or paths without a policy reference are skipped in the policy resolution chain.

The root path (`/`) itself references the root policy object, which is thus the default policy for all objects in the system, except as otherwise specified.

In the absence of a root object policy, messages are considered invalid and discarded. During development, a more relaxed root policy is recommended to allow for easier testing and development.

For example, to post to `/foo/bar/baz`:

1. Check for a collection object with a policy reference at `/foo/bar/baz`
2. If none, check `/foo/bar`, then `/foo`, then `/`
3. Use the first collection object with `Policy-Ref` found
4. If none exists, the message is considered invalid and discarded.

Policy objects themselves are specified in the [Policy Specification](./SBO%20Policy%20Specification.md).

## Future Extensions
- The `update_type` field supports future merge strategies (e.g., diffs, CRDTs).
- Support for content-addressed storage (e.g., IPFS) may be added via `content_storage_ref` in lieu of the payload.

## Example

```
SBO-Version: 0.5
Action: post
Path: /random/stuff/
ID: hello-world-123
Type: object
Content-Type: application/json
Content-Encoding: utf-8
Content-Length: 27
Content-Hash: sha256:4b7a3c8f2e1d5a9b0c6e3f7a2d4b8c1e5f9a3d7b0c4e8f2a6d9b3c7e1f5a9d3b
Public-Key: secp256k1:02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a
Signature: 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809

{"message":"Hello, world!"}
```
