
# SBO v0.4 - Simple Blockchain Objects

## Status
Draft

## Overview
The Simple Blockchain Object (SBO) is a minimal data model and envelope format for posting and updating structured objects to a blockchain or data availability layer in a way that supports replication, verification, and mutability. This version (v0.4) assumes a simple base layer with ordered transaction inclusion and no smart contract logic.

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

## Paths

Paths are collections, and are hierarchical. They may be nested (e.g. `nfts/animals/`), similar to file system paths.

Paths are themselves objects in the system with `Type: collection`, and may be created, updated, transferred, or deleted like any other object. Unlike other objects, they do not contain a payload, but they are used to set access control rules for the objects they contain. Deep paths can be used without explicitly creating the intermediate paths.

SBO does not define a hard-coded (assumed) ownership semantics for paths, but through the policy system, it is possible to define such semantics. For example, an SBO database may define /users/<user_id> paths where the owner of each collection is the user with the specified ID, and they can create and control objects within that scope.

Object references may be relative to the path of the object they are in, or absolute. For example, given two objects in the same collection, one object may refer to the other without a path.

Note that some references (owner, creator in particular) refer to identity objects in the names/ namespace as specified in the [Name Resolution Spec](#name-resolution-spec-v01).

## Creators

SBO includes an identity name resolution system that allows users to map human-readable names to public keys or other identity objects. See the [Name Resolution Spec](#name-resolution-spec-v01) for details.

When an object is owned by the same identity as the collection it is in, references to the object may omit the creator's identity (e.g. `abc` instead of `userA:abc`). Otherwise, the creator's identity must be specified to prevent collisions and ambiguity.

## URIs

SBO objects may be referenced using SBO URIs, which provide a more complete way to identify objects including cross-chain references and historical states. See the [SBO URI Format](#sbo-uri-format-v02) for details.

## On-Chain Messages

Objects are defined and manipulated via messages posted on chain. These messages represent specific actions (post, transfer, delete, etc.).

Each message contains a header envelope and (where appropriate) a payload. The canonical wire format is defined in the [SBO Wire Format Specification](./SBO%20Wire%20Format%20Specification%20v0.1.md).

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
| `Action` | One of `post`, `move`, `transfer`, or `delete` |
| `Path` | Collection path with trailing slash, e.g. `/nfts/` |
| `ID` | Object ID string, e.g. `nft-123` |
| `Type` | Either `object` or `collection` |
| `Content-Type` | MIME type of payload, e.g. `application/json` |
| `Content-Length` | Size of the payload in bytes |
| `Content-Hash` | Hash of payload with algorithm prefix, e.g. `sha256:a1b2c3...` |
| `Signing-Key` | Public key with algorithm prefix, e.g. `secp256k1:02a1b2...` |
| `Signature` | Signature bytes in lowercase hex |

### Optional Headers

| Header | Description |
|--------|-------------|
| `Owner` | Owner of the object (identity reference) |
| `Creator` | Original creator (defaults to signer) |
| `Content-Encoding` | Transport encoding (`utf-8`, `gzip`, `base64`) |
| `Content-Schema` | Payload schema (e.g. `nft.v1`) |
| `New-ID` | Required for `move` action |
| `New-Path` | Required for `move` action |
| `New-Owner` | Required for `transfer` action |
| `Policy-Ref` | Reference to a policy object (SBO URI) |
| `Related` | JSON array of related object references |

See the [Wire Format Specification](./SBO%20Wire%20Format%20Specification%20v0.1.md) for complete details on header ordering, cryptographic formats, and signature computation.

### ID, Path, and Type

- `ID`, `Path`, and `Type` are all required headers.
- The object or collection is defined by its ID at the path specified by `Path`.
- If `Type` is `collection`, the object refers to a collection, and contains metadata but no payload.
- If `Type` is `object`, the object is an object with a payload.

The same ID in the same collection may only refer to one object (or collection), unless the objects (or collections) have different creators.

### Actions

Valid values for `action` are:

- `post`: Create a new object or post an updated version. This is the only action used to create or mutate object content or headers.
- `move`: Move and/or rename an object. Requires `New-ID` and/or `New-Path` headers.
- `transfer`: Change ownership of an object. Requires `New-Owner` header.
- `delete`: Mark an object as removed. Modeled as a transfer to a null owner (`null:`).

### Related Objects

The `Related` header contains a JSON array of relationship objects. Each entry has:
- `rel`: the type of relation (e.g., `license`, `collection`, `policy`)
- `ref`: a reference (SBO URI or relative path) to the target object

Example: `Related: [{"rel":"license","ref":"sbo://Avail:13/licenses/cc-by"}]`

### Signature Scope

The signature covers all header bytes (in canonical order) plus the trailing blank line, **excluding the `Signature` header entirely**. The payload is protected indirectly via `Content-Hash`.

See the [Wire Format Specification](./SBO%20Wire%20Format%20Specification%20v0.1.md) for the exact signature computation algorithm.

## Rules

- Messages are processed in blockchain order.
- Invalid messages must be rejected (skipped by all clients).
- Validity is determined by:
  - Adherence to the SBO specification (envelope format, fields, ownership, signature, etc.)
  - Conformance to applicable policy constraints
  - Other specific rules as defined below
- Unless otherwise specified or constrained by a policy object, the canonical state of an object is determined using a Last-Write-Wins (LWW) policy.

### Object Ownership

Ownership of an object is determined by the `Owner` header. This header points to an identity record as specified in the [Name Resolution Specification](./SBO%20Name%20Resolution%20Specification%20v0.1.md).

Ownership may be transferred to another identity via a transfer message.

### Action Specific Rules

#### post
- Object creation is idempotent: it may create a new object or update an existing one.
- Object creation is governed by the policy of the nearest ancestor collection object with a policy reference.
- Object updates are governed by the policy of the object itself.
- May only set or update `Policy-Ref` if the object is owned by the creator of the object.
- Only the current owner may post updates to the object, unless forbidden by the object's policy.

#### move
- Move may modify both `id` and `path` (if allowed by policy).
- Only valid if the destination ID does not exist by the same creator at the destination path.
- Move is governed by both the policies of the source and destination paths. In both cases the nearest ancestor collection object with a policy reference is used:
  - Source path: Must allow moving the object out of the collection.
  - Destination path: Must allow receiving the object.

#### transfer
- Transfers are governed by the policy of the object itself.
- (TBD - under consideration) Transfers may move the object to the "inbox" path as specified in the destination owner's identity claim object (see [Name Resolution](#name-resolution-spec-v01)).
- Only the current owner may transfer the object, unless forbidden by the object's policy.

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

Policy objects themselves are specified in ... (a future spec).

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
Signing-Key: secp256k1:02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a
Signature: 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809

{"message":"Hello, world!"}
```
