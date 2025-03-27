
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

Paths are themselves objects in the system with `type: collection`, and may be created, updated, transferred, or deleted like any other object. Unlike other objects, they do not contain a payload, but they are used to set access control rules for the objects they contain. Deep paths can be used without explicitly creating the intermediate paths.

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

Each message contains a frontmatter envelope and (where appropriate) a payload.

### Envelope Format
The envelope consists of a YAML metadata header followed by the object payload, separated by a `---` marker and a newline. Valid fields are:

- `schema`: Must be `"SBO-v0.4"`.
- `id`: Object ID string, e.g. `nft-123`.
- `path`: Path string, e.g. `/nfts`.
- `type`: Object type, either `object` or `collection`.
- `owner`: Optional. Owner of the object. See [Ownership](#ownership).
- `action`: One of `post`, `rename`, `transfer`, or `delete`.
- `update_type`: Optional. `replace` (default), other values reserved for future merge strategies.
- `new_id`: Required for `rename`.
- `new_owner`: Required for `transfer`.
- `policy_ref`: Optional. Reference to a policy object.
- `related`: List of references to other objects, see below.
- `content_type`: MIME type of the object payload, e.g. `application/json`.
- `content_schema`: Optional payload schema (e.g. `nft.v1`).
- `content_encoding`: Transport encoding (e.g. `utf-8`, `gzip`).
- `content_size`: Size of the decoded content, in bytes.
- `content_hash`: Hash of the decoded payload.
- `content_hash_algorithm`: Hash algorithm used (e.g. SHA-256, Keccak256).
- `content_storage_ref`: Optional reference to a content-addressed storage location (not yet implemented, reserved for future use).
- `signature_algorithm`: Signature algorithm used (e.g. `ecdsa`).
- `signing_key`: Public key that signed the envelope.
- `signature`: Signature over the envelope (see below).
- `---`: End of YAML metadata (followed by a newline).
- [Raw payload]: Starts immediately after `---\n`.

### ID, Path, and Type

- `id`, `path`, and `type` are all required fields.
- The object or collection is defined by its ID `id` at the path specified by `path`.
- If `type` is `collection`, the object refers to a collection, and contains metadata but no payload.
- If `type` is `object`, the object is an object with a payload.

The same ID in the same collection may only refer to one object (or collection), unless the objects (or collections) have different creators.

### Actions

Valid values for `action` are:

- `post`: Create a new object or post an updated version. This is the only action used to create or mutate object content or frontmatter.
- `rename`: Rename an object. Requires a `new_id` field.
- `transfer`: Change ownership of an object. Requires a `new_owner` field.
- `delete`: Mark an object as removed. Modeled as a transfer to a null owner (`null:`).

### Related Objects
The `related` field is a list of relationships and target objects. Each entry has:
- `relation`: the type of relation (e.g., 'collection', 'license', etc.)
- `target`: a reference (URI or ID) to the target object

### Signature Scope
The signature covers:
- All bytes from the start of the envelope up to and including the line containing `---\n`.
- The `signature` field itself is excluded entirely from the signed content.

## Rules

- Messages are processed in blockchain order.
- Invalid messages must be rejected (skipped by all clients).
- Validity is determined by:
  - Adherence to the SBO specification (envelope format, fields, ownership, signature, etc.)
  - Conformance to applicable policy constraints
  - Other specific rules as defined below
- Unless otherwise specified or constrained by a policy object, the canonical state of an object is determined using a Last-Write-Wins (LWW) policy.

### Object Ownership

Ownership of an object is determined by the `owner` field in the envelope. This field points to an identity record as specified in the [Name Resolution](#name-resolution-spec-v01) spec.

Ownership may be transferred to another identity via a transfer message.

### Action Specific Rules

#### post
- Object creation is idempotent: it may create a new object or update an existing one.
- Object creation is governed by the policy of the nearest ancestor path object with a policy reference.
- Object updates are governed by the policy of the object itself.
- May only set or update `policy_ref` if the object is owned by the creator of the object.
- Only the current owner may post updates to the object, unless forbidden by the object's policy.

#### rename
- Rename may modify both `id` and `path` (if allowed by policy).
- Only valid if the destination ID does not exist by the same creator at the destination path.
- Rename is governed by the policy of the nearest ancestor collection object of the destination path with a policy reference.

#### transfer
- Transfers are governed by the policy of the object itself.
- (TBD - under consideration) Transfers may move the object to the "inbox" path as specified in the destination owner's identity claim object (see [Name Resolution](#name-resolution-spec-v01)).
- Only the current owner may transfer the object, unless forbidden by the object's policy.

#### delete
- Modeled as transfers to a null owner (`null:`).
- Message must be signed by the current owner of the object.

### Policies

A policy object may be used to constrain the behavior of an object or (in the case of paths) its hierarchical descendants. Policies are themselves objects in the system, and are referenced by the `policy_ref` field in the envelope.

Policies are resolved by following the path hierarchy. Objects and paths inherit policy enforcement from the nearest ancestor path object with a policy reference. Nonexistent intermediate path objects or paths without a policy reference are skipped in the policy resolution chain.

The root path (`/`) itself references the root policy object, which is thus the default policy for all objects in the system, except as otherwise specified.

In the absence of a root object policy, messages are considered invalid and discarded. During development, a more relaxed root policy is recommended to allow for easier testing and development.

For example, to post to `/foo/bar/baz`:

1. Check for a path object with a policy reference at `/foo/bar/baz`
2. If none, check `/foo/bar`, then `/foo`, then `/`
3. Use the first path object with `policy_ref` found
4. If none exists, the message is considered invalid and discarded.

Policy objects themselves are specified in ... (a future spec).

## Future Extensions
- The `update_type` field supports future merge strategies (e.g., diffs, CRDTs).
- Support for content-addressed storage (e.g., IPFS) may be added via `content_storage_ref` in lieu of the payload.

## Example
```
schema: "SBO-v0.4"
id: "hello-world-123"
path: "/random/stuff"
type: "object"
action: "post"
content_type: "application/json"
content_encoding: "utf-8"
content_size: 27
content_hash: "0xabcde12345..."
signing_key: "0xuser1pubkey"
signature: "0xsigneddata"
---
{ "message": "Hello, world!" }
```
