---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO State Commitment Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v0.2**: Changed leaf value from `Content-Hash` to `object_hash` (SHA-256 of complete raw SBO bytes). This ensures proofs commit to the full object including headers, not just payload. Added creator as path segment for disambiguation.
- **v0.2.1**: Specified that the creator path segment is the author's *resolved controller* (attributed email for email-rooted authors), not the signing key — so an author's objects do not fragment across browserid key rotation. Still deterministic (inclusion-time-pinned).
- **v0.3**: Expanded the checkpoint model into a bootstrap/fast-sync story: publisher-chosen cadence with a RECOMMENDED (not mandated) max-staleness bound; the *exclude-self* root rule; **snapshots** (a compact, self-verifying object-set at a checkpoint height); **checkpoint attestations** (client-chosen web-of-trust over a checkpoint root); and a **sync-point discovery manifest**. All remain optional performance features — canonical state is still replay.

## Overview

This document defines the state commitment structure for SBO, enabling lightweight verification and state proofs. The design uses a sparse Merkle trie where each path segment corresponds to a tree level, allowing efficient proofs for:

- Object existence and content at a path
- Non-existence of a path
- Completeness of a subtree (all objects under a path)

State commitment is an **optional performance and light-client feature**, not a source of canonical truth. Canonical state is defined by replaying the ordered chain and applying SBO validity (see [Validity Layers](./SBO%20Specification.md#validity-layers)); the trie and checkpoints let clients verify and sync efficiently without changing what is valid. In particular, **attribution durability does not depend on checkpoints**: a write's attribution evidence is self-authenticating against the pinned DNS root KSK (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)), so it remains verifiable by replay whether or not any checkpoint exists.

---

## Object Hash

The **object hash** is the SHA-256 hash of the complete raw SBO object bytes (headers + payload in wire format):

```
object_hash = sha256(raw_sbo_bytes)
```

Where `raw_sbo_bytes` is the complete wire-format serialization:
```
HEADER-NAME: HEADER-VALUE\n
HEADER-NAME: HEADER-VALUE\n
\n
[payload bytes]
```

**Why object_hash instead of Content-Hash?**

The `Content-Hash` header only covers the payload bytes. The `object_hash` covers the complete object including:
- All headers (Path, ID, Creator, Action, signatures, etc.)
- The payload

This is important because:
1. Proofs can embed the complete object for verification
2. Verifiers can hash the embedded bytes and confirm they match the leaf
3. The commitment covers the full object identity, not just content

---

## State Tree Structure

The state tree is a **sparse path-segment trie**. Each node represents a path prefix, and its children represent the next segment in paths under it.

### Node Format

```json
{
  "children": {
    "segment1": "sha256:...",
    "segment2": "sha256:...",
    ...
  }
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `children` | object | Map of segment name to hash |

The hash value can reference:
- Another node (if the path continues deeper)
- An object's **object hash** (if it's a leaf)

### Example Tree

For objects at `/names/alice`, `/names/bob`, `/userA/nft-001`, `/userA/nft-002`:

```
Root node:
{
  "children": {
    "names": "sha256:aaa...",
    "userA": "sha256:bbb..."
  }
}

/names node (hash: sha256:aaa...):
{
  "children": {
    "alice": "sha256:111...",
    "bob": "sha256:222..."
  }
}

/userA node (hash: sha256:bbb...):
{
  "children": {
    "nft-001": "sha256:333...",
    "nft-002": "sha256:444..."
  }
}
```

The leaf hashes (`sha256:111...`, etc.) are the **object hashes** (SHA-256 of complete raw bytes) of the objects at those paths.

### Creator as Path Segment

In SBO, objects are uniquely identified by `(path, creator, id)` rather than just `(path, id)`. Multiple creators can post objects with the same ID at the same path. To handle this in the trie, the **creator** is included as a path segment between the path and the ID.

**Full path segments:** `[path_segments..., creator, id]`

**The creator segment is the author's resolved controller, not the signing key.** It is derived deterministically from the message and chain state at inclusion time: the explicit `Creator` header if present, else — when the signer carries a valid attribution — the **attributed email** (the address the signer is proven to speak for; see the [Authorization Specification](./SBO%20Authorization%20Specification.md#verification-algorithm)), else the signer's claimed name, else a stable encoding of the signing key. Using the attributed email means an email-rooted author's objects share one creator segment **across browserid key rotation**, rather than fragmenting under each ephemeral cert key — and because attribution is pinned to the inclusion-time clock, the segment is a deterministic function of message + on-chain state, so a from-genesis replayer reconstructs the identical trie.

**Transfer is creator-invariant.** A `transfer` re-homes the existing `(path, creator, id)` leaf to `(new_path, creator, new_id)` — deleting the source leaf and inserting the destination leaf with the **same object hash**. The creator segment does not change (only `path`, `id`, and/or the object's `owner` may). The destination-collision rule ("does not exist by the same creator at the destination") is evaluated against this preserved creator.

**Example:**

An object at `/sys/names/` with ID `alice` created by `user123` has trie segments:
```
["sys", "names", "user123", "alice"]
```

The tree structure becomes:
```
Root:
{
  "children": {
    "sys": "sha256:..."
  }
}

/sys node:
{
  "children": {
    "names": "sha256:..."
  }
}

/sys/names node:
{
  "children": {
    "user123": "sha256:...",
    "user456": "sha256:..."   // Different creator
  }
}

/sys/names/user123 node:
{
  "children": {
    "alice": "sha256:111...",   // object_hash
    "bob": "sha256:222..."      // another object by same creator
  }
}
```

This design:
1. Allows multiple creators at the same path to have objects with the same ID
2. Enables proofs for all objects by a specific creator under a path
3. Maintains the trie's hierarchical structure
4. Makes proofs slightly larger due to the extra segment, but keeps them efficient (O(depth))

---

## Node Serialization

Nodes are serialized deterministically for hashing:

1. JSON object with single key `"children"`
2. Children keys sorted lexicographically
3. No whitespace
4. UTF-8 encoded

**Node hash:** `sha256(serialized_json)`

**Example:**

```json
{"children":{"alice":"sha256:111...","bob":"sha256:222..."}}
```

---

## State Root

The **state root** is the hash of the root node. It commits to the entire SBO state at a given block.

### Computation

State roots are computed out-of-band by clients and indexers:

```
For block N:
  1. Start with state tree from block N-1 (or empty tree for genesis)
  2. Apply each action in block N in order
  3. Recompute affected node hashes up to root
  4. State root = hash of root node
```

The state root is deterministic: given the same block sequence, all implementations produce the same root.

---

## Tree Updates

### Post (Create or Update)

```
post /userA/nft-001

1. Compute object_hash = sha256(raw_sbo_bytes)
2. Traverse from root, creating nodes as needed
3. Set children["nft-001"] = object_hash in /userA node
4. Rehash /userA node
5. Update root's children["userA"] with new hash
6. Rehash root node
```

### Delete

```
delete /userA/nft-001

1. Traverse to /userA node
2. Remove children["nft-001"]
3. If /userA node is now empty, remove from root
4. Rehash affected nodes up to root
```

### Transfer

```
transfer /userA/nft-001 to /userB/nft-001

1. Read object_hash at /userA/nft-001
2. Delete from /userA/nft-001
3. Post to /userB/nft-001 with same object_hash
4. Rehash all affected nodes
```

**Note:** Transfer preserves the object_hash because the raw bytes (including original path/id in headers) remain the same. The tree location changes but the committed content does not.

**Cost:** All operations are O(depth) where depth = number of path segments.

---

## Inclusion Proof

Proves that a path has a specific object relative to a state root.

### Format

```json
{
  "state_root": "sha256:abc123...",
  "block": 12345,
  "path": "/userA/nft-001",
  "object_hash": "sha256:def456...",
  "proof": [
    {
      "segment": "userA",
      "siblings": {
        "bridge": "sha256:...",
        "names": "sha256:..."
      }
    },
    {
      "segment": "nft-001",
      "siblings": {
        "nft-002": "sha256:...",
        "nft-003": "sha256:..."
      }
    }
  ],
  "object": "<base64 or hex encoded raw SBO bytes>"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `state_root` | string | Root hash this proof is anchored to |
| `block` | number | Block number (optional, for context) |
| `path` | string | Path being proven |
| `object_hash` | string | Object hash at path, or null for non-existence |
| `proof` | array | Nodes from root to leaf with sibling hashes |
| `object` | string | Raw SBO object bytes (optional, for verification) |

### Verification Algorithm

```
1. If object is provided:
   a. Compute sha256(object_bytes)
   b. Verify it equals object_hash

2. Start with object_hash (the leaf)
3. For each proof level (bottom to top):
   a. Reconstruct node: siblings + {segment: current_hash}
   b. Serialize and hash the node
   c. current_hash = result
4. Final hash must equal state_root
```

---

## Non-Existence Proof

Proves that a path does not exist.

### Format

```json
{
  "state_root": "sha256:abc123...",
  "path": "/userA/nft-999",
  "object_hash": null,
  "proof": [
    {
      "segment": "userA",
      "siblings": {
        "bridge": "sha256:...",
        "names": "sha256:..."
      }
    },
    {
      "segment": null,
      "siblings": {
        "nft-001": "sha256:...",
        "nft-002": "sha256:..."
      }
    }
  ]
}
```

The final proof level has `segment: null`, indicating the parent node exists but lacks the target segment. The siblings show what does exist at that level.

---

## Subtree Proof

Proves the complete contents of a path prefix.

### Format

```json
{
  "state_root": "sha256:abc123...",
  "block": 12345,
  "path": "/userA",
  "subtree_root": "sha256:xyz789...",
  "subtree": {
    "nft-001": "sha256:aaa...",
    "nft-002": "sha256:bbb...",
    "nft-003": "sha256:ccc..."
  },
  "proof": [
    {
      "segment": "userA",
      "siblings": {
        "bridge": "sha256:...",
        "names": "sha256:..."
      }
    }
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Subtree path being proven |
| `subtree_root` | string | Hash of the subtree |
| `subtree` | object | Complete subtree contents (object hashes) |
| `proof` | array | Path from state root to subtree root |

### Nested Subtrees

If the subtree contains collections, it can be nested:

```json
{
  "subtree": {
    "nfts": {
      "punk-001": "sha256:...",
      "punk-002": "sha256:..."
    },
    "profile": "sha256:..."
  }
}
```

### Verification

1. Serialize and hash `subtree` -> must equal `subtree_root`
2. Verify `proof` shows `subtree_root` at `path` under `state_root`

---

## Checkpoints

Checkpoints are on-chain commitments to state roots, enabling clients to bootstrap to a recent height without replaying all history. They are **optional**: they accelerate sync but are not required for correctness, and attribution does not rely on them (see [Overview](#overview)). A checkpoint on its own asserts nothing a client must believe — it is a *claim* about a root that the client verifies by whatever trust mechanism it accepts (signature, attestations, or proof; see [Trust Mechanisms](#trust-mechanisms)).

### Publishing cadence

Cadence is **publisher-chosen and configurable**; this specification does **not** mandate any specific interval. What it RECOMMENDS is an **upper bound on staleness** so that a bootstrapping client never faces an unbounded tail replay after the latest checkpoint. A publisher SHOULD checkpoint frequently enough that the gap to the tip stays within its target; a common, effective policy is a **dual trigger** — publish when *either* some number of confirmed writes *or* some number of DA blocks have elapsed since the last checkpoint, whichever comes first. Publishers MAY use any policy; clients MUST NOT assume a fixed cadence and MUST discover the actual available checkpoints (see [Sync-Point Discovery](#sync-point-discovery)).

The write counter that drives a write-based trigger SHOULD exclude checkpoint objects themselves, so publishing a checkpoint does not advance its own trigger.

### The exclude-self rule

A checkpoint commits to `state_root` **as of `block`** — the root over all objects confirmed at or before `block`. Because the checkpoint object is itself written to the chain at a *later* block, **the root a checkpoint commits to never includes that checkpoint object** (nor any [snapshot](#snapshots) taken at the same height). This is by construction: a publisher computes the root at height `h`, builds the snapshot at `h`, and only *then* submits the checkpoint (which lands at `h′ > h`). A bootstrapping client reconstructs the trie from the height-`h` snapshot and obtains exactly the committed root; the checkpoint object and any writes after `h` are applied normally during tail replay from `h+1`.

### Checkpoint authority

A checkpoint is an ordinary signed on-chain write to `/sys/checkpoints/`, so genesis policy MUST grant write access to `/sys/checkpoints/**` to the deployment's **checkpoint authority** — the genesis `sys` identity, or a key `sys` delegates for least privilege (rotatable without a genesis change). The authority signature is the T2 trust anchor (see [Trust Mechanisms](#trust-mechanisms)); it is not a source of canonical truth.

### Checkpoint Object

```
SBO-Version: 0.5
Action: post
Path: /sys/checkpoints/
ID: block-12345
Type: object
Content-Type: application/json
Content-Schema: checkpoint.v1
Public-Key: <checkpoint authority>
Signature: ...

{
  "block": 12345,
  "state_root": "sha256:abc123...",
  "prev_checkpoint": "/sys/checkpoints/block-10000"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `block` | number | Block number this checkpoint covers |
| `state_root` | string | State root at this block |
| `prev_checkpoint` | string | URI of previous checkpoint (optional) |

### Trust Mechanisms

A checkpoint root is a claim; *why* a client believes it is deployment- and client-specific. These are points on one spectrum — the client bootstraps with the same [snapshot](#snapshots) either way and only the verification differs:

- **Authority signature (T2-sys)**: trust the checkpoint authority's signature on the root. Simplest; the client trusts the publisher not to sign a wrong root.
- **Checkpoint attestations (T2-attest)**: a client-chosen **web of trust** — accept the root once enough parties *the client independently trusts* have attested it on chain (see [Checkpoint Attestations](#checkpoint-attestations)). No fixed validator set; the client decides whose word counts.
- **ZK proof (T1)**: verify a proof that the root is the correct result of validated history — **trustless** (see the [prover integration]; the proof is published aligned to the checkpoint height).
- **Optimistic**: accept provisionally and replay-verify from the snapshot forward (or fall back to full replay) in the background; the strongest assurance is always independent replay.

The mechanism is not mandated here and may be mixed (e.g. accept on the authority signature *and* opportunistically strengthen with attestations or a proof). Maximum assurance is independent replay from genesis; checkpoints only let a client choose a faster point on the trust/speed curve.

---

## Snapshots

A **snapshot** is a compact, self-verifying serialization of the full confirmed object set **as of a checkpoint height**, so a client can download state and skip replaying from genesis. Snapshots are optional and, like checkpoints, are a performance feature only.

### Alignment and scope

- **Snapshot height == checkpoint height.** Every snapshot corresponds to a checkpoint at the same block `h`, so the client always has a matching on-chain `state_root` to verify against. Per the [exclude-self rule](#the-exclude-self-rule), the snapshot at `h` does **not** contain the checkpoint object that commits to it.
- **Confirmed, tip-only.** A snapshot captures *confirmed* state (never the optimistic tip) at the latest checkpoint height. This specification defines **no historical (`as_of`) snapshots**: the canonical state model retains only the latest value per object, so snapshots exist only at recent checkpoint heights, not for arbitrary past blocks.

### Contents

A snapshot carries, at minimum:

| Field | Description |
|-------|-------------|
| `block` | The checkpoint height `h` this snapshot is taken at |
| `state_root` | The claimed state root at `h` (MUST equal the height-`h` checkpoint's `state_root`) |
| objects | The complete set of confirmed objects at `h`, as **raw SBO wire bytes** (headers + payload) |

The object bytes are what the trie commits to (`object_hash = sha256(raw_sbo_bytes)`), so the objects alone are sufficient to reconstruct the trie and recompute the root.

### Encoding

The wire encoding is **implementation-defined and non-canonical** — only the resulting state root is canonical, so publishers MAY choose any compact, streamable, **compressed** representation (e.g. a small header followed by length-prefixed raw object records, compressed). A snapshot's integrity does not rest on its byte layout; it rests on the root check below.

### Verification (self-verifying)

A snapshot is **not trusted**; it is verified against a checkpoint root the client accepts:

```
1. Decode the objects from the snapshot.
2. Reconstruct the state trie by inserting each object at its
   [path, creator, id] segments (see State Tree Structure) with leaf = object_hash.
3. Compute the state root.
4. It MUST equal the state_root of the checkpoint at `block`
   (obtained on chain and trusted per Trust Mechanisms). Otherwise REJECT the snapshot.
```

On success the client adopts the snapshot as its confirmed state at `h`, sets its head to `h`, and **tail-replays from `h+1`** to the tip. The snapshot's trust is exactly the checkpoint's trust — a forged snapshot fails the root check; a snapshot that passes is as trustworthy as the root the client accepted.

---

## Checkpoint Attestations

A **checkpoint attestation** is an on-chain statement by any party that a checkpoint's `(block, state_root)` is correct — typically because the attestor independently replayed to `block` and recomputed the root. Attestations let a client trust a checkpoint via a **web of trust of its own choosing** rather than the publisher alone, with **no protocol-defined validator set**.

### Attestation Object

An attestor posts, in **their own namespace** (per the author-namespace storage of the [Attestation Specification](./SBO%20Attestation%20Specification.md)):

```
Path: /u/<attestor>/attestations/checkpoints/
ID: block-<h>
Content-Schema: checkpoint-attestation.v1

{
  "subject": "/sys/checkpoints/block-<h>",
  "block": <h>,
  "state_root": "sha256:...",
  "method": "replay",          // how the attestor verified (e.g. full replay)
  "issued_at": <unix-seconds>
}
```

Because it lives in the attestor's namespace and is signed by them, it is a first-class SBO object: deterministically validated, and its authorship (the attestor's resolved controller) is exactly the identity a client decides whether to trust.

### Client Use

- **Client-chosen trust.** A client maintains its own set of trusted attestors and a threshold (e.g. "≥ 2 of my trusted set agree on `(h, root)`"). It does **not** consult a fixed committee.
- **Direct discovery.** Knowing its trusted attestors, a client reads `/u/<attestor>/attestations/checkpoints/block-<h>` for each — no indexer required. A reverse index (checkpoint → attestations) is an optional indexer product (subject to the usual completeness caveats).
- **Optimistic strengthening.** A client MAY bootstrap from a snapshot immediately on the authority signature and then *accrue* trusted attestations as it tails, upgrading its confidence over time — or fall back to replay-from-snapshot if the trust threshold is never met.

Attestations attest a *root*, not availability or validity of any specific object; a client that wants object-level guarantees still uses [inclusion/subtree proofs](#inclusion-proof).

---

## Sync-Point Discovery

To let a client take the fastest acceptable path to the tip, a node MAY serve a **sync-point manifest** advertising the bootstrap artifacts it can provide. The manifest is a **convenience, never a trust root**: every artifact it lists is verified against on-chain truth (a checkpoint's root, an attestation's signature, a proof) exactly as if discovered by replay.

A manifest SHOULD advertise:

- **genesis** — the repo's `@firstBlock`/genesis hash (so the client confirms which database it is bootstrapping);
- **checkpoints** — available `(block, state_root)` and how to fetch the on-chain checkpoint object;
- **snapshots** — `(block, url, byte size, content hash, compression)` for each snapshot the node serves;
- **attestations** — known checkpoint attestations `(block, attestor, state_root)` the node has observed (advisory; the client re-reads/verifies those from attestors it trusts);
- **proofs** — when available, `(block, receipt kind, url/ref)` for published state-transition proofs.

A client selects a `(checkpoint, snapshot[, proof/attestations])` tuple at the highest block whose trust it can satisfy, then bootstraps per [Snapshots §Verification](#verification-self-verifying). The manifest is reachable via the `node`/`checkpoint` URL in the repo's `_sbo` record (see the [URI Specification](./SBO%20URI%20Specification.md)); its outputs are "verified, never trusted blindly," consistent with that record's resolution semantics.

---

## State Root Recording

Full nodes record state roots during sync for proof verification:

1. **On every block**: Record `last_processed_block`
2. **On state change**: Record `(block_number, state_root)` mapping

This allows verification of proofs for any block up to `last_processed_block`:
- If proof's block equals a recorded block, use that state root
- If proof's block is between recorded blocks, use the most recent state root at or before that block (state didn't change)
- If proof's block > `last_processed_block`, reject as future/unknown

---

## Compatibility

- State roots are computed deterministically from block contents
- All conforming implementations produce identical state roots
- Proofs are self-contained and verifiable without additional context
- The tree structure is independent of the underlying DA layer

---
