---
license: CC-BY-4.0
---

> This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

# SBO State Commitment Specification

**Part of SBO Protocol v0.5**

## Status
Draft

## Changelog

- **v2 — `state-commitment/v2` (2026-11, audit; root-changing)**: (1) **Domain separation** (D4): a leaf hashes as `sha256(0x00 ‖ object_hash)` and an internal node as `sha256(0x01 ‖ serialized_json)`, so an object hash can never be read as a subtree hash. (2) **Object-versus-container rule** (W3-4): an object at `(path, id)` and a collection whose segments extend `[path…, id]` coexist; a node carries an optional `object` member beside `children`, and nothing is evicted. (3) `object_hash` is over the **bytes as included on chain**, never a reserialization; consumers never reserialize (Q32, Q35). (4) `state_root` on the wire is `sha256:<hex>` everywhere (Q34). Every state root, snapshot root and proof changes; see [Migration from v1](#migration-from-v1). Earlier entries below describe the v0.x line of this document, which is now **v1** of the commitment.
- **v0.2**: Changed leaf value from `Content-Hash` to `object_hash` (SHA-256 of complete raw SBO bytes). This ensures proofs commit to the full object including headers, not just payload. Added creator as path segment for disambiguation.
- **v0.2.1**: Specified that the creator path segment is the author's *resolved controller* (attributed email for email-rooted authors), not the signing key — so an author's objects do not fragment across browserid key rotation. Still deterministic (inclusion-time-pinned).
- **v0.3**: Expanded the checkpoint model into a bootstrap/fast-sync story: publisher-chosen cadence with a RECOMMENDED (not mandated) max-staleness bound; the *exclude-self* root rule; **snapshots** (a compact, self-verifying object-set at a checkpoint height); **checkpoint attestations** (client-chosen web-of-trust over a checkpoint root); and a **sync-point discovery manifest**. All remain optional performance features — canonical state is still replay.
- **v0.5**: Made object identity **globally unique on `(path, id)`** — dropped `creator` from the trie key (leaf keyed by `[path…, id]`); `creator` is retained as an immutable object attribute (wire `Creator` header, still gating creator-integrity authorization and preserved across transfer) but no longer disambiguates identity. First-valid-write-wins by DA inclusion order resolves the create race; transfer destination-collision is now a global empty-slot check; added the *Slot occupancy and create-race resolution* section (create-side analog of LWW, incl. reorg semantics).
- **v0.4**: Unified the trust mechanisms — the authority signature and checkpoint attestations are the *same* mechanism over signed `(block, state_root)` claims under a client trust policy `{attestors, threshold}`; `T2-sys` is just `{attestors:[sys], threshold:1}` and the authority is no longer privileged in the protocol. Specified that attestations **lag** the checkpoint (an attestor attests a past block from a later height) and the resulting client behaviour: provisional anchor + accrue-while-tailing (the tail-replay *is* the discovery walk), *freshest-already-attested* selection, and a bounded liveness fallback.

## Overview

This document defines the state commitment structure for SBO, enabling lightweight verification and state proofs. The design uses a sparse Merkle trie where each path segment corresponds to a tree level, allowing efficient proofs for:

- Object existence and content at a path
- Non-existence of a path
- Completeness of a subtree (all objects under a path)

State commitment is an **optional performance and light-client feature**, not a source of canonical truth. Canonical state is defined by replaying the ordered chain and applying SBO validity (see [Validity Layers](./SBO%20Specification.md#validity-layers)); the trie and checkpoints let clients verify and sync efficiently without changing what is valid. In particular, **attribution durability does not depend on checkpoints**: a write's attribution evidence is self-authenticating against the pinned DNS root KSK (see the [Authorization Specification](./SBO%20Authorization%20Specification.md)), so it remains verifiable by replay whether or not any checkpoint exists. Likewise, a **self-certifying `domain.v1`** (see the [Identity Specification](./SBO%20Identity%20Specification.md#domain-objects-domainv1)) binds domain authority into **genesis validity**, not into any checkpoint or snapshot: its `dnssec.v1` evidence lives in the genesis block and is checked against the genesis DA-block time by whoever verifies genesis (a full replayer, or the base case of a recursive proof). A snapshot is only ever trusted relative to its root; domain authenticity is not re-derived "from the snapshot" but carried up from genesis by that same verification, so it does not depend on the evidence surviving in mutable state.

---

## Object Hash

The **object hash** is the SHA-256 hash of the complete raw SBO object bytes (headers + payload in wire format):

```
object_hash = sha256(raw_sbo_bytes)
```

Where `raw_sbo_bytes` is the message **exactly as included on chain** — the bytes of that message within its DA submission (after any transport decoding such as gzip), from the first byte of `SBO-Version` through the last payload byte:
```
HEADER-NAME: HEADER-VALUE\n
HEADER-NAME: HEADER-VALUE\n
\n
[payload bytes]
```

**Never a reserialization.** A consumer computes `object_hash` over the bytes it received and parsed, not over a header block rebuilt from a parsed structure. The [Wire Format](./SBO%20Wire%20Format%20Specification.md#consumers-never-reserialize) rule is *bytes in, bytes out*: the signature covers the received header block, an unknown header is valid only if the signer covered it, and a consumer that does not model a header keeps its bytes. Because a message that is not canonical is invalid, the included bytes of every accepted message equal the canonical serialization its signer produced, and two consumers that model different header subsets compute the same `object_hash` by construction. The same rule defines `genesisHash` in the [Genesis Specification](./SBO%20Genesis%20Specification.md#genesishash-bytes).

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
  },
  "object": "sha256:..."
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `children` | object | Map of segment name to the **node hash** of the child (present, possibly empty, on every internal node) |
| `object` | string | The **object hash** of the object whose segments end exactly at this node (present only when such an object exists **and** the node also has children) |

A child entry's value is always a node hash. Two kinds of node exist:

- A **leaf**: a segment at which an object sits and nothing continues deeper. It has no JSON form; its node hash is the domain-separated object hash (below).
- An **internal node**: a segment at which the path continues deeper. If an object *also* sits exactly here, the node carries it in `object`.

### Domain Separation

Leaf and internal preimages are distinguished by a one-byte prefix, so that no object hash can be presented as a subtree hash or vice versa:

```
leaf_hash(object_hash)   = sha256(0x00 ‖ object_hash_bytes)          # 33-byte preimage
node_hash(node)          = sha256(0x01 ‖ serialize(node))            # 0x01 ‖ canonical JSON
```

`object_hash_bytes` is the 32 raw bytes of the object hash. A verifier MUST compute both forms exactly; an inclusion proof whose final step treats a 32-byte value as a bare leaf (v1 behaviour) does not verify against a v2 root.

### Object Versus Container

Under `segments = path ++ [id]`, an object `a` at `/x/` (segments `["x","a"]`) and an object `b` at `/x/a/` (segments `["x","a","b"]`) are both legal writes, and `a` is both an object and the container of `b`. The rule is: **both coexist; neither evicts the other.** The node at `["x","a"]` is an internal node with `children = {"b": …}` and `object = leaf-less object hash of a`. Its hash is `node_hash({"children":{"b":…},"object":"sha256:<object_hash(a)>"})`, with the `object` value being the object hash itself (not `leaf_hash`; the `0x01` prefix of the node already separates the domain). Deleting `a` removes `object`; deleting `b` leaves the node with empty `children`, at which point the node **collapses to a leaf** for `a` (hash `leaf_hash(object_hash(a))`). An implementation MUST produce the same root regardless of the order in which `a` and `b` were written.

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

The leaf hashes (`sha256:111...`, etc.) are the **leaf hashes** `sha256(0x00 ‖ object_hash)` of the objects at those paths, where `object_hash` is the SHA-256 of the complete bytes as included. (The example writes `sha256:…` for every value; the prefix names the algorithm, not the domain.)

### Object Identity in the Trie

In SBO, objects are **globally uniquely identified by `(path, id)`**: at most one object may occupy a given `(path, id)` across all creators (see the [SBO Specification](./SBO%20Specification.md#object-identity)). The trie is keyed on the path and id alone.

**Full path segments:** `[path_segments..., id]`

`creator` is **not** a trie segment. It is retained as an immutable object attribute (the wire `Creator` header, resolved to the author's controller — see below), used for creator-integrity authorization and provenance, but it does not disambiguate identity.

**The stored creator attribute is the author's resolved controller, not the signing key.** It is derived deterministically from the message and chain state at inclusion time: the explicit `Creator` header if present, else — when the signer carries a valid attribution — the **attributed email** (the address the signer is proven to speak for; see the [Authorization Specification](./SBO%20Authorization%20Specification.md#verification-algorithm)), else the signer's claimed name, else a stable encoding of the signing key. Using the attributed email means an email-rooted author's objects share one creator attribute **across browserid key rotation**, rather than fragmenting under each ephemeral cert key — and because attribution is pinned to the inclusion-time clock, the attribute is a deterministic function of message + on-chain state, so a from-genesis replayer reconstructs the identical object (and trie).

**Transfer is creator-invariant.** A `transfer` re-homes the existing `(path, id)` leaf to `(new_path, new_id)` — deleting the source leaf and inserting the destination leaf with the **same object hash** and the **same immutable `creator` attribute**. The destination-collision rule is now **global**: the transfer is valid only if the destination `(new_path, new_id)` slot is occupied by **no valid object** (regardless of creator).

**Example:**

An object at `/sys/names/` with ID `alice` has trie segments:
```
["sys", "names", "alice"]
```
Its creator (`user123`) is recorded on the object, not in the key; a second creator cannot file a second `alice` here.

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
    "alice": "sha256:111...",   // object_hash; creator is a leaf attribute
    "bob":   "sha256:222..."
  }
}
```

This design:
1. Enforces one canonical object per `(path, id)` (first-valid-write-wins by inclusion order)
2. Turns every existence/first-object lookup into a point lookup (no per-creator scan)
3. Maintains the trie's hierarchical structure
4. Keeps proofs one segment shorter (`[path…, id]`), O(depth)

(Per-creator enumeration is no longer a trie affordance; where per-author collections are wanted, the author is a **path** segment — e.g. `/<issuer>/attestations/…` — so a creator's objects remain a subtree by construction.)

---

## Node Serialization

Nodes are serialized deterministically for hashing:

1. JSON object with key `"children"`, followed by `"object"` only when an object sits at this node (keys in that order: `children`, `object`)
2. Children keys sorted by byte value (ASCII; segments are ASCII-only, see Core §Identifier Syntax)
3. No whitespace
4. UTF-8 encoded
5. Hash values written as `sha256:<64 lowercase hex>`

**Node hash:** `sha256(0x01 ‖ serialized_json)` (see [Domain Separation](#domain-separation))

**Examples:**

```json
{"children":{"alice":"sha256:111...","bob":"sha256:222..."}}
{"children":{"b":"sha256:333..."},"object":"sha256:aaa..."}
```

---

## State Root

The **state root** is the node hash of the root node. It commits to the entire SBO state at a given block. An empty state has the root `node_hash({"children":{}})`.

### Wire Form

Wherever a state root (or any node, leaf, subtree or object hash) appears on the wire — `checkpoint.v1`, `checkpoint-attestation.v1`, `snapshot` metadata, proofs, manifests, HTTP responses — it is written as `sha256:<64 lowercase hex characters>`, the same prefixed form as `Content-Hash`, `Prev` and `genesisHash`. A bare hex string is not a valid state root: a consumer MUST NOT treat a `checkpoint.v1` whose `state_root` is unprefixed as a claim. (Implementations migrating from a bare-hex emitter MAY accept both forms for a bounded migration period but MUST emit the prefixed form.)

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

1. Compute object_hash = sha256(bytes as included)
2. Traverse from root, creating nodes as needed
3. If no node exists at /userA/nft-001: set children["nft-001"] = leaf_hash(object_hash) in /userA node
   If an internal node exists there (nft-001 is also a container): set its "object" = object_hash and rehash it
4. Rehash /userA node
5. Update root's children["userA"] with new hash
6. Rehash root node
```

### Delete

```
delete /userA/nft-001

1. Traverse to /userA node
2. If nft-001 is a leaf: remove children["nft-001"]
   If nft-001 is an internal node with "object": remove "object" (its children stay)
3. If /userA node now has no children and no object, remove it from root;
   if it has no children but an object, it collapses to a leaf
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

### Slot occupancy and create-race resolution

**Slot occupancy.** Each `(path, id)` slot holds at most one object. Its occupant is determined by DA inclusion order over all *valid* creates targeting the slot while it is empty: within a block the lower message index wins; across blocks the earlier block wins. A create's validity is evaluated against confirmed+pending state **as of its own inclusion point** — a create into a slot occupied by a valid object at that point is invalid unless the signer is authorized to update the occupant. A **delete** or a **transfer away** vacates the slot; a later create by any authorized creator may then occupy it. In the optimistic-tip overlay a **pending** create MUST be superseded (dropped, not merged) once a create/transfer earlier in inclusion order is confirmed for the same slot. On a **reorg** that evicts the create establishing the occupant, the slot re-opens as of the reorg point and is re-resolved by this same rule; a previously-preempted create MAY become the occupant and a previously-valid one MAY become invalid. Occupancy is a function of the canonical chain at the read height (as content value is under LWW); consumers needing cross-reorg stability pin by `object_hash` / `as_of`.

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
   a. Compute sha256(object_bytes)        # the bytes as included; never reserialize
   b. Verify it equals object_hash

2. Start at the target node:
   a. If the final step has no "children" (the object is a leaf):
        current_hash = leaf_hash(object_hash) = sha256(0x00 ‖ object_hash)
   b. If the final step carries "children" (the object is also a container):
        current_hash = node_hash({"children": children, "object": object_hash})
3. For each remaining proof level (bottom to top):
   a. Reconstruct node: siblings + {segment: current_hash} (+ "object" if the step carries one)
   b. current_hash = node_hash(node) = sha256(0x01 ‖ serialize(node))
4. Final hash must equal state_root
```

A proof step MAY carry an `object` member (the object hash of an object sitting at that intermediate node) and, for the final step, a `children` member; a verifier MUST include them in the reconstruction exactly as given. All proof parsing is over untrusted input: a verifier MUST bounds-check every length and index (a proof with fewer steps than the path has segments, or a `segment: null` first step with an empty path, is rejected, never indexed; see the [Indexer and Client Specification](./SBO%20Indexer%20and%20Client%20Specification.md#hostile-indexer-threats)).

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

1. Rebuild the subtree bottom-up with the v2 node rules (leaves as `leaf_hash`, internal nodes as `node_hash`, an `object` member where a node is also an object) -> the root of the rebuilt subtree must equal `subtree_root`
2. Verify `proof` shows `subtree_root` at `path` under `state_root`

A subtree proof is the only **completeness** proof in this specification: it is what a client needs to know that a listing is complete. Note that the reference indexer's `/v1/list` does not yet serve one (see the [Indexer and Client Specification](./SBO%20Indexer%20and%20Client%20Specification.md#completeness-proofs-are-not-served)).

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
| `state_root` | string | State root at this block, `sha256:<hex>` (see [Wire Form](#wire-form)); a bare hex value is not a claim |
| `prev_checkpoint` | string | URI of previous checkpoint (optional) |

### Trust Mechanisms

A checkpoint root is a claim; *why* a client believes it is deployment- and client-specific. These are points on one spectrum — the client bootstraps with the same [snapshot](#snapshots) either way and only the verification differs.

#### The unified model: signed `(block, state_root)` claims

The authority signature and checkpoint attestations are **not two separate mechanisms** — they are the *same* mechanism at different settings. A checkpoint's trust reduces to a single local decision over **signed `(block, state_root)` claims**:

> A client holds a **trust policy** `{ attestors: [identity…], threshold: N }` and accepts a root `R` at height `h` once **≥ N distinct trusted attestors** have each signed the claim `(h, R)` on chain.

Both object types carry exactly that claim, signed by their author:

- a `checkpoint.v1` written by the checkpoint authority *is* the authority's signed `(h, R)` claim;
- a `checkpoint-attestation.v1` written by any party *is* that party's signed `(h, R)` claim.

They differ only in **who signed** and **where the client's policy places that signer** — not in how they are verified. So the tiers are just policy settings:

Write `AUTH` for the deployment's **checkpoint-authority identity** — the id that signs `checkpoint.v1` (in the default mingo genesis this is `sys-checkpointer`, the `sys`-delegated checkpoint key, **not** `sys` itself).

| Tier | Trust policy | Meaning |
|------|-------------|---------|
| **T2-sys** | `{attestors: [AUTH], threshold: 1}` | the current default: trust the checkpoint authority alone |
| **T2-attest** | `{attestors: [AUTH, alice, bob…], threshold: N}` | client-chosen web of trust; no fixed validator set |
| **T1-zk** | a proof discharges the claim outright | trustless; the proof *is* the evidence, no signer trusted. **Design slot only (2026-11):** the experimental `sbo-zkvm` guest carries no validity claim yet, so no client may place itself in this tier today (see `docs/plans/ZK-Validity-Proofs-Design.md`). |

The checkpoint authority is therefore **not privileged in the protocol** — it is merely the attestor every default policy happens to include. A deployment or client MAY drop `AUTH` from its set entirely and trust only independent attestors, or require `AUTH` **and** peers (`threshold ≥ 2` with `AUTH` in the set). Implementations SHOULD model the authority checkpoint and peer attestations through **one verifier** over signed `(h, R)` claims rather than two code paths.

- **Optimistic strengthening.** Because trust is just "count agreeing claims," a client MAY accept a root provisionally at a low bar (e.g. `sys` alone) to start serving immediately, then *accrue* further trusted claims as it tails and upgrade its confidence — see [Checkpoint Attestations §Timing](#timing-attestations-lag-the-checkpoint).

The mechanism is not mandated here and may be mixed. Maximum assurance is independent replay from genesis; checkpoints only let a client choose a faster point on the trust/speed curve.

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
   [path, id] segments (see State Tree Structure) with leaf = object_hash.
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

Because it lives in the attestor's namespace and is signed by them, it is a first-class SBO object: deterministically validated, and its authorship (the attestor's resolved controller) is exactly the identity a client decides whether to trust. The attestation re-states `state_root`, so it is an **independent claim** ("I computed root R at h"), not a co-signature of the authority's object — it stands even if the authority checkpoint is wrong or absent.

### Producing an attestation

An attestor is a node that has **independently computed** the root at `h` — ideally a full replayer from genesis (`method: "replay"`), so its claim is not merely an echo of the same snapshot it is attesting. On observing an on-chain checkpoint at height `h`, it compares its own recorded root at `h` to the checkpoint's `state_root`; **on match** it posts the attestation, **on mismatch** it withholds it and raises a divergence alarm (it never signs a root it did not reproduce). An attestor with a correlated source (e.g. one that only bootstrapped from the very snapshot under attestation) provides weaker assurance; the value of an attestation is exactly the independence of the computation behind it, which is why trust is client-chosen.

### Timing: attestations lag the checkpoint

Attestations are **not concurrent** with the checkpoint — an attestor can only attest a block it has already reached and verified, so a `checkpoint-attestation.v1` for `block-h` is itself written at some later height `h' > h`. A client's trust in a root therefore accrues over the blocks it tails, not instantaneously:

```
t0        checkpoint/snapshot height h
t0+1      sys publishes checkpoint.v1{h, R}   (satisfies {attestors:[sys], threshold:1})
t2        client bootstraps: downloads snapshot@h, rebuilds trie -> R,
          adopts h PROVISIONALLY, begins tail-replay from h+1
t3        an independent attestor, having reached h, posts its attestation for block-h
t4        client, tail-replaying past t3, SEES that attestation; once >= threshold
          trusted attestors agree on R, the h anchor is CONFIRMED
```

Because tail-replay already walks the client forward from `h`, **the walk is the discovery** — the client encounters attestation objects for `block-h` as they land in later blocks, with no separate scan (a [sync-point manifest](#sync-point-discovery) is only an optional index, and cannot list attestations posted after it was fetched). Note forward replay from `h` only proves `h→tip` transitions *given* `h`; the anchor at `h` (a downloaded snapshot, not replayed from genesis) is what the attestations establish.

### Client Use

- **Client-chosen trust.** A client maintains its own trust policy `{attestors, threshold}` (§[The unified model](#the-unified-model-signed-block-state_root-claims)) and accepts a root once that many trusted attestors agree on `(h, R)`. It does **not** consult a fixed committee.
- **Selection: freshest already-attested.** A client that does not need bleeding-edge state SHOULD anchor at the **most recent checkpoint whose threshold is already satisfied** on chain, then tail forward — establishing trust immediately with no waiting. Only a client that needs state newer than any sufficiently-attested checkpoint falls back to *walk-and-wait*: anchor provisionally at the newest checkpoint and tail forward accruing attestations until the threshold is met.
- **Liveness fallback (bounded wait).** A web-of-trust client can never trust *newer* than its attestors have reached; if they lag or go silent it MUST NOT wait forever. It SHOULD bound the walk-and-wait (max blocks / max time) and, on exhaustion, either fall back to an older sufficiently-attested checkpoint, degrade to a weaker policy (e.g. `sys`-only), or report *trust not established* — a deployment/client choice.
- **Direct discovery.** Knowing its trusted attestors, a client can also read `/u/<attestor>/attestations/checkpoints/block-<h>` directly for each — no indexer required.

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

## Migration from v1

v2 changes every state root, snapshot root and proof, so it cannot be introduced on a live chain by a client upgrade alone: a v1 checkpoint does not verify under v2 and a v2 root does not verify under v1. The protocol has no in-band version negotiation for the commitment; the commitment version is a property of the repository, fixed at genesis.

- A repository is v2 from its genesis onward or not at all. Existing v1 repositories either stay v1 (the reference implementation drops v1 support, so they become read-only history) or are **regenesised**: a new genesis submission on a fresh anchor, with state rebuilt by replay under v2 rules.
- The reference deployment (mingo, app 506) is regenesised with v2, together with the other genesis-affecting changes of the 2026-11 audit (Genesis spec: self-certifying Mode B, mode objects first; Identity: no bare-key owners; Authorization/Policy: explicit `to: owner` grant, strict policy parsing; `brokers.v1` object form).
- `checkpoint.v1`, `checkpoint-attestation.v1`, snapshots and proofs produced under v1 MUST NOT be accepted by a v2 client, and vice versa. A checkpointer or attestor upgrading to v2 starts a new claim history at the new genesis.
- The hashing rule for `object_hash` (bytes as included) does not by itself change any root for a chain whose messages were all canonical; the domain-separation and object-versus-container changes do.

---
