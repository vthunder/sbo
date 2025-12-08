
# SBO State Commitment Specification (v0.1)

## Status
Draft

## Overview

This document defines the state commitment structure for SBO, enabling lightweight verification and state proofs. The design uses a sparse Merkle trie where each path segment corresponds to a tree level, allowing efficient proofs for:

- Object existence and content at a path
- Non-existence of a path
- Completeness of a subtree (all objects under a path)

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
- An object's content hash (if it's a leaf)

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

The leaf hashes (`sha256:111...`, etc.) are the `Content-Hash` values of the objects at those paths.

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
post /userA/nft-001 with Content-Hash sha256:xyz...

1. Traverse from root, creating nodes as needed
2. Set children["nft-001"] = "sha256:xyz..." in /userA node
3. Rehash /userA node
4. Update root's children["userA"] with new hash
5. Rehash root node
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

1. Read value at /userA/nft-001
2. Delete from /userA/nft-001
3. Post to /userB/nft-001 with same value
4. Rehash all affected nodes
```

**Cost:** All operations are O(depth) where depth = number of path segments.

---

## Inclusion Proof

Proves that a path has a specific value relative to a state root.

### Format

```json
{
  "state_root": "sha256:abc123...",
  "block": 12345,
  "path": "/userA/nft-001",
  "value": "sha256:def456...",
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
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `state_root` | string | Root hash this proof is anchored to |
| `block` | number | Block number (optional, for context) |
| `path` | string | Path being proven |
| `value` | string | Content hash at path, or null for non-existence |
| `proof` | array | Nodes from root to leaf with sibling hashes |

### Verification Algorithm

```
1. Start with value (the leaf)
2. For each proof level (bottom to top):
   a. Reconstruct node: siblings + {segment: current_hash}
   b. Serialize and hash the node
   c. current_hash = result
3. Final hash must equal state_root
```

---

## Non-Existence Proof

Proves that a path does not exist.

### Format

```json
{
  "state_root": "sha256:abc123...",
  "path": "/userA/nft-999",
  "value": null,
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
| `subtree` | object | Complete subtree contents |
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

1. Serialize and hash `subtree` → must equal `subtree_root`
2. Verify `proof` shows `subtree_root` at `path` under `state_root`

---

## Checkpoints

Checkpoints are periodic on-chain commitments to state roots, enabling lite clients to sync without replaying all history.

### Checkpoint Object

```
SBO-Version: 0.5
Action: post
Path: /.checkpoints/
ID: block-12345
Type: object
Content-Type: application/json
Content-Schema: checkpoint.v1
Signing-Key: <checkpoint authority>
Signature: ...

{
  "block": 12345,
  "state_root": "sha256:abc123...",
  "prev_checkpoint": "sbo://.../.checkpoints/block-10000"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `block` | number | Block number this checkpoint covers |
| `state_root` | string | State root at this block |
| `prev_checkpoint` | string | URI of previous checkpoint (optional) |

### Trust Mechanisms

How lite clients trust checkpoints is deployment-specific. Options include:

- **ZK proof**: Trustless verification of state transition
- **Trusted indexer**: Single trusted party signs checkpoints
- **Committee/multisig**: Threshold of trusted parties (e.g., 3-of-5)
- **Optimistic + fraud proofs**: Trust unless challenged within window

The trust mechanism is not specified here and may vary by deployment.

---

## Compatibility

- State roots are computed deterministically from block contents
- All conforming implementations produce identical state roots
- Proofs are self-contained and verifiable without additional context
- The tree structure is independent of the underlying DA layer

---
