# Migration: state commitment v1 → v2 and the app 506 regenesis

Part of the 2026-11 security audit (`docs/security-audit-2026-11.md`,
decisions in `docs/security-audit-2026-11-decisions.md`). Coordination bean
`sbo-eefz`; decision Q18 (a): every root-changing and genesis-changing fix
ships together, once, under `state-commitment/v2`, and the reference
deployment (mingo, Avail app 506) is regenesised rather than upgraded in
place.

## What changes in the commitment

`specs/SBO State Commitment Specification.md`, changelog entry v2. The
reference implementation of all of it is `crates/sbo-crypto/src/trie.rs`;
sbo-core proofs (SBOQ), the daemon state root, snapshots, sync witnesses and
the zkVM guest hash nothing themselves.

| | v1 | v2 |
|---|---|---|
| Leaf | bare `object_hash` | `sha256(0x00 ‖ object_hash)` (D4) |
| Internal node | `sha256(json)` | `sha256(0x01 ‖ json)` (D4) |
| Node JSON | `{"children":{…}}` | `{"children":{…}}` or `{"children":{…},"object":"sha256:<object_hash>"}` (W3-4) |
| Object at `[x,a]` and object at `[x,a,b]` | one evicts the other, order-dependent | both coexist; node `a` carries `object` beside `children`; deleting `b` collapses `a` back to a leaf |
| `object_hash` | sha256 of a reserialization | sha256 of the bytes as included on chain (D3, Q32/Q35) |
| `state_root` on the wire | bare hex in places | `sha256:<hex>` everywhere (Q34) |
| Proof step | `{segment, siblings}` | plus optional `object` (object at that level's node) and, on the final inclusion step, `children` (the target's own children) |
| Non-existence of a container that holds no object | not expressible | trailing `{"segment":null,"siblings":<its children>}` step |

Consequences:

- **Every** state root, snapshot root, checkpoint, attestation and proof
  computed under v1 differs under v2. There is no in-band negotiation; the
  commitment version is a property of the repository, fixed at genesis.
- A v2 client MUST NOT accept v1 `checkpoint.v1`, `checkpoint-attestation.v1`,
  snapshots or SBOQ proofs, and vice versa. The reference implementation
  drops v1 support: it does not carry a compatibility switch.
- The SBOQ wire form is backward compatible in shape (the new members are
  omitted when absent), but a v1 proof never verifies against a v2 root.
- Conformance vectors `conformance/trie.json` were regenerated (roots
  change; TRIE-05 covers object-and-container). Runner `EXPECTED_FAIL`
  tables no longer carry `TRIE-03/distinct`.

Known residual divergence: the v2 spec text states the empty-state root is
`node_hash({"children":{}})`; the implementation, the daemon genesis path,
the zkVM guest and TRIE-04 all keep the `[0u8; 32]` sentinel for "no state".
Nothing on a live chain ever has an empty state after genesis, so no root
differs in practice; aligning it is a separate root-changing decision and
is not part of this bundle.

## What rides the same regenesis

Everything below is consensus-changing (it alters which writes are valid or
what the genesis batch must look like), so it cannot be adopted by a client
upgrade on a live chain either. Q18 (a) bundles all of it into the one
regenesis.

| Item | Decision | Effect on genesis / policies |
|---|---|---|
| D3 / W6-4 | `object_hash` over the bytes as included; non-canonical wire rejected (`sbo-xypz`, `sbo-zom8`) | none for a canonical genesis; roots change only via D4 |
| D4 / W3-4 | trie domain separation, object-versus-container (`sbo-39qi`) | every root |
| Q2 | `brokers.v1` payload is the spec object form `{"brokers":[…]}`, not a bare array | the genesis brokers object is rewritten |
| Q6 | bare-key owners removed entirely: `Owner`/`Creator`/`New-Owner` must be a `/sys/names` name or an email, and the signer-key fallback is gone; the only exception is `/sys/names/sys` in the anchor batch | any genesis message naming a bare key is rewritten |
| Q8 | self-certifying Mode B: the `dnssec.v1` evidence for the repository domain is a genesis object | the genesis batch gains the dnssec object |
| Q13 | no owner fast-path: the owner is a principal like any other, and the presets / root policy carry an explicit `to: owner` grant for update/transfer/delete | root policy and presets regenerated; every existing community policy must still admit its owner (survey below) |
| Q33 | genesis batch order: mode objects first (`dnssec` → `domain` → `sys` → root policy), everything after the root policy validated normally | the v5/v6 layout (nine community objects before the root policy) is invalid; the batch is reordered |
| Q39 | strict policy parsing: unknown keys reject the policy | every existing policy must be free of stray keys (survey below) |

## What regenesis means for mingo (app 506)

1. **Survey app 506 first** (`sbo-eefz`, unticked): run every policy on the
   live chain through strict parsing (Q39) and the explicit-owner rule
   (Q13); fix the source documents before they are re-submitted. Any policy
   with a stray key or without an owner grant would silently stop
   governing after cutover.
2. **New genesis batch** (mingo-side, v7): Q33 order, the `dnssec.v1`
   object (Q8), `brokers.v1` in object form (Q2), no bare-key owners (Q6),
   `to: owner` in the root policy and presets (Q13).
3. **Fresh anchor**: submit the new genesis to a new app / new anchor and
   point `_sbo` at it. The old chain stays as read-only history; the v1
   daemon can keep serving it but no v2 client will accept its roots.
4. **Re-sync da.sandmill.org** (mingo-side, infra): wipe `/data` state for
   the daemon, start from the new genesis, and verify the first state root
   it publishes with an independent replay (`sbo-cli` over the trie helper).
5. **Checkpointers and attestors** start a new claim history at the new
   genesis; no v1 claim is carried over.
6. Clients and the mingo app drop any cached checkpoint, snapshot or SBOQ
   proof; everything re-derives from the new genesis.

Nothing about user data forces a loss: objects are re-submitted under the
new genesis with the same bytes (so the same `object_hash`) where their
policies still admit them.

## Version markers

- Spec: `specs/SBO State Commitment Specification.md` changelog v2 (the
  v0.x entries describe what is now v1 of the commitment). The document
  still sits under "SBO Protocol v0.5"; the umbrella protocol version is
  not bumped by this bundle.
- Conformance: `conformance/trie.json` carries the v2 roots.
