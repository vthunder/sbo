---
# sbo-syib
title: 'Fix D26/D27/D34/W4-2: fast-sync trusts only signed checkpoints by pinned keys; verify snapshot policy_versions'
status: completed
type: bug
priority: high
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:54:06Z
parent: sbo-ax7t
---

**High.** `bootstrap.rs:62-66` counts `sys-checkpointer` as a backer with no claim read; `:252-262` adopts the manifest's root (`RootTrust::ServingNode`); `:128-135` loads `policy_versions` unverified while the doc comment claims a hash check (W4-2). `bootstrap.rs:24` names the authority while `trust.rs` pins keys (D34). WS8 P5: a hostile serving node chooses the client's state and its frozen governance. Q12 (a).

No open decision.

- [x] A root counts only with a `checkpoint.v1` signed by a pinned key (from chain or manifest, re-verified); `sys-checkpointer` becomes a pinned key
- [x] Remove `bootstrap_provisional` or gate it behind `--trust-serving-node`
- [x] Reconstruct `policy_versions` from covered objects or verify each against its content hash; fix the comment
- [x] Acceptance (un-ignore): ws4 `d26_authority_does_not_back_a_root_without_a_signed_checkpoint`, `d27_snapshot_policy_versions_are_verified_against_their_hash`; invert WS8 `poc_d26_*`, `poc_d27_*`

## Summary of Changes

- `bootstrap.rs` rewritten around one key-pinned policy (`pub use trust::TrustPolicy`; `SYS_AUTHORITY` and the name-based policy are gone, D34). `evaluate_trust(policy, block, root, &[ObservedClaim])` counts only distinct **pinned signing keys** on verified `checkpoint.v1`/attestation claims; a non-enforcing policy backs nothing. `RootTrust` is now `SignedCheckpoints{backers}` / `Provisional` / `ServingNode`.
- Signed checkpoints travel with the manifest: `CheckpointView.wire` (base64 of the on-chain signed object, optional) — the serving node retains the wire of every verified `checkpoint.v1` it observes (`trust::save_checkpoint_wire`, 1 hook in `sync.rs` next to the existing claim extraction) and `sync_points` carries it; the client re-verifies (`verified_manifest_claims`: parse, `verify_message`, path `/sys/checkpoints/<id>`, schema, pinned key). A bare `(block, state_root)` backs nothing.
- `bootstrap_with_policy` requires an enforcing policy: freshest snapshot backed by `threshold` verified manifest checkpoints → `SignedCheckpoints` (trusted at once); otherwise the snapshot is loaded against its **own computed root** and returned `Provisional` — `main.rs` persists the `PendingAnchor` and the existing walk-forward gate (`trust.rs`) keeps reads refused until pinned on-chain claims confirm it. `bootstrap_provisional` and the default trust-the-node `bootstrap()` are removed; `bootstrap_trust_serving_node` exists only behind the new `sbo-daemon bootstrap --trust-serving-node` flag (explicit opt-in, loud warning). Without pinned keys and without the flag, bootstrap refuses.
- `verify_and_load_payload`: `policy_versions` are **reconstructed from covered objects** — an entry loads only from a snapshot object (covered by the verified root) whose `content_hash` is the key, parsed from that object's payload; the carried policy value is never trusted; unbacked entries are dropped with a warning. Doc comment fixed (W4-2).
- **Behaviour change recorded:** the in-crate P2 test `p2_snapshot_roundtrip_authorizes_pinned_child` asserted an unverified carry of a superseded pinned ancestor; it is renamed `p2_snapshot_roundtrip_drops_uncovered_pinned_version` and now asserts the fast-synced node fails closed (denies the pinned child's governed write). P2 authorization on a fast-synced node for an ancestor that has moved on needs a full replay today; carrying raw pinned payload bytes (hash-verifiable) in the snapshot would restore it — follow-up, not in this bean.
- Tests: ws4 `d26_*`, `d27_*` un-ignored; `d34_*` inverted (shared key-pinned policy, no name authority); WS8 `poc_d26_*`/`poc_d27_*` inverted and un-ignored, plus a positive loopback test that a manifest-carried checkpoint signed by a pinned key yields `SignedCheckpoints{1}` and an unpinned signer yields `Provisional`. `examples/fastsync_backers.rs` updated to pinned keys.
