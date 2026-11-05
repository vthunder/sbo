---
# sbo-yd72
title: 'Fix Q6/S7/D16/D55: remove bare-key owners (explicit literals and the signer fallback); genesis anchor is the only exception'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T11:26:02Z
parent: sbo-ax7t
---

**Medium.** `resolve.rs:128-129` maps any `ed25519:` literal to `Controller::Key`; `validate.rs:510-518` falls back to the signer key when no owner is named; `resolve_creator` emits `e_<16 hex>` / `unknown` sentinels (D16/D55). Q6 (Dan): an identity is a `/sys/names` name or an email; explicit bare-key `Owner`/`Creator`/`New-Owner` reject AND the signer fallback is dropped; key-rooted name records stay; only the genesis batch at the anchor is exempt. July `sbo-4arq`.

Blocked by: state-commitment v2 bundle (regenesis). No open decision.

- [x] Thread provenance (explicit vs fallback) through `resolve_controller`; reject both forms after genesis
- [x] Delete the `e_<hex>`/`unknown` sentinels
- [x] Identity spec: owner-reference table and `resolve_controller` pseudocode lose the bare-key row
- [x] Acceptance (un-ignore): ws4 `q6_explicit_bare_key_owner_is_rejected`, `q6_signer_fallback_owner_is_rejected_after_genesis`; `d16_unnamed_signer_creator_is_a_truncated_key` inverts

## Summary of Changes

- `crates/sbo-core/src/resolve.rs`: a bare key (`ed25519:`/`bls12-381:` literal) resolves to `Controller::Unresolved` instead of `Controller::Key`; unit test `bare_key_is_not_a_reference` replaces `bare_key_resolves_to_key_controller`. Key-rooted name records still resolve to their key.
- `crates/sbo-daemon/src/validate.rs`: `effective_owner_ref` is now `Result`: `Owner` else `Creator`, no signer-key fallback, a bare-key reference is an error; the one self-certifying form is a `/sys/names/<name>` claim with no `Owner` (owner = the claimed name; at the L2 gate an empty-slot claim skips owner resolution because the schema stage verified the identity JWT against the signing key). `New-Owner` bare keys are rejected in `validate_transfer`. `resolve_creator` is `Result`: `Creator` → attributed email → claimed name (pubkey index) → the claimed name for a name claim → the `Owner` the signer was authorized against → error; the `e_<hex>` / `unknown` sentinels are gone. `message_to_stored_object` returns `None` for a message with no creator/owner and stores the owner reference (never a key) in the legacy `owner` field.
- Genesis exception: the mode objects of the genesis prefix are applied by the sync path (sbo-3q6x) with creator = the sys identity and owner = `sys`, never through this gate.
- Identity spec: the owner-reference table and `resolve_controller` pseudocode already lost the bare-key row on this branch (spec group, Q6 wording); ticked as present, not re-edited here.
- Presets: `set_trust_brokers`, `set_dnssec`, `policy_with_restrictions` carry `Owner: sys`; `post_to_own_namespace` carries `Owner: <name>`. Other builders (`post`, `create_domain`, …) are unchanged: callers must name an owner (sbo-cli / sbo-wasm clients: mingo-side).
- Tests: un-ignored ws4 `q6_explicit_bare_key_owner_is_rejected`, `q6_signer_fallback_owner_is_rejected_after_genesis`; `d16_unnamed_signer_creator_is_a_truncated_key` inverted (no creator for an unnamed signer; a named one resolves to its name); `l2_authorization::ownerless_write_authorized_via_signer_key_controller` inverted to `ownerless_write_is_rejected_there_is_no_signer_key_fallback`; `resolve_creator_prefers_explicit_creator_then_key_hex` re-pinned without the key-hex tier; `policy_vars::u_namespace_create_denied_without_declared_owner` now expects the Attribution stage. Every other daemon test that relied on the signer fallback now names a registered key-rooted owner (helpers `q6_name_for`/`q6_register`, `put_name`, `register_name`).
- Conformance: `conformance/batch.json` regenerated (`audit_2026_11_ws2_generate`): the batch vectors name `Owner: alice` / `Owner: bob` (seed keys) and the daemon runner registers those names; the other vector files are byte-identical.
- Regenesis bundle sbo-eefz: owner-less writes on the live chain are invalid under this rule.
