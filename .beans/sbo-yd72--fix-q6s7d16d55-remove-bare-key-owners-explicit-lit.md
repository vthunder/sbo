---
# sbo-yd72
title: 'Fix Q6/S7/D16/D55: remove bare-key owners (explicit literals and the signer fallback); genesis anchor is the only exception'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `resolve.rs:128-129` maps any `ed25519:` literal to `Controller::Key`; `validate.rs:510-518` falls back to the signer key when no owner is named; `resolve_creator` emits `e_<16 hex>` / `unknown` sentinels (D16/D55). Q6 (Dan): an identity is a `/sys/names` name or an email; explicit bare-key `Owner`/`Creator`/`New-Owner` reject AND the signer fallback is dropped; key-rooted name records stay; only the genesis batch at the anchor is exempt. July `sbo-4arq`.

Blocked by: state-commitment v2 bundle (regenesis). No open decision.

- [ ] Thread provenance (explicit vs fallback) through `resolve_controller`; reject both forms after genesis
- [ ] Delete the `e_<hex>`/`unknown` sentinels
- [ ] Identity spec: owner-reference table and `resolve_controller` pseudocode lose the bare-key row
- [ ] Acceptance (un-ignore): ws4 `q6_explicit_bare_key_owner_is_rejected`, `q6_signer_fallback_owner_is_rejected_after_genesis`; `d16_unnamed_signer_creator_is_a_truncated_key` inverts
