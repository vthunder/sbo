---
# sbo-nepw
title: 'Fix W2-1/Q36: one identifier grammar in sbo-types, re-exported by sbo-core::message'
status: completed
type: task
priority: low
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:20:48Z
parent: sbo-ax7t
---

**Low.** `sbo-types` (`Id`, `Path`, `Action`; re-exported as `sbo_core::Id`, used by the zkVM guest) rejects `@ + :` and case-folds actions admitting `create`/`update`; `sbo-core::message` is the wire grammar. 13 vectors differ.

Depends on: **Q36 (open)**. Blocked by: identity helper.

- [x] Move the `sbo-core::message` grammar into `sbo-types`; `sbo-core::message` re-exports; sbo-wasm follows
- [x] Acceptance: 13 entries out of `audit_2026_11_ws2_types.rs` `EXPECTED_FAIL`; `sbo_types_id_is_subset_of_core_id` flips to equality

## Decision

Decided as recommended (Dan, 2026-11-05; see docs/security-audit-2026-11-decisions.md).

## Summary of Changes

- `sbo-types` is now the one grammar: `Id` (charset + `.`/`..` + identity rule), `Path` (`ancestors`, `Hash`), `Action` (the four wire actions with transfer/import payloads, exact lowercase parse, serde as the wire name). `sbo-core::message` re-exports them; `sbo-core::error::ParseError` gains `From<sbo_types::ParseError>`; sbo-wasm adds the `sbo-types` dependency (no_std-clean) and follows by `#[path]`.
- Removed the duplicate `Id`/`Path` serde impls from `sbo-core::state::objects` (now provided by sbo-types) and the old `sbo-core::message::Id/Path` definitions.
- `sbo-types/tests/serde_integration.rs` re-pinned to the wire actions (was `create`/`update`): decision Q36 changed the behaviour.
- `audit_2026_11_ws2_types.rs` `EXPECTED_FAIL` is empty; `sbo_types_id_is_subset_of_core_id` asserts equality on every string.
