---
# sbo-nepw
title: 'Fix W2-1/Q36: one identifier grammar in sbo-types, re-exported by sbo-core::message'
status: draft
type: task
priority: low
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Low.** `sbo-types` (`Id`, `Path`, `Action`; re-exported as `sbo_core::Id`, used by the zkVM guest) rejects `@ + :` and case-folds actions admitting `create`/`update`; `sbo-core::message` is the wire grammar. 13 vectors differ.

Depends on: **Q36 (open)**. Blocked by: identity helper.

- [ ] Move the `sbo-core::message` grammar into `sbo-types`; `sbo-core::message` re-exports; sbo-wasm follows
- [ ] Acceptance: 13 entries out of `audit_2026_11_ws2_types.rs` `EXPECTED_FAIL`; `sbo_types_id_is_subset_of_core_id` flips to equality
