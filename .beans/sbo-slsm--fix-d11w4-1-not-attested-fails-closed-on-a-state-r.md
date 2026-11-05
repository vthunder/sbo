---
# sbo-slsm
title: 'Fix D11/W4-1: not_attested fails closed on a state-read error; index attestations'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:23:53Z
parent: sbo-ax7t
---

**Medium.** `validate.rs:2085-2090` `unwrap_or_default()` turns a RocksDB error into 'not banned'; every attested check scans all `attestation.v1` objects (W4-1). July `sbo-zocd`.

- [x] Propagate the read error as `ValidationStage::State`
- [x] Index attestations by subject/type
- [x] Acceptance (un-ignore): ws4 `d11_not_attested_fails_closed_on_state_read_error`

## Summary of Changes

- `attested_subject_matches` returns `Result<bool, String>`; a failed `list_objects_by_schema` is an error, never "no attestation". `evaluate_policy_for` records the error from the (bool-only) policy callback and returns a new `PolicyError::State`; `check_policy` / `check_policy_at` / `require_govern` / `governing_parent_policy` now return `PolicyError` (`State` or `Denied`), and every call site maps `State` to `ValidationStage::State` and `Denied` to `ValidationStage::Policy` (`PolicyError::into_invalid`). Policy-resolution DB errors are `State` too.
- `StateDb` gains a `by_schema` column family (`<schema>\x1f<object key>`), kept in step by `put_object` / `delete_object` in one `WriteBatch`; `list_objects_by_schema` reads through it instead of scanning the objects CF. A database that predates the index is backfilled once on open (meta key `schema_index_v1`), so an upgraded node does not silently see an empty attestation set. The in-memory filter by type/subject stays in `attested_subject_matches` (the index narrows to the schema, which is what every attested check needs; subject resolution is name-graph dependent and cannot be a static key).
- Un-ignored `d11_not_attested_fails_closed_on_state_read_error`.
