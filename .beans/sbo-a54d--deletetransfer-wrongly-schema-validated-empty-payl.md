---
# sbo-a54d
title: 'Delete/transfer wrongly schema-validated: empty payload + Content-Schema -> Schema-stage reject'
status: completed
type: bug
priority: high
created_at: 2026-07-16T23:42:00Z
updated_at: 2026-07-16T23:42:00Z
---

## Symptom (observed live)

mingo post deletion via /poster/submit failed: daemon 400 `Schema: Invalid JSON payload: EOF while parsing a value at line 1 column 0`.

## Cause

`validate_message` ran `validate_schema(msg)` for ALL actions (validate.rs:566). A delete legitimately carries no payload, but the client sets `Content-Schema: post.v1` on the delete envelope so a delegated-signer (poster) warrant's `schema:` scope matches. The daemon then parsed the empty payload as post.v1 JSON → EOF. Transfer has the same latent issue.

## Fix

Exempt transfer/delete from payload schema validation — they act on an existing object and carry no new payload — mirroring the existing L2-attribution exemption for the same actions (validate.rs:603-609). Gate `validate_schema` behind `!is_transfer_or_delete`.

## Verification

New regression test `owner_delete_with_schema_and_empty_payload_passes_schema_stage` (asserts a delete with Content-Schema + empty payload is not rejected at Schema stage). Full sbo-daemon suite green (56 + others). Needs daemon redeploy + mingo SBO_REV bump to fix the live chain.

## Summary of Changes
Gated payload schema validation to skip transfer/delete in `crates/sbo-daemon/src/validate.rs`; added regression test.
