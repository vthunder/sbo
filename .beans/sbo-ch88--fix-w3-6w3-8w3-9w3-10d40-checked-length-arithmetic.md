---
# sbo-ch88
title: 'Fix W3-6/W3-8/W3-9/W3-10/D40: checked length arithmetic and total parsers for SBOP, SBOQ, batch splitter and non-existence proofs'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:35:50Z
parent: sbo-ax7t
---

**Medium.** W3-9: `proof/sbop.rs:113` slices past the end when the image has no blank line — one DA submission panics every light node. W3-10: `wire/parser.rs:75` `pos + Content-Length` wraps into a slice panic — one DA submission kills every node's sync task (also `/v1/submit`). W3-8: `trie.rs:1246` `verify_nonexistence_proof` indexes `path_segments[idx]` unchecked; the proof an indexer returns for a missing top-level object panics the client. W3-6: `Receipt-Length`/`Object-Length` unchecked arithmetic (SBOQ panics in release from a hostile indexer). D40 heuristics in `extract_sbo_payload`.

- [x] Checked arithmetic + upper bounds on every length header; `path_segments.get(idx)`; blank-line terminator required
- [x] Lift the guards in the `proof_parse`, `wire_parse`, `trie_proof` fuzz targets
- [x] Acceptance (un-ignore): `w3_6_sbop_huge_receipt_length_does_not_panic`, `w3_6_sboq_huge_object_length_does_not_panic`, `w3_8_nonexistence_verifier_rejects_short_path_segments`, `w3_9_sbop_without_blank_line_does_not_panic`, `w3_10_huge_content_length_does_not_panic`

## Summary of Changes

- `wire/parser.rs` (W3-10): `Content-Length` parsed as a canonical decimal, bounded by the Wire spec §Size Bounds (`MAX_MESSAGE_BYTES` 2 MiB for header block + payload, `MAX_HEADER_BLOCK_BYTES` 64 KiB, `MAX_SUBMISSION_BYTES` 4 MiB in `parse_batch`), and `body_start.checked_add(len)` checked against the buffer before any slice.
- `proof/sbop.rs` (W3-9, W3-6, D40): the blank-line terminator is required; `Receipt-Length` bounded by `MAX_RECEIPT_LENGTH` (64 MiB), base64 length computed with `div_ceil`/`saturating_mul`, and a payload too short for the declared receipt rejects before decoding.
- `proof/sboq.rs` (W3-6): `obj_start.checked_add(Object-Length)` bounded by the buffer.
- `sbo-crypto/src/trie.rs` (W3-8): `verify_nonexistence_proof` uses `path_segments.get(idx)` and answers `Err(InvalidProof)`.
- Fuzz guards lifted in `fuzz/fuzz_targets/{wire_parse,proof_parse,trie_proof}.rs`.
