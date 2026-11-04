---
# sbo-ch88
title: 'Fix W3-6/W3-8/W3-9/W3-10/D40: checked length arithmetic and total parsers for SBOP, SBOQ, batch splitter and non-existence proofs'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Medium.** W3-9: `proof/sbop.rs:113` slices past the end when the image has no blank line — one DA submission panics every light node. W3-10: `wire/parser.rs:75` `pos + Content-Length` wraps into a slice panic — one DA submission kills every node's sync task (also `/v1/submit`). W3-8: `trie.rs:1246` `verify_nonexistence_proof` indexes `path_segments[idx]` unchecked; the proof an indexer returns for a missing top-level object panics the client. W3-6: `Receipt-Length`/`Object-Length` unchecked arithmetic (SBOQ panics in release from a hostile indexer). D40 heuristics in `extract_sbo_payload`.

- [ ] Checked arithmetic + upper bounds on every length header; `path_segments.get(idx)`; blank-line terminator required
- [ ] Lift the guards in the `proof_parse`, `wire_parse`, `trie_proof` fuzz targets
- [ ] Acceptance (un-ignore): `w3_6_sbop_huge_receipt_length_does_not_panic`, `w3_6_sboq_huge_object_length_does_not_panic`, `w3_8_nonexistence_verifier_rejects_short_path_segments`, `w3_9_sbop_without_blank_line_does_not_panic`, `w3_10_huge_content_length_does_not_panic`
