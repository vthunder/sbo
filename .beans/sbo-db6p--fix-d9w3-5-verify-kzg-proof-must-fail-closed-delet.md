---
# sbo-db6p
title: 'Fix D9/W3-5: verify_kzg_proof must fail closed; delete dead merkle.rs'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:31:37Z
updated_at: 2026-11-04T21:31:37Z
parent: sbo-ax7t
---

**High** as a crypto claim, scoped by Q20 (c). `sbo-crypto/src/kzg.rs:116-157` returns `Ok(true)` after point checks, no pairing. The LC read path does not call it (Q20), so this round the function returns `Err(KzgError::Unsupported)` instead of lying; the full pairing waits for the light-node migration (sbo-wn15). W3-5: `merkle.rs` is dead code with a prover/verifier mismatch.

- [ ] `verify_kzg_proof` → `Err(Unsupported)` until a pairing is implemented
- [ ] Delete `sbo-crypto/src/merkle.rs` or wire it in with a fix
- [ ] Acceptance (un-ignore): `crates/sbo-crypto/tests/audit_2026_11_ws6.rs` `d9_kzg_verify_rejects_a_proof_that_does_not_open_the_commitment` (`--features kzg`)
