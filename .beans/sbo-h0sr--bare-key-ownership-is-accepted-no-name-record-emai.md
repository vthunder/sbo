---
# sbo-h0sr
title: Bare-key ownership is accepted (no name record / email / DNSSEC)
status: scrapped
type: bug
priority: critical
created_at: 2026-07-08T15:48:22Z
updated_at: 2026-07-08T15:49:37Z
parent: sbo-f5wn
blocking:
    - sbo-4arq
---

resolve.rs:128 returns Controller::Key for any ed25519:/bls: Owner literal; authorize.rs:129 authorizes on direct signature. Owner: ed25519:<key> grants ownership with no /sys/names record, no email, no DNSSEC. Impl cannot distinguish explicit bare-key Owner from the legitimate signer-fallback (both -> Controller::Key), so fix needs provenance threaded through resolve_controller. Spec also still lists bare-key as a valid owner form and must be updated.
- [ ] Thread provenance (explicit-owner vs signer-fallback) into resolve_controller
- [ ] Reject explicit bare-key Owner/Creator literals as invalid identities
- [ ] Update Identity Spec (owner-reference table + resolve_controller pseudocode) to drop bare-key owner
See also existing bean sbo-4arq.

## Reasons for Scrapping

Duplicate of the pre-existing sbo-4arq, which covers the same bare-key-ownership issue in more detail. Folded the new review findings (provenance threading, spec update) into sbo-4arq instead. sbo-4arq is now parented under the review epic sbo-f5wn.
