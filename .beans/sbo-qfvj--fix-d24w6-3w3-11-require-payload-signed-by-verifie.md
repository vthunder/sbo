---
# sbo-qfvj
title: 'Fix D24/W6-3/W3-11: require_payload_signed_by verifies the JWT against the domain key; JWT kind claim'
status: todo
type: bug
priority: low
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Low** today (fails closed), Medium once the path bug is fixed. `policy/evaluate.rs:253-300`: `issuer_to_path` yields `/sys/domains/<d>` without a trailing slash so every payload is denied (W6-3); behind that, only the issuer string is matched, the JWT signature is never verified. W3-11: identity and domain JWT claim types are mutually decodable.

- [ ] Fix the path; load the issuer object; verify the JWT signature against its key
- [ ] Add a kind/typ claim to identity and domain JWTs
- [ ] Acceptance (un-ignore): ws6 core `d24_payload_signed_by_admits_the_domain_key_and_rejects_a_forged_issuer`
