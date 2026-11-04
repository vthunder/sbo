---
# sbo-uv8a
title: 'Fix D33/Q16: /sys/dnssec refresh must be monotonic (never lower the incumbent''s RRSIG expiration or DNSKEY set)'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:32:42Z
parent: sbo-ax7t
---

**Medium.** `policy/evaluate.rs:224-250` checks validity only; any party can replace the proof with an older valid chain or a pre-rotation key still inside its window. Q16 (a).

Blocked by: the W6-5 fixture bean (needs an offline chain to test).

- [ ] Compare the new proof's RRSIG expiration and DNSKEY set against the incumbent's in the dnssec policy path
- [ ] Acceptance: new test `AUDIT-2026-11 D33` over the fixture
