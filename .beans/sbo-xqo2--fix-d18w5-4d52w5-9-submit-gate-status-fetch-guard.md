---
# sbo-xqo2
title: 'Fix D18/W5-4/D52/W5-9: submit-gate status fetch guard and no evidence capture before the presentation is self-consistent'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Medium.** `status.rs:76-82` fetches status URIs with a default client (redirects, no address check, uncapped body); URI host never compared to the authority (D52); `main.rs:640-668` runs live DNSSEC captures for issuers named by unverified presentation claims before any signature check (W5-9, I2 class). browserid-ng H1/W6-5 class.

- [ ] `redirect::Policy::none()`, https only, non-global addresses rejected before connecting, body cap (64 KiB), `uri_host(status.uri) == authority` for access/config certs
- [ ] Check presentation internal consistency before any capture; cap issuers per submit at two; count captures against the limiter
- [ ] Acceptance (un-ignore): ws5 `status_fetch_never_dials_a_non_public_address`, `status_fetch_requires_uri_host_to_equal_the_authority`; new `AUDIT-2026-11 W5-9` test
