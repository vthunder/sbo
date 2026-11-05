---
# sbo-xqo2
title: 'Fix D18/W5-4/D52/W5-9: submit-gate status fetch guard and no evidence capture before the presentation is self-consistent'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:40:21Z
parent: sbo-ax7t
---

**Medium.** `status.rs:76-82` fetches status URIs with a default client (redirects, no address check, uncapped body); URI host never compared to the authority (D52); `main.rs:640-668` runs live DNSSEC captures for issuers named by unverified presentation claims before any signature check (W5-9, I2 class). browserid-ng H1/W6-5 class.

- [x] `redirect::Policy::none()`, https only, non-global addresses rejected before connecting, body cap (64 KiB), `uri_host(status.uri) == authority` for access/config certs
- [x] Check presentation internal consistency before any capture; cap issuers per submit at two; count captures against the limiter
- [x] Acceptance (un-ignore): ws5 `status_fetch_never_dials_a_non_public_address`, `status_fetch_requires_uri_host_to_equal_the_authority`; new `AUDIT-2026-11 W5-9` test



## Summary of Changes

`status.rs` (W5-4 / D52): the checker's client is built with `redirect::Policy::none()`; `fetch_and_verify` now, after the https / evidence / window checks and before any connection, requires `uri_host(status.uri) == authority` for the `access cert` and `config cert` refs (warrants stay signer-chosen: their authority IS the URI host by construction), then `validate_status_host` resolves the host and refuses any non-global address (loopback, private, link-local, ULA, CGNAT, unspecified, multicast; `is_global_ip`, copied from browserid-ng `validate_status_url`), and the body is read through `read_capped` (64 KiB, enforced on the stream, Content-Length included). `validate_status_host`, `is_global_ip`, `read_capped` are `pub` and reused by the bootstrap fetch (sbo-q11b).

`evidence.rs` (W5-9): new `capture_issuers(msg)` returns the issuers a write may make the node capture for only after the presentation is internally consistent (envelope signing key == access cert `access-key`, assertion signed by it and naming the warrant audience, warrant signed by the config cert key, grantee == access identity); a legacy single-JWT presentation keeps one issuer; `MAX_ISSUERS_PER_SUBMIT = 2`. `main.rs::submit` uses it (400 `Attribution: presentation: ...` before any capture) and refuses a batch naming more than two distinct issuers. Captures run inside the submit handler, so public mode's per-source spend budget (sbo-b4cx) bounds them. `required_issuers` is kept (pure claim read; the ws5 pin still passes).

Tests un-ignored: ws5 `status_fetch_never_dials_a_non_public_address`, `status_fetch_requires_uri_host_to_equal_the_authority`. New: ws5 `w5_9_inconsistent_presentation_names_no_issuers_for_capture`; status.rs unit tests for `uri_host`, `is_global_ip`, literal-loopback refusal.
