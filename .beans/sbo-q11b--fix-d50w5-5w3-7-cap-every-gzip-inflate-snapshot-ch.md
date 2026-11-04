---
# sbo-q11b
title: 'Fix D50/W5-5/W3-7: cap every gzip inflate (snapshot, chain data) and refuse redirects on bootstrap fetches'
status: todo
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Medium.** `snapshot.rs:117-120` and `sbo-rpc/src/decode.rs::extract_data_from_encoded_extrinsic` inflate with `read_to_end` (254 KiB → 768 MiB peak; a 2 MiB submission → ~2 GiB on every syncing node); `bootstrap.rs:185-197` follows redirects with a default client.

- [ ] One `Take`-capped reader for both; cap from the manifest's `uncompressed_bytes` (itself capped) / the largest legal submission
- [ ] `redirect::Policy::none()` + address check on `fetch_manifest`/`fetch_snapshot`
- [ ] Acceptance (un-ignore): ws5 `snapshot_fetch_refuses_redirects`, `snapshot_decode_rejects_a_gzip_bomb_without_inflating_it`; ws3_daemon `d50_snapshot_inflation_is_capped`; ws3_decode `w3_7_gzip_inflation_is_capped`
