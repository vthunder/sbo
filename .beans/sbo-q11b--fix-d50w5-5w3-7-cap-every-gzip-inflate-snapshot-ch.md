---
# sbo-q11b
title: 'Fix D50/W5-5/W3-7: cap every gzip inflate (snapshot, chain data) and refuse redirects on bootstrap fetches'
status: completed
type: bug
priority: normal
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:40:21Z
parent: sbo-ax7t
---

**Medium.** `snapshot.rs:117-120` and `sbo-rpc/src/decode.rs::extract_data_from_encoded_extrinsic` inflate with `read_to_end` (254 KiB → 768 MiB peak; a 2 MiB submission → ~2 GiB on every syncing node); `bootstrap.rs:185-197` follows redirects with a default client.

- [x] One `Take`-capped reader for both; cap from the manifest's `uncompressed_bytes` (itself capped) / the largest legal submission
- [x] `redirect::Policy::none()` + address check on `fetch_manifest`/`fetch_snapshot`
- [x] Acceptance (un-ignore): ws5 `snapshot_fetch_refuses_redirects`, `snapshot_decode_rejects_a_gzip_bomb_without_inflating_it`; ws3_daemon `d50_snapshot_inflation_is_capped`; ws3_decode `w3_7_gzip_inflation_is_capped`



## Summary of Changes

`snapshot.rs` (D50 / W5-5): `inflate_capped(gz, cap)` reads through `GzDecoder::take(cap + 1)` into a buffer sized once (`with_capacity`), so the peak allocation is the cap, and errors when the stream exceeds it. `decode_snapshot_payload` uses the hard ceiling `MAX_SNAPSHOT_BYTES` (32 MiB); `decode_snapshot_payload_capped(gz, cap)` clamps a caller cap to it. `bootstrap_provisional` passes the chosen snapshot's advertised `uncompressed_bytes` via the new `fetch_snapshot_capped`.

`bootstrap.rs` (W5-5): `fetch_manifest` / `fetch_snapshot` go through one `fetch_client()` with `redirect::Policy::none()` and a 60 s timeout; `check_node_url` refuses a node hostname that resolves to a non-global address (a literal IP or `localhost` chosen by the operator stays allowed, so a local dev node still works); bodies are read via `status::read_capped` (manifest 4 MiB, compressed snapshot 16 MiB).

`sbo-rpc/src/decode.rs` (W3-7): `extract_data_from_encoded_extrinsic` inflates through `take(MAX_INFLATED_BYTES + 1)` (16 MiB, exported) and returns `None` for an over-cap blob; the same cap applied to the second inflate in `sbo-daemon/src/rpc.rs` (cell-decoded app data), which `continue`s past an over-cap blob.

Tests un-ignored: ws5 `snapshot_fetch_refuses_redirects`, `snapshot_decode_rejects_a_gzip_bomb_without_inflating_it` (peak < 64 MiB for a 256 MiB bomb); ws3_daemon `d50_snapshot_inflation_is_capped`; sbo-rpc ws3_decode `w3_7_gzip_inflation_is_capped`.
