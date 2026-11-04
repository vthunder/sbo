---
# sbo-hs4r
title: 'Fix W7-5/W7-14/W4-3: config.toml and key files 0600 and asserted on load; debug dumps under the daemon dir; sbo-capture no-redirect client'
status: todo
type: bug
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-04T21:34:00Z
parent: sbo-ax7t
---

**Low.** `config.rs:369,498` writes `config.toml` (holding the TurboDA key) at umask 0644; `load_checkpoint_key` never asserts mode; `rpc.rs:243` writes raw block dumps to the fixed, symlink-followable `/tmp/sbo-debug` (debug flag only); `sbo-capture/src/lib.rs:83` follows redirects to the operator-chosen IdP base URL.

- [ ] `OpenOptions::mode(0o600)`; assert mode on load
- [ ] Dumps under `Config::sbo_dir()/debug`, `create_dir` + `O_NOFOLLOW`
- [ ] `redirect::Policy::none()` in sbo-capture
- [ ] Acceptance (un-ignore): `audit_2026_11_ws7.rs` `w7_5_sample_config_holding_the_turbo_da_key_is_owner_only`
