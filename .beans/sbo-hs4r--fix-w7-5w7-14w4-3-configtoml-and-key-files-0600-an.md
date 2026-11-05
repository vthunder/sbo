---
# sbo-hs4r
title: 'Fix W7-5/W7-14/W4-3: config.toml and key files 0600 and asserted on load; debug dumps under the daemon dir; sbo-capture no-redirect client'
status: completed
type: bug
priority: low
created_at: 2026-11-04T21:34:00Z
updated_at: 2026-11-05T10:40:22Z
parent: sbo-ax7t
---

**Low.** `config.rs:369,498` writes `config.toml` (holding the TurboDA key) at umask 0644; `load_checkpoint_key` never asserts mode; `rpc.rs:243` writes raw block dumps to the fixed, symlink-followable `/tmp/sbo-debug` (debug flag only); `sbo-capture/src/lib.rs:83` follows redirects to the operator-chosen IdP base URL.

- [x] `OpenOptions::mode(0o600)`; assert mode on load
- [x] Dumps under `Config::sbo_dir()/debug`, `create_dir` + `O_NOFOLLOW`
- [x] `redirect::Policy::none()` in sbo-capture
- [x] Acceptance (un-ignore): `audit_2026_11_ws7.rs` `w7_5_sample_config_holding_the_turbo_da_key_is_owner_only`



## Summary of Changes

- `config.rs` (W7-5): `save` and `save_sample` write through `write_private` (`OpenOptions` `mode(0o600)` + `O_NOFOLLOW`, then `set_permissions(0o600)` so an existing file is pinned too). `Config::load` asserts the mode: a group/other-readable `config.toml` that holds a credential (`turbo_da.api_key`, `[[turbo_da.repos]]`, `[http] bearer_tokens`) is refused; a credential-free one only warns. Mingo-side note: the image `COPY`s `/app/config.toml` at 0644, which is fine today (its key comes from `SBO_TURBO_DA_API_KEY`); it will log the warning, and would refuse to start only if someone put a key in the file.
- `main.rs` (W7-14): `load_checkpoint_key` (used for both `[checkpoint] key_file` and `[attest] key_file`) calls `Config::assert_private_key_file` first and refuses a key file that is not owner-only (entrypoint.sh already `chmod 600`s both).
- `rpc.rs` (W4-3): raw-block debug dumps go to `Config::sbo_dir()/debug` (`/data/.sbo/debug` in the container), created `0700` via `DirBuilder` and refused if a symlink / non-directory sits there; dump files open `0600` + `O_NOFOLLOW`. Doc comment and `docs/daemon-debugging.md` updated.
- `sbo-capture/src/lib.rs`: `BrokerClient`'s reqwest client is `redirect::Policy::none()` (the session cookie never follows a bounce).

Test un-ignored: ws7 `w7_5_sample_config_holding_the_turbo_da_key_is_owner_only`.
