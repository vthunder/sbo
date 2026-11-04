//! Security audit 2026-11, WS7 (supply chain, secrets, logging): tests that
//! pin what was verified and encode the confirmed findings. Tests marked
//! `#[ignore]` with an `AUDIT-2026-11 W7-n: fails today` comment are the
//! acceptance tests for the matching remediation bean; un-ignore them when the
//! fix lands. Report: docs/security-audit-2026-11-ws7-supply-chain.md.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// W7-5: `Config::save_sample` writes the daemon config, which the generated
/// file itself tells the operator to fill with the TurboDA `api_key`, with the
/// process umask (0644 by default), so the credential is readable by every
/// local user. The checkpoint and attestor key files in the deployment are
/// chmod 600 by entrypoint.sh; the config file never is.
#[test]
#[ignore] // AUDIT-2026-11 W7-5: fails today (config.toml is created 0644)
fn w7_5_sample_config_holding_the_turbo_da_key_is_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    sbo_daemon::config::Config::save_sample(&path).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("api_key"), "the sample config documents the api_key field");
    assert_eq!(mode(&path), 0o600, "config.toml must be 0600: it is where the TurboDA API key goes");
}

/// Re-verified: the keyring directory is 0700 and every secret-key file and
/// the metadata file are 0600 after creation (sbo-core keyring.rs). The write
/// is `fs::write` then `set_permissions`, so there is a window at umask
/// before the chmod and the temp file is renamed into place afterwards; the
/// final state is what this pins.
#[test]
fn keyring_directory_and_key_files_are_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let keys_dir = dir.path().join("keys");
    let mut kr = sbo_core::keyring::Keyring::open_at(keys_dir.clone()).unwrap();
    let _pk = kr.generate("audit").unwrap();
    assert_eq!(mode(&keys_dir), 0o700);
    assert_eq!(mode(&keys_dir.join("keyring.json")), 0o600);
    assert_eq!(mode(&keys_dir.join("audit.key")), 0o600);
}
