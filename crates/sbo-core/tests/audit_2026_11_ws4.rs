//! Security audit 2026-11, WS4: core-side pins for the daemon's filesystem
//! mirror (D21) and the CLI keyring (host layer). See
//! `docs/security-audit-2026-11-ws4-layers.md`.

use sbo_core::message::{Id, Path};

/// AUDIT-2026-11 D21: fails today. `Id::new` admits `.` and `..`, which the
/// daemon joins verbatim into the mirror path (`repo/<path>/<id>`), so an
/// on-chain `Path: /../../` or `ID: ..` escapes the repo directory. The core
/// grammar says nothing about dot segments; a filesystem mirror needs them out.
#[test]
fn d21_dot_segments_are_not_valid_ids() {
    assert!(Id::new("..").is_err(), "'..' must not be a valid id");
    assert!(Id::new(".").is_err(), "'.' must not be a valid id");
    assert!(Path::parse("/../").is_err(), "'/../' must not be a valid path");
    assert!(Path::parse("/a/../").is_err(), "'/a/../' must not be a valid path");
}

/// Passes today (pins D21's second half): an id and a path segment share one
/// grammar, so `x` can be both an object id at `/c/` and a collection `/c/x/`;
/// the mirror maps both to `repo/c/x`, and whichever lands second fails
/// `create_dir_all` / `write` and aborts the block on that node (D58).
#[test]
fn d21_object_id_and_collection_name_share_a_grammar() {
    assert!(Id::new("x").is_ok());
    assert!(Path::parse("/c/x/").is_ok());
    // `with_extension("tmp")` on `a.b` yields `a.tmp`, which is itself a valid
    // id, so two objects can race for one temp file.
    assert!(Id::new("a.b").is_ok() && Id::new("a.tmp").is_ok());
    assert_eq!(std::path::Path::new("a.b").with_extension("tmp"), std::path::Path::new("a.tmp"));
}

/// Passes today: the CLI keyring creates its directory 0700 and key files 0600.
#[test]
fn keyring_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let mut kr = sbo_core::keyring::Keyring::open_at(keys.clone()).unwrap();
    kr.generate("k1").unwrap();
    assert_eq!(std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777, 0o700);
    for entry in std::fs::read_dir(&keys).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600,
                "{} is not 0600",
                p.display()
            );
        }
    }
}
