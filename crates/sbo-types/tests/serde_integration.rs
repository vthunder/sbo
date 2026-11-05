#![cfg(feature = "serde")]

use sbo_types::id::Id;
use sbo_types::path::Path;
use sbo_types::action::Action;

#[test]
fn test_id_serde_roundtrip() {
    let id = Id::new("alice").unwrap();
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, r#""alice""#);

    let deserialized: Id = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, id);
}

#[test]
fn test_id_serde_validation() {
    // Invalid ID should fail during deserialization
    let result: Result<Id, _> = serde_json::from_str(r#""has space""#);
    assert!(result.is_err());
}

#[test]
fn test_path_serde_roundtrip() {
    let path = Path::parse("/alice/nfts/").unwrap();
    let json = serde_json::to_string(&path).unwrap();
    assert_eq!(json, r#""/alice/nfts/""#);

    let deserialized: Path = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, path);
}

#[test]
fn test_path_root_serde() {
    let path = Path::root();
    let json = serde_json::to_string(&path).unwrap();
    assert_eq!(json, r#""/""#);

    let deserialized: Path = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, path);
}

#[test]
fn test_path_serde_validation() {
    // Invalid path should fail during deserialization
    let result: Result<Path, _> = serde_json::from_str(r#""no-trailing-slash""#);
    assert!(result.is_err());
}

#[test]
fn test_action_serde_roundtrip() {
    // Audit 2026-11 Q36: the wire grammar has no `create` (post creates).
    let action = Action::Post;
    let json = serde_json::to_string(&action).unwrap();
    assert_eq!(json, r#""post""#);

    let deserialized: Action = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, action);
}

#[test]
fn test_all_actions_serde() {
    let actions = vec![
        (Action::Post, r#""post""#),
        (Action::Delete, r#""delete""#),
        (Action::parse("transfer").unwrap(), r#""transfer""#),
        (Action::parse("import").unwrap(), r#""import""#),
    ];
    assert!(serde_json::from_str::<Action>(r#""create""#).is_err());
    assert!(serde_json::from_str::<Action>(r#""POST""#).is_err());

    for (action, expected_json) in actions {
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, expected_json);

        let deserialized: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, action);
    }
}
