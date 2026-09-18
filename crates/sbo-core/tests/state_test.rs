use sbo_core::state::{StateDb, StoredObject};
use sbo_core::message::{Id, Path};
use sbo_core::crypto::ContentHash;
use tempfile::tempdir;

#[test]
fn test_store_and_retrieve_object() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let obj = StoredObject {
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        creator: Id::new("alice").unwrap(),
        owner: Id::new("alice").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None, related: None,
        content_schema: None,
        owner_ref: None,
        block_number: 1,
        object_hash: [0u8; 32], // Placeholder - in production, this is sha256(raw_sbo_bytes)
        hlc: None,
        prev: None,
    };

    db.put_object(&obj).unwrap();

    let retrieved = db.get_object(
        &Path::parse("/test/").unwrap(),
        &Id::new("hello").unwrap(),
    ).unwrap();

    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id.as_str(), "hello");
    assert_eq!(retrieved.block_number, 1);
}

/// Deleting a policy must remove it from the policy index, so the ancestor walk
/// falls through to the parent.
///
/// It did not (mingo-hpli): `resolve_policy_entry` kept returning the deleted
/// policy, every write under that path was denied `No matching grant`, and the
/// path could never be used again — on a public forum, a community id burned
/// for good. Deleting a policy means "inherit the parent", not "deny
/// everything, permanently".
#[test]
fn deleting_a_policy_falls_through_to_the_parent() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let root = Path::parse("/sys/policies/").unwrap();
    let child = Path::parse("/communities/agents/").unwrap();
    let pat = |g: &sbo_core::policy::Grant| serde_json::to_string(&g.on).unwrap().trim_matches('"').to_string();
    let parse = |v: serde_json::Value| -> sbo_core::policy::Policy { serde_json::from_value(v).unwrap() };

    let root_policy = parse(serde_json::json!({
        "grants": [{ "to": "*", "can": ["post"], "on": "/**" }]
    }));
    let child_policy = parse(serde_json::json!({
        "grants": [{ "to": { "role": "member" }, "can": ["create"], "on": "/communities/agents/spaces/**" }]
    }));

    db.put_policy_at(&root, &root_policy, "sha256:root", 1).unwrap();
    db.put_policy_at(&child, &child_policy, "sha256:child", 2).unwrap();

    // The nearer policy governs while it exists.
    let got = db.resolve_policy(&child).unwrap().expect("a policy governs");
    assert_eq!(got.grants.len(), 1);
    assert_eq!(pat(&got.grants[0]), "/communities/agents/spaces/**");

    // Delete it: the parent governs again — NOT nothing.
    db.delete_policy_at(&child).unwrap();
    let got = db.resolve_policy(&child).unwrap()
        .expect("the parent policy must govern once the child is gone, not nothing");
    assert_eq!(pat(&got.grants[0]), "/**", "fell through to the root policy");

    // And the path is usable again: re-indexing works.
    db.put_policy_at(&child, &child_policy, "sha256:child2", 3).unwrap();
    assert_eq!(
        pat(&db.resolve_policy(&child).unwrap().unwrap().grants[0]),
        "/communities/agents/spaces/**",
    );
}
