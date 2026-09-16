//! The real browserid-pay root policy must parse and enforce under this
//! implementation. Inlined rather than fetched, so the shape a live chain
//! depends on is pinned here as a regression test (bean sbo-pu34 / browserid-pay-er8j).

use sbo_core::policy::Policy;

const ROOT_POLICY: &str = r#"{
  "roles": { "admin": [{ "key": "ed25519:3464f4e59cfb240f246618094a41c42ec0dbd4ea73f5cf645999c7938fcc62e4" }] },
  "grants": [
    { "to": "*", "can": ["create"], "on": "/sys/names/*" },
    { "to": "owner", "can": ["update", "delete"], "on": "/sys/names/*" },
    { "to": "*", "can": ["post", "delete"], "on": "/$user/**" },
    { "to": "*", "can": ["post"], "on": "/providers/custodians/$user/**" },
    { "to": "*", "can": ["create"], "on": "/agreements/**" },
    { "to": { "role": "admin" }, "can": ["post", "transfer", "delete", "govern"], "on": "/**" }
  ],
  "restrictions": [
    { "on": "/providers/**", "require": { "schema": "provider.v1", "max_size": 16384 } },
    { "on": "/agreements/**", "require": { "max_size": 65536 } },
    { "on": "/agreements/*/", "id": "proposal", "require": { "fields": [
      { "pointer": "/contribution/fn", "eq": "max" },
      { "pointer": "/contribution/amount", "min": 0.01 },
      { "pointer": "/contribution/percentage", "min": 0.01 }
    ]}}
  ]
}"#;

#[test]
fn root_policy_parses_with_id_and_field_conditions_intact() {
    let policy: Policy = serde_json::from_str(ROOT_POLICY).expect("root policy must parse");

    let r = policy
        .restrictions
        .iter()
        .find(|r| r.id.is_some())
        .expect("the contribution restriction keeps its id");
    assert_eq!(r.require.fields.len(), 3, "all three field conditions survive");

    // Re-serializing preserves `id` and `fields` (the only delta is the
    // pre-existing `deny: []`, which has a serde default but no skip).
    let back = serde_json::to_value(&policy).unwrap();
    let restriction = back["restrictions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r.get("id").is_some())
        .expect("id survives re-serialization");
    assert_eq!(restriction["id"], "proposal");
    assert_eq!(restriction["require"]["fields"].as_array().unwrap().len(), 3);

    // A policy with no id/fields must not grow them.
    let plain = &back["restrictions"][0];
    assert!(plain.get("id").is_none(), "absent id stays absent: {plain}");
    assert!(plain["require"].get("fields").is_none(), "absent fields stays absent: {plain}");
}
