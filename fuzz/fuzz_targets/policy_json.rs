#![no_main]
//! WS3: `Policy` deserialization is total on arbitrary text, its
//! serialization round-trips, and evaluation on a fixed message terminates
//! with the same verdict for the policy and its round-tripped twin.
//!
//! Matching is memoised and role resolution is bounded (W3-1 / D10 fixed under
//! `sbo-0qqq` / `sbo-sla3`), so every policy that parses is evaluated; the
//! parse itself rejects cycles, over-deep role chains and patterns over the
//! wildcard cap.

use libfuzzer_sys::fuzz_target;
use sbo_core::message::Id;
use sbo_core::policy::{check_descendant_constraint, evaluate, ActionType, Policy, PolicyResult, PolicyVars};

fuzz_target!(|data: &[u8]| {
    let s = sbo_fuzz::text(data);
    let Ok(p) = serde_json::from_str::<Policy>(&s) else { return };
    let v = serde_json::to_value(&p).unwrap();
    let p2: Policy = serde_json::from_value(v.clone()).expect("serialized policy deserializes");
    assert_eq!(serde_json::to_value(&p2).unwrap(), v, "policy JSON round trip unstable");
    let msg = sbo_fuzz::envelope("/u/alice/posts/", "p1", br#"{"v":1}"#.to_vec(), 1);
    let vars = PolicyVars { owner: Some("alice"), user: Some("alice"), email: Some("alice@example.com"), name: Some("alice"), };
    for act in [ActionType::Create, ActionType::Update, ActionType::Delete, ActionType::Govern] {
        let a = matches!(evaluate(&p, &Id::new("alice").unwrap(), act, "/u/alice/posts/", &vars, true, &|_| false, &msg, Some("example.com")), PolicyResult::Allowed);
        let b = matches!(evaluate(&p2, &Id::new("alice").unwrap(), act, "/u/alice/posts/", &vars, true, &|_| false, &msg, Some("example.com")), PolicyResult::Allowed);
        assert_eq!(a, b, "round-tripped policy evaluates differently");
        if !p.deny.is_empty() && p.deny.iter().any(|d| d.matches(&sbo_core::message::Path::parse("/u/alice/posts/").unwrap(), &vars)) {
            assert!(!a, "deny did not win");
        }
    }
    if let Some(dc) = &p.descendant_constraint {
        let _ = check_descendant_constraint(&p, dc);
        let _ = check_descendant_constraint(&p2, dc);
    }
});
