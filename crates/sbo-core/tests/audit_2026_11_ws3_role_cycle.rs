//! Security audit 2026-11, WS3: role resolution termination (WS1 lead D10,
//! July `sbo-bynl`; threat model I11). In its own test binary because a
//! failing run is a stack overflow that ABORTS the process rather than a
//! panic. Fixed under `sbo-sla3` (D10 / Q17 (a)): cycles and over-deep chains
//! reject at parse, and the evaluator bounds resolution regardless.

mod audit_2026_11_ws3_support;
use audit_2026_11_ws3_support::*;

use sbo_core::message::Id;
use sbo_core::policy::{evaluate, ActionType, Policy, PolicyResult, PolicyVars};

fn eval(pol: &Policy) -> bool {
    let msg = signed("/c/", "o", b"{}".to_vec(), &key_from_seed(1));
    matches!(
        evaluate(pol, &Id::new("nobody").unwrap(), ActionType::Create, "/c/", &PolicyVars::default(), false, &|_| false, &msg, None),
        PolicyResult::Allowed
    )
}

/// D10 (High): a policy whose roles reference each other in a cycle is
/// accepted by the parser and sends `identity_matches` into unbounded
/// recursion. Expected: the policy is rejected at parse/validation time, or
/// evaluation terminates with a denial.
#[test]
fn d10_cyclic_roles_terminate() {
    let v = serde_json::json!({
        "roles": {"admin": [{"role": "mod"}], "mod": [{"role": "admin"}]},
        "grants": [{"to": {"role": "admin"}, "can": ["create"], "on": "/**"}]
    });
    match serde_json::from_value::<Policy>(v) {
        Err(_) => {} // rejected at parse: acceptable
        Ok(pol) => assert!(!eval(&pol), "nobody is a member of a cyclic role"),
    }
}

/// D10 (High): a self-referencing role is the one-node cycle.
#[test]
fn d10_self_referencing_role_terminates() {
    let v = serde_json::json!({
        "roles": {"r": [{"role": "r"}]},
        "grants": [{"to": {"role": "r"}, "can": ["create"], "on": "/**"}]
    });
    if let Ok(pol) = serde_json::from_value::<Policy>(v) {
        assert!(!eval(&pol));
    }
}

/// D10 (High), depth half: even without a cycle, a chain of N roles recurses
/// N deep. With no depth bound a long acyclic chain overflows the stack too;
/// expected: a validation-time bound (I11 "role resolution at evaluation time
/// is bounded").
#[test]
fn d10_role_chain_depth_is_bounded() {
    let n = 200_000;
    let mut roles = serde_json::Map::new();
    for i in 0..n {
        roles.insert(format!("r{i}"), serde_json::json!([{"role": format!("r{}", i + 1)}]));
    }
    roles.insert(format!("r{n}"), serde_json::json!(["nobody-else"]));
    let v = serde_json::json!({
        "roles": roles,
        "grants": [{"to": {"role": "r0"}, "can": ["create"], "on": "/**"}]
    });
    match serde_json::from_value::<Policy>(v) {
        Err(_) => {}
        Ok(pol) => assert!(!eval(&pol)),
    }
}

/// Pinned: a well-formed acyclic role tree resolves (passes today).
#[test]
fn acyclic_roles_resolve() {
    let v = serde_json::json!({
        "roles": {"admin": ["someone-else"], "staff": [{"role": "admin"}, {"any": [{"role": "admin"}]}]},
        "grants": [{"to": {"role": "staff"}, "can": ["create"], "on": "/**"}]
    });
    let pol: Policy = serde_json::from_value(v).unwrap();
    // "someone-else" is not the actor, so the grant does not apply, but evaluation terminates.
    assert!(!eval(&pol));
}
