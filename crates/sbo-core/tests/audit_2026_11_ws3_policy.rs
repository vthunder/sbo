//! Security audit 2026-11, WS3: property tests over the policy layer — path and
//! id patterns, grant/deny/restriction composition, action coverage, the
//! descendant-constraint narrowing rule, and policy JSON parsing
//! (threat model I9, I10, I11, I12; WS1 lead D10 is in
//! `audit_2026_11_ws3_role_cycle.rs` because it aborts the process).

mod audit_2026_11_ws3_support;
use audit_2026_11_ws3_support::*;

use proptest::prelude::*;
use sbo_core::message::{Id, Path};
use sbo_core::policy::{
    action_covered_by, check_descendant_constraint, evaluate, grant_covered_by_template, ActionType,
    DescendantConstraint, Grant, IdPattern, PathPattern, Policy, PolicyResult, PolicyVars, Requirements, Restriction,
};
use std::time::{Duration, Instant};

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

const ACTIONS: [ActionType; 8] = [
    ActionType::Create, ActionType::Update, ActionType::Post, ActionType::Delete,
    ActionType::Transfer, ActionType::Import, ActionType::Govern, ActionType::All,
];

fn action() -> impl Strategy<Value = ActionType> {
    prop::sample::select(ACTIONS.to_vec())
}

fn policy(v: serde_json::Value) -> Policy {
    serde_json::from_value(v).unwrap()
}

fn allowed(r: &PolicyResult) -> bool {
    matches!(r, PolicyResult::Allowed)
}

/// Reference path-pattern matcher: `*` one segment, `**` zero or more, else
/// literal. Written as a backtracking regex-free recursion with memoisation so
/// it stays polynomial even where the implementation is exponential.
fn reference_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let seg: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut memo = vec![vec![None; seg.len() + 1]; pat.len() + 1];
    fn go(pat: &[&str], seg: &[&str], i: usize, j: usize, memo: &mut Vec<Vec<Option<bool>>>) -> bool {
        if let Some(v) = memo[i][j] { return v; }
        let r = if i == pat.len() {
            j == seg.len()
        } else if pat[i] == "**" {
            (j..=seg.len()).any(|k| go(pat, seg, i + 1, k, memo))
        } else if j == seg.len() {
            false
        } else {
            (pat[i] == "*" || pat[i] == seg[j]) && go(pat, seg, i + 1, j + 1, memo)
        };
        memo[i][j] = Some(r);
        r
    }
    go(&pat, &seg, 0, 0, &mut memo)
}

fn seg_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "[ab]{1,2}",
        1 => Just("*".to_string()),
        1 => Just("**".to_string()),
    ]
}

fn pattern_str() -> impl Strategy<Value = String> {
    prop::collection::vec(seg_pattern(), 0..5).prop_map(|v| format!("/{}/", v.join("/")))
}

fn small_path() -> impl Strategy<Value = String> {
    prop::collection::vec("[ab]{1,2}", 0..5).prop_map(|v| if v.is_empty() { "/".into() } else { format!("/{}/", v.join("/")) })
}

proptest! {
    #![proptest_config(cfg())]

    /// `PathPattern::matches` agrees with the reference glob semantics on
    /// small alphabets (so every `*`/`**`/literal interaction is covered).
    #[test]
    fn path_pattern_matches_reference(pattern in pattern_str(), path in small_path()) {
        let p = Path::parse(&path).unwrap();
        let got = PathPattern::new(&pattern).matches(&p, &PolicyVars::default());
        prop_assert_eq!(got, reference_match(&pattern, &path), "pattern {:?} path {:?}", pattern, path);
    }

    /// An undefined policy variable fails closed: `/$owner/**` never matches a
    /// real path when `owner` is `None`, and matches exactly the owner's
    /// subtree when it is set.
    #[test]
    fn undefined_variable_fails_closed(owner in plain_id_str(), other in plain_id_str(), tail in small_path()) {
        prop_assume!(owner != other);
        let pat = PathPattern::new("/$owner/**");
        let own = Path::parse(&format!("/{owner}{tail}")).unwrap();
        let oth = Path::parse(&format!("/{other}{tail}")).unwrap();
        prop_assert!(!pat.matches(&own, &PolicyVars::default()));
        let vars = PolicyVars { owner: Some(&owner), ..Default::default() };
        prop_assert!(pat.matches(&own, &vars));
        prop_assert!(!pat.matches(&oth, &vars));
    }

    /// `IdPattern` glob: a literal matches only itself; `*` matches any id;
    /// `prefix*` matches exactly the ids with that prefix.
    #[test]
    fn id_pattern_semantics(id in plain_id_str(), other in plain_id_str(), cut in 0usize..12) {
        let vars = PolicyVars::default();
        prop_assert!(IdPattern::new(&id).matches(&id, &vars));
        prop_assert_eq!(IdPattern::new(&id).matches(&other, &vars), id == other);
        prop_assert!(IdPattern::new("*").matches(&id, &vars));
        let cut = cut.min(id.len());
        let prefix = &id[..cut];
        let star = format!("{}*", prefix);
        prop_assert!(IdPattern::new(&star).matches(&id, &vars));
        prop_assert_eq!(IdPattern::new(&star).matches(&other, &vars), other.starts_with(prefix));
    }

    /// `action_covered_by`: reflexive; `*` covers everything except `govern`;
    /// `post` covers exactly create/update besides itself; `govern` is covered
    /// only by `govern` (I10).
    #[test]
    fn action_coverage_lattice(g in action(), r in action()) {
        prop_assert!(action_covered_by(r, r));
        let expect = match (g, r) {
            (_, ActionType::Govern) => g == ActionType::Govern,
            (ActionType::All, _) => true,
            (ActionType::Post, ActionType::Create | ActionType::Update) => true,
            _ => g == r,
        };
        prop_assert_eq!(action_covered_by(g, r), expect, "{:?} covers {:?}", g, r);
    }

    /// Composition: `deny` beats every grant, for every actor and action
    /// (core §post: "no grants can override a deny").
    #[test]
    fn deny_beats_grant(path in small_path(), act in action(), id in plain_id_str()) {
        prop_assume!(act != ActionType::Govern && act != ActionType::All);
        let pol = policy(serde_json::json!({
            "deny": ["/**"],
            "grants": [{"to": "*", "can": ["*", "govern"], "on": "/**"}]
        }));
        let msg = signed(&path, &id, b"{}".to_vec(), &key_from_seed(1));
        let r = evaluate(&pol, &Id::new("anyone").unwrap(), act, &path, &PolicyVars::default(), true, &|_| true, &msg, None);
        prop_assert!(!allowed(&r));
    }

    /// Composition: with no grant nothing is allowed, whatever the actor
    /// claims; with a `to: "*"` grant on the path everything in `can` is.
    #[test]
    fn grant_is_necessary_and_sufficient(path in small_path(), act in action(), id in plain_id_str(), granted in prop::collection::vec(action(), 0..3)) {
        prop_assume!(act != ActionType::All);
        let empty = policy(serde_json::json!({}));
        let msg = signed(&path, &id, b"{}".to_vec(), &key_from_seed(2));
        let actor = Id::new("x").unwrap();
        prop_assert!(!allowed(&evaluate(&empty, &actor, act, &path, &PolicyVars::default(), true, &|_| true, &msg, None)));
        let names: Vec<serde_json::Value> = granted.iter().map(|a| serde_json::to_value(a).unwrap()).collect();
        let pol = policy(serde_json::json!({"grants": [{"to": "*", "can": names, "on": "/**"}]}));
        let expect = granted.iter().any(|g| action_covered_by(*g, act));
        prop_assert_eq!(allowed(&evaluate(&pol, &actor, act, &path, &PolicyVars::default(), false, &|_| false, &msg, None)), expect);
    }

    /// Restrictions: a `max_size` restriction on the path denies exactly the
    /// payloads above the limit; `not_attested` denies exactly when the
    /// attestation check says the actor is attested (fail-closed shape).
    #[test]
    fn restrictions_narrow_grants(n in 0usize..64, max in 0usize..64, banned in any::<bool>()) {
        let pol = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["post"], "on": "/r/**"}],
            "restrictions": [{"on": "/r/**", "require": {"max_size": max, "not_attested": {"type": "ban"}}}]
        }));
        let msg = signed("/r/", "o", vec![b'x'; n], &key_from_seed(3));
        let r = evaluate(&pol, &Id::new("u").unwrap(), ActionType::Create, "/r/", &PolicyVars::default(), false, &|_| banned, &msg, None);
        prop_assert_eq!(allowed(&r), n <= max && !banned);
    }

    /// Descendant constraint (P3): a child grant is covered iff recipient and
    /// path are byte-equal to a template grant and every child action is
    /// covered by that template's actions; a child never broadens.
    #[test]
    fn descendant_constraint_is_a_narrowing(tcan in prop::collection::vec(action(), 1..3), ccan in prop::collection::vec(action(), 1..3), same_to in any::<bool>(), same_on in any::<bool>()) {
        let t: Grant = serde_json::from_value(serde_json::json!({"to": "*", "can": tcan, "on": "/c/**"})).unwrap();
        let c: Grant = serde_json::from_value(serde_json::json!({
            "to": if same_to { "*" } else { "alice" },
            "can": ccan,
            "on": if same_on { "/c/**" } else { "/**" }
        })).unwrap();
        let expect = same_to && same_on && ccan.iter().all(|c| tcan.iter().any(|t| action_covered_by(*t, *c)));
        prop_assert_eq!(grant_covered_by_template(&c, std::slice::from_ref(&t)), expect);
        // The whole-policy check agrees, and an identical child is always fine.
        let dc = DescendantConstraint { allowed_grants: vec![t.clone()], mandated_restrictions: vec![], forbid_pinning: false };
        let child = Policy { grants: vec![c], ..policy(serde_json::json!({})) };
        prop_assert_eq!(check_descendant_constraint(&child, &dc).is_ok(), expect);
        let twin = Policy { grants: vec![t.clone()], ..policy(serde_json::json!({})) };
        prop_assert!(check_descendant_constraint(&twin, &dc).is_ok());
    }

    /// Mandated restrictions must be present verbatim; any change to the
    /// mandated `max_size` (looser OR tighter) is a violation, which is the
    /// conservative byte-exact rule the design calls for.
    #[test]
    fn mandated_restriction_must_be_verbatim(max in 1usize..100, delta in -5i64..6) {
        let r: Restriction = serde_json::from_value(serde_json::json!({"on": "/m/**", "require": {"max_size": max}})).unwrap();
        let dc = DescendantConstraint { allowed_grants: vec![], mandated_restrictions: vec![r], forbid_pinning: false };
        let got = (max as i64 + delta).max(0) as usize;
        let child = policy(serde_json::json!({"restrictions": [{"on": "/m/**", "require": {"max_size": got}}]}));
        prop_assert_eq!(check_descendant_constraint(&child, &dc).is_ok(), got == max);
    }

    /// Policy JSON: deserialize → serialize → deserialize is stable, and
    /// arbitrary JSON never panics the deserializer.
    #[test]
    fn policy_json_roundtrip_and_totality(grants in prop::collection::vec((prop::sample::select(vec!["*", "owner", "alice"]), prop::collection::vec(action(), 1..3), pattern_str()), 0..3), junk in "[\\[\\]{}\":a-z0-9,]{0,40}") {
        let gs: Vec<serde_json::Value> = grants.iter().map(|(to, can, on)| serde_json::json!({"to": to, "can": can, "on": on})).collect();
        let v = serde_json::json!({"grants": gs, "deny": ["/x/**"]});
        let p: Policy = serde_json::from_value(v).unwrap();
        let s = serde_json::to_value(&p).unwrap();
        let p2: Policy = serde_json::from_value(s.clone()).unwrap();
        prop_assert_eq!(serde_json::to_value(&p2).unwrap(), s);
        let _ = serde_json::from_str::<Policy>(&junk);
        let _ = serde_json::from_str::<Requirements>(&junk);
    }
}

// ---------------------------------------------------------------------------
// Findings: fail today
// ---------------------------------------------------------------------------

/// W3-1 (High): `PathPattern::match_parts` backtracks over every split of
/// every `**`, so a pattern with k `**` segments against an n-segment path
/// costs O(n^k). A policy author (anyone with a `govern` grant on a subtree,
/// or a `descendant_constraint` template) can install a pattern that every
/// node evaluates on every write under that subtree, and replay stalls
/// chain-wide. The same recursion is in `scopes_authorize`'s path glob
/// (`audit_2026_11_ws3_time_scopes.rs`, W3-2) and in `IdPattern::glob_match`.
#[test]
fn w3_1_path_pattern_matching_is_polynomial() {
    let pattern = PathPattern::new(format!("/{}/zz/", vec!["**"; 10].join("/")));
    let path = Path::parse(&format!("/{}/", vec!["a"; 24].join("/"))).unwrap();
    let t0 = Instant::now();
    let m = bounded(5, move || pattern.matches(&path, &PolicyVars::default()));
    let dt = t0.elapsed();
    assert_eq!(m, Some(false), "10×`**` against 24 segments did not finish in {dt:?}");
    assert!(dt < Duration::from_millis(200), "10×`**` against 24 segments took {dt:?}");
}

/// W3-1 (High), id half: `glob_match` tries every split for every `*`, so
/// `*a*a*a*a*a*a*a*b` against a long run of `a` is exponential.
#[test]
fn w3_1_id_pattern_matching_is_polynomial() {
    let pattern = IdPattern::new(format!("{}b", "*a".repeat(14)));
    let id = "a".repeat(40);
    let t0 = Instant::now();
    let m = bounded(5, move || pattern.matches(&id, &PolicyVars::default()));
    let dt = t0.elapsed();
    assert_eq!(m, Some(false), "14×`*` against 40 chars did not finish in {dt:?}");
    assert!(dt < Duration::from_millis(200), "14×`*` against 40 chars took {dt:?}");
}

/// W3-3 (Medium): `Requirements` (and `Policy`, `Grant`, `Restriction`) are
/// deserialized without `deny_unknown_fields`, so a restriction whose
/// condition key is misspelled (`max_sise`, `not_attestd`) is accepted as an
/// EMPTY requirement that every write satisfies — the restriction silently
/// fails open. Threat model I11: unknown condition keys reject at write time.
/// Fixed (sbo-zzx7, Q39 (a)): every policy struct is `deny_unknown_fields`.
#[test]
fn w3_3_unknown_policy_keys_are_rejected() {
    proptest!(cfg(), |(key in "[a-z_]{3,12}", val in 0u32..100)| {
        let known = ["max_size", "fields", "schema", "content_type", "require_payload_signed_by", "attested", "not_attested", "dnssec_proof"];
        prop_assume!(!known.contains(&key.as_str()));
        let v = serde_json::json!({"restrictions": [{"on": "/**", "require": {key.clone(): val}}]});
        prop_assert!(serde_json::from_value::<Policy>(v).is_err(), "restriction with unknown key {:?} accepted (fails open)", key);
        let g = serde_json::json!({"grants": [{"to": "*", "can": ["post"], "on": "/**", key.clone(): val}]});
        prop_assert!(serde_json::from_value::<Policy>(g).is_err(), "grant with unknown key {:?} accepted", key);
    });
}

/// I11: an unknown action name in `can` must reject. (Passes today: serde's
/// enum rejects it. Pinned.)
#[test]
fn unknown_action_name_rejects() {
    let v = serde_json::json!({"grants": [{"to": "*", "can": ["administer"], "on": "/**"}]});
    assert!(serde_json::from_value::<Policy>(v).is_err());
}
