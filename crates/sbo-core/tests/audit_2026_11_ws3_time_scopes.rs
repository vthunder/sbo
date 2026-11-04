//! Security audit 2026-11, WS3: property tests over time arithmetic (HLC,
//! last-writer-wins, attestation windows, the attribution window
//! intersection and the authoring-instant clock) and over warrant scope
//! narrowing (threat model I19, I22, I24, I25, I26; WS1 leads D22, D28).

mod audit_2026_11_ws3_support;

use proptest::prelude::*;
use sbo_core::attribution::{check_domain_binding, AttributionError, TrustAnchors};
use sbo_core::authorize::{audience_identifies_db, scopes_authorize};
use sbo_core::browserid_core::device::{AccessCert, AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
use sbo_core::browserid_core::{Assertion, KeyPair};
use sbo_core::device_attribution::{effective_author, verify_device_attribution_with_provider_keys};
use sbo_core::hlc::{lww_wins, Hlc, LwwKey, DEFAULT_MAX_AUTHORING_LAG_MS, DEFAULT_SKEW_TOLERANCE_MS};
use sbo_core::schema::{parse_attestation, parse_collection, validate_collection, Attestation};
use sbo_core::uri::SboRawUri;
use std::time::{Duration, Instant};

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

// ---------------------------------------------------------------------------
// HLC and LWW
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    /// `Hlc::parse` ∘ `to_wire` is the identity; parse rejects everything that
    /// is not `<non-negative decimal>.<non-negative decimal>`.
    #[test]
    fn hlc_wire_roundtrip(physical in 0i64..=i64::MAX, counter in any::<u64>()) {
        let h = Hlc { physical, counter };
        let w = h.to_wire();
        prop_assert_eq!(Hlc::parse(&w).unwrap(), h);
    }

    #[test]
    fn hlc_parse_rejects_non_canonical(s in "[-+0-9a-z.]{0,16}") {
        let ok = Hlc::parse(&s).is_ok();
        let canonical = s.split_once('.').is_some_and(|(p, c)| {
            !c.contains('.') && p.parse::<i64>().is_ok_and(|v| v >= 0) && c.parse::<u64>().is_ok()
        });
        prop_assert_eq!(ok, canonical, "{:?}", s);
    }

    /// `within_bound` is exactly `t_b − W ≤ physical ≤ t_b + ε` for sane
    /// (non-overflowing) inputs.
    #[test]
    fn hlc_bound_is_the_spec_interval(physical in 0i64..1 << 50, t_b in 0i64..1 << 50, w in 0i64..1 << 40, eps in 0i64..1 << 40) {
        let h = Hlc { physical, counter: 0 };
        prop_assert_eq!(h.within_bound(t_b, w, eps), physical >= t_b - w && physical <= t_b + eps);
    }

    /// The LWW key is a strict total order: antisymmetric, transitive, and a
    /// replayed duplicate never wins (I26).
    #[test]
    fn lww_is_a_strict_total_order(a in (0i64..4, 0u64..3, 0u8..3, 0u8..3), b in (0i64..4, 0u64..3, 0u8..3, 0u8..3), c in (0i64..4, 0u64..3, 0u8..3, 0u8..3)) {
        let signers = ["s0", "s1", "s2"];
        let hashes = [[0u8; 32], [1u8; 32], [2u8; 32]];
        let key = |t: &(i64, u64, u8, u8)| LwwKey { hlc: Hlc { physical: t.0, counter: t.1 }, signer: signers[t.2 as usize], object_hash: &hashes[t.3 as usize] };
        let (ka, kb, kc) = (key(&a), key(&b), key(&c));
        prop_assert!(!(lww_wins(ka, kb) && lww_wins(kb, ka)));
        if a == b { prop_assert!(!lww_wins(ka, kb)); } else { prop_assert!(lww_wins(ka, kb) || lww_wins(kb, ka)); }
        if lww_wins(ka, kb) && lww_wins(kb, kc) { prop_assert!(lww_wins(ka, kc)); }
    }

    /// Attestation freshness: in force iff `issued_at ≤ t < expires`; an
    /// attestation without `expires` never self-expires.
    #[test]
    fn attestation_in_force_interval(issued in -1000i64..1000, len in 0i64..1000, t in -2000i64..2000, open in any::<bool>()) {
        let expires = if open { None } else { Some(issued + len) };
        let att = parse_attestation(serde_json::json!({"subject": "s", "type": "x", "value": 1, "issued_at": issued, "expires": expires}).to_string().as_bytes()).unwrap();
        let expect = issued <= t && expires.map_or(true, |e| t < e);
        prop_assert_eq!(att.is_in_force(t), expect);
        let _: &Attestation = &att;
    }

    /// Domain self-cert binding: the inclusion time must lie inside the RRSIG
    /// window (inclusive both ends) and the key must match in either encoding.
    #[test]
    fn domain_binding_window_is_inclusive(inception in 0i64..1000, len in 0i64..1000, t in -100i64..2100, hex_form in any::<bool>()) {
        let kp = KeyPair::generate();
        let pk = kp.public_key();
        let key = if hex_form { format!("ed25519:{}", hex::encode(pk.as_bytes())) } else { pk.to_base64() };
        let r = check_domain_binding(&key, &pk, inception, inception + len, t);
        let inside = t >= inception && t <= inception + len;
        prop_assert_eq!(r.is_ok(), inside);
        let is_window_err = matches!(r, Err(AttributionError::EvidenceWindowMismatch { .. }));
        if !inside { prop_assert!(is_window_err); }
        // Wrong key, inside the window: KeyMismatch.
        let other = KeyPair::generate().public_key();
        let is_key_err = matches!(check_domain_binding(&key, &other, inception, inception + len, inception), Err(AttributionError::KeyMismatch));
        prop_assert!(is_key_err);
    }
}

// ---------------------------------------------------------------------------
// Scope narrowing (I19) and the effective author (I22)
// ---------------------------------------------------------------------------

fn dim_value() -> impl Strategy<Value = String> {
    "[a-z]{1,4}"
}

/// Reference for `scopes_authorize`: OR within a dimension, AND across;
/// `sign:sbo:<a>` ≡ `action:<a>`; `as:` is ignored; anything else rejects.
fn reference_scopes(scopes: &[String], action: &str, path: &str, schema: Option<&str>) -> bool {
    let (mut acts, mut paths, mut schemas) = (vec![], vec![], vec![]);
    for s in scopes {
        match s.split_once(':') {
            Some(("action", v)) => acts.push(v.to_string()),
            Some(("sign", v)) => match v.strip_prefix("sbo:") { Some(a) => acts.push(a.to_string()), None => return false },
            Some(("path", v)) => paths.push(v.to_string()),
            Some(("schema", v)) => schemas.push(v.to_string()),
            Some(("as", _)) => {}
            _ => return false,
        }
    }
    (acts.is_empty() || acts.iter().any(|a| a == action))
        && (paths.is_empty() || paths.iter().any(|p| p.trim_matches('/') == path.trim_matches('/')))
        && (schemas.is_empty() || schema.is_some_and(|s| schemas.iter().any(|x| x == s)))
}

proptest! {
    #![proptest_config(cfg())]

    /// `scopes_authorize` agrees with the reference on literal (glob-free)
    /// scopes; unknown dimensions and unknown `sign:` kinds fail closed.
    #[test]
    fn scopes_are_or_within_and_across(
        scopes in prop::collection::vec((prop::sample::select(vec!["action", "sign", "path", "schema", "as", "zzz"]), dim_value()), 0..5),
        action in dim_value(), path in dim_value(), schema in prop::option::of(dim_value()), sign_sbo in any::<bool>(),
    ) {
        let scopes: Vec<String> = scopes.into_iter().map(|(d, v)| match d {
            "sign" if sign_sbo => format!("sign:sbo:{v}"),
            "path" => format!("path:/{v}/"),
            d => format!("{d}:{v}"),
        }).collect();
        let p = format!("/{path}/");
        prop_assert_eq!(scopes_authorize(&scopes, &action, &p, schema.as_deref()), reference_scopes(&scopes, &action, &p, schema.as_deref()), "{:?}", scopes);
    }

    /// Adding a scope in a NEW dimension never widens: if the write was not
    /// authorized before, it is not authorized after (scopes only narrow).
    #[test]
    fn adding_a_scope_never_widens(base in prop::collection::vec((prop::sample::select(vec!["action", "path", "schema"]), dim_value()), 0..4), extra_dim in prop::sample::select(vec!["action", "path", "schema"]), extra in dim_value(), action in dim_value(), path in dim_value(), schema in prop::option::of(dim_value())) {
        let mk = |d: &str, v: &str| if d == "path" { format!("path:/{v}/") } else { format!("{d}:{v}") };
        let base: Vec<String> = base.iter().map(|(d, v)| mk(d, v)).collect();
        let p = format!("/{path}/");
        if base.iter().any(|s| s.starts_with(&format!("{extra_dim}:"))) { return Ok(()); }
        let before = scopes_authorize(&base, &action, &p, schema.as_deref());
        let mut after = base.clone();
        after.push(mk(extra_dim, &extra));
        let after_ok = scopes_authorize(&after, &action, &p, schema.as_deref());
        prop_assert!(!(after_ok && !before), "adding {:?} widened {:?}", extra, base);
    }

    /// `effective_author`: no `as:` ⇒ grantee; exactly one `as:<grantor>` with
    /// a `path:` scope ⇒ grantor; any other `as:` shape rejects.
    #[test]
    fn effective_author_rules(grantor in "[a-c]@x\\.test", grantee in "[d-f]\\+bot@x\\.test", who in prop::sample::select(vec!["grantor", "grantee", "other@y.test"]), n_as in 0usize..3, has_path in any::<bool>()) {
        let who = match who { "grantor" => grantor.clone(), "grantee" => grantee.clone(), o => o.to_string() };
        let mut scopes: Vec<String> = (0..n_as).map(|_| format!("as:{who}")).collect();
        if has_path { scopes.push("path:/u/**".into()); }
        let r = effective_author(&grantor, &grantee, &scopes);
        match n_as {
            0 => prop_assert_eq!(r.unwrap(), grantee),
            1 if who == grantor && has_path => prop_assert_eq!(r.unwrap(), grantor),
            _ => { let is_as_err = matches!(r, Err(AttributionError::InvalidAsScope(_))); prop_assert!(is_as_err); }
        }
    }

    /// Audience rule (I18): only a bare `sbo+raw://` reference with the same
    /// `chain:appId` identifies the database; `sbo://` never does; an anchor
    /// or `?genesis=` in the audience must match when present.
    #[test]
    fn audience_identifies_exactly_this_db(app in 1u32..1000, other in 1u32..1000, anchor in prop::option::of(1u64..100), aud_anchor in prop::option::of(1u64..100), genesis_matches in prop::option::of(any::<bool>()), with_path in any::<bool>()) {
        let db = SboRawUri::parse(&format!("sbo+raw://avail:turing:{app}{}/", anchor.map(|a| format!("@{a}")).unwrap_or_default())).unwrap();
        let g = "sha256:aa";
        let mut aud = format!("sbo+raw://avail:turing:{other}{}/", aud_anchor.map(|a| format!("@{a}")).unwrap_or_default());
        if with_path { aud.push_str("x/"); }
        if let Some(m) = genesis_matches { aud.push_str(if m { "?genesis=sha256:aa" } else { "?genesis=sha256:bb" }); }
        let expect = other == app && !with_path
            && aud_anchor.map_or(true, |a| anchor == Some(a))
            && genesis_matches.map_or(true, |m| m);
        prop_assert_eq!(audience_identifies_db(&aud, &db, Some(g)), expect, "{}", aud);
        prop_assert!(!audience_identifies_db(&aud.replacen("sbo+raw://", "sbo://", 1), &db, Some(g)));
    }
}

// ---------------------------------------------------------------------------
// Device-presentation clock: windows and the authoring instant (I16, Q9)
// ---------------------------------------------------------------------------

const IDP: &str = "x.test";
const EMAIL: &str = "alice@x.test";
const AUD: &str = "sbo+raw://avail:turing:506/";

/// A valid presentation whose assertion lives `[now, now + assertion_secs]`
/// and whose certs live for a day around `now`.
/// `AccessPresentation` is not `Clone`; re-parse its encoding.
fn reparse(p: &AccessPresentation) -> AccessPresentation {
    AccessPresentation::parse(&p.encode()).unwrap()
}

fn presentation(now: i64, assertion_secs: i64) -> (AccessPresentation, KeyPair, String) {
    let idp = KeyPair::generate();
    let access = KeyPair::generate();
    let config = KeyPair::generate();
    let day = chrono::Duration::days(1);
    let _ = now;
    let access_cert = AccessCert::create(IDP, EMAIL, Holder::new("h").unwrap(), &access.public_key(), day, &idp, None).unwrap();
    let config_cert = DeviceCert::create(IDP, &config.public_key(), Purpose::Authorization, Holder::new("h").unwrap(), vec![EMAIL.into()], day, &idp, None).unwrap();
    let warrant = Warrant::create(EMAIL, EMAIL, HolderMatcher::new("h").unwrap(), AUD, vec!["action:post".into()], day, &config, None).unwrap();
    let assertion = Assertion::create(AUD, chrono::Duration::seconds(assertion_secs), &access).unwrap();
    let key = format!("ed25519:{}", hex::encode(access.public_key().as_bytes()));
    (AccessPresentation { access_cert, assertion, warrant, config_cert }, idp, key)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// The attribution window is the intersection of the access-cert window
    /// and every DNSSEC window; inclusion outside any DNSSEC window rejects;
    /// an empty intersection rejects.
    #[test]
    fn attribution_window_is_the_intersection(lo in -600i64..600, len in 0i64..1200, t_off in -700i64..1900) {
        let now = chrono::Utc::now().timestamp();
        let (pres, idp, key) = presentation(now, 300);
        let (inc, exp) = (now + lo, now + lo + len);
        let t = now + t_off;
        let proven = vec![(IDP.to_string(), idp.public_key(), inc, exp)];
        let r = verify_device_attribution_with_provider_keys(&key, reparse(&pres), &proven, AUD, t, Some(now), &TrustAnchors::default());
        if t < inc || t > exp {
            let is_window_err = matches!(r, Err(AttributionError::EvidenceWindowMismatch { .. }));
            prop_assert!(is_window_err, "{:?}", r.err());
        } else {
            let a = r.expect("inside window");
            let ac = pres.access_cert.claims();
            prop_assert_eq!(a.valid_from, ac.iat.max(inc));
            prop_assert_eq!(a.valid_until, ac.exp.min(exp));
            prop_assert_eq!(a.email.as_str(), EMAIL);
        }
    }

    /// The presentation's own expiries are judged at `authored_at` when given
    /// (Q9: the assertion is the one object judged at the authoring instant):
    /// an assertion expired at inclusion but live at authoring verifies, and
    /// one expired at authoring does not — the clock is never the wall clock.
    #[test]
    fn expiries_are_judged_at_the_authoring_instant(assertion_secs in 60i64..600, lag in 0i64..1200) {
        let now = chrono::Utc::now().timestamp();
        let (pres, idp, key) = presentation(now, assertion_secs);
        let proven = vec![(IDP.to_string(), idp.public_key(), now - 86_400, now + 86_400)];
        let inclusion = now + lag;
        let authored = now;
        let r_authored = verify_device_attribution_with_provider_keys(&key, reparse(&pres), &proven, AUD, inclusion, Some(authored), &TrustAnchors::default());
        prop_assert!(r_authored.is_ok(), "{:?}", r_authored.err());
        let r_inclusion = verify_device_attribution_with_provider_keys(&key, reparse(&pres), &proven, AUD, inclusion, None, &TrustAnchors::default());
        // browserid-core applies a small skew; treat anything past the assertion
        // lifetime plus that skew as "must reject".
        if lag > assertion_secs + 120 {
            prop_assert!(r_inclusion.is_err(), "assertion {}s old accepted at inclusion", lag);
        }
        let r_late = verify_device_attribution_with_provider_keys(&key, pres, &proven, AUD, inclusion, Some(now + assertion_secs + 300), &TrustAnchors::default());
        prop_assert!(r_late.is_err());
    }
}

// ---------------------------------------------------------------------------
// Findings: fail today
// ---------------------------------------------------------------------------

/// W3-2 (High): `scopes_authorize`'s path glob has the same exponential
/// backtracking as `PathPattern` (W3-1), but here the pattern is WARRANT
/// authored — any user's wallet signs scope strings — and it is evaluated at
/// the submit gate and on every replay of the write. One warrant with
/// `path:/**/**/**/**/**/**/**/**/**/**/x` stalls every node that validates
/// a write under it.
#[test]
#[ignore] // AUDIT-2026-11 W3-2: fails today — warrant path-scope matching is exponential in the number of `**`
fn w3_2_scope_path_glob_is_polynomial() {
    let scope = format!("path:/{}/zz/", vec!["**"; 10].join("/"));
    let path = format!("/{}/", vec!["a"; 24].join("/"));
    let t0 = Instant::now();
    let ok = scopes_authorize(&[scope], "post", &path, None);
    let dt = t0.elapsed();
    assert!(!ok);
    assert!(dt < Duration::from_millis(200), "10×`**` scope against 24 segments took {dt:?}");
}

/// I24 / D22 (Medium): `Hlc::within_bound` uses unchecked `t_b − W` and
/// `t_b + ε`. With a hostile `W` from a collection `_config`
/// (`max_authoring_lag_s`, any non-negative i64, multiplied by 1000 with
/// saturation) the subtraction overflows for a large inclusion time, and in
/// any case the bound becomes vacuous. The decided rule (Q9) caps `W` at a
/// protocol maximum; the arithmetic must be checked.
#[test]
#[ignore] // AUDIT-2026-11 I24: fails today — HLC bound arithmetic is unchecked (overflow) and W is unbounded
fn i24_hlc_bound_arithmetic_is_checked() {
    proptest!(cfg(), |(t_b in any::<i64>(), w in any::<i64>(), eps in any::<i64>(), physical in any::<i64>())| {
        // Must not panic for any inputs (debug builds panic on overflow today).
        let r = std::panic::catch_unwind(|| Hlc { physical, counter: 0 }.within_bound(t_b, w, eps));
        prop_assert!(r.is_ok(), "within_bound panicked for t_b={} w={} eps={}", t_b, w, eps);
    });
}

/// I25 / Q9 (Medium): `collection.v1` accepts any non-negative
/// `max_authoring_lag_s`, so a `_config` with `W = i64::MAX` makes the
/// authoring bound vacuous and lets a write resurrect any expired credential
/// (the presentation is judged at the claimed authoring instant). The spec
/// decision is a protocol maximum (reference 24 h).
#[test]
#[ignore] // AUDIT-2026-11 D22: fails today — W (max_authoring_lag_s) has no protocol maximum
fn d22_max_authoring_lag_has_a_protocol_maximum() {
    const PROTOCOL_MAX_S: i64 = 24 * 3600;
    proptest!(cfg(), |(lag in (PROTOCOL_MAX_S + 1)..=i64::MAX)| {
        let payload = serde_json::json!({"max_authoring_lag_s": lag}).to_string().into_bytes();
        let key = audit_2026_11_ws3_support::key_from_seed(1);
        let mut msg = audit_2026_11_ws3_support::signed("/c/", "_config", payload.clone(), &key);
        msg.content_schema = Some("collection.v1".into());
        prop_assert!(validate_collection(&msg).is_err(), "W = {} s accepted", lag);
        let _ = parse_collection(&payload);
    });
}

/// Observation for the ledger (no decision yet, see decisions doc Q22): a
/// warrant with an EMPTY scope list authorizes every action on every path.
/// Pinned as today's behaviour so a change is deliberate.
#[test]
fn empty_scopes_authorize_everything_today() {
    assert!(scopes_authorize(&[], "delete", "/sys/policies/", Some("policy.v2")));
}

#[test]
fn defaults_are_the_spec_reference_values() {
    assert_eq!(DEFAULT_SKEW_TOLERANCE_MS, 5 * 60 * 1000);
    assert_eq!(DEFAULT_MAX_AUTHORING_LAG_MS, 5 * 60 * 1000);
}
