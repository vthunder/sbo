//! Security audit 2026-11 remediation: offline DNSSEC coverage (`sbo-ospt`,
//! W6-5), the pinned `/sys/trust/dns-root` anchor (`sbo-evne`, D6/S4, Q3 (a))
//! and the monotonic `/sys/dnssec` refresh rule (`sbo-uv8a`, D33, Q16 (a)) at
//! the verifier level. Everything here runs offline:
//!
//! - `fixtures/mingo-place-browserid.rfc9102` is a real chain for
//!   `_browserid.mingo.place` captured with `sbo-capture`'s `capture_fixture`
//!   test (read-only DNS). Its RRSIG window is fixed at capture time and the
//!   tests pin an inclusion time inside it, so the file never goes stale.
//! - Synthetic chains come from `sbo_core::dnssec_fixture` (a test P-256 zone
//!   signer; `dnssec-prover` has no Ed25519, W6-2), rooted at a key the test
//!   pins as its own DNS root.

use sbo_core::attribution::{
    check_dnssec_refresh_monotonic, dnssec_proof_freshness, extract_provider_key_with_anchors,
    verify_dnssec_proof_for_domain, verify_dnssec_proof_for_domain_with_anchors, verify_domain_self_cert_with_anchors,
    AttributionError, RootKsk, TrustAnchors,
};
use sbo_core::dnssec_fixture::{browserid_txt, dns_root_v1, ChainSpec, SyntheticRoot, ZoneKey};

const MINGO_FIXTURE: &[u8] = include_bytes!("fixtures/mingo-place-browserid.rfc9102");
/// Inclusion time inside the captured fixture's RRSIG window.
const MINGO_T: i64 = 1_794_000_000;

const T0: i64 = 1_700_000_000;
const T1: i64 = 1_700_100_000;
const T2: i64 = 1_700_200_000;

fn pinned(root: &SyntheticRoot) -> TrustAnchors {
    TrustAnchors::default().with_dns_root(vec![root.root_ksk(0, None)])
}

// ───────────────────────── W6-5: the real captured chain ─────────────────────────

/// The captured mingo.place chain validates against the library's IANA anchors
/// (no pin) at an inclusion time inside its window, and binds to mingo.place only.
#[test]
fn real_mingo_place_chain_validates_offline_against_iana_root() {
    let (inception, expiration) = verify_dnssec_proof_for_domain(MINGO_FIXTURE, "mingo.place").unwrap();
    assert!(inception <= MINGO_T && MINGO_T <= expiration, "pin MINGO_T inside [{inception}, {expiration}]");
    assert!(matches!(
        verify_dnssec_proof_for_domain(MINGO_FIXTURE, "example.com"),
        Err(AttributionError::MissingProviderRecord(_))
    ));
}

/// The same real chain validates when `/sys/trust/dns-root` pins the IANA root
/// KSKs — taken from the chain's own root DNSKEY RRset, so the test does not
/// hardcode IANA key material — and fails when it pins something else.
#[test]
fn real_chain_validates_against_pinned_iana_history_only() {
    use dnssec_prover::rr::RR;
    use base64::Engine as _;
    let rrs = dnssec_prover::ser::parse_rr_stream(MINGO_FIXTURE).unwrap();
    let history: Vec<RootKsk> = rrs
        .iter()
        .filter_map(|rr| match rr {
            RR::DnsKey(k) if k.name.as_str() == "." && k.flags & 1 == 1 => Some(RootKsk {
                key_tag: k.key_tag(),
                algorithm: k.alg,
                public_key: base64::engine::general_purpose::STANDARD.encode(&k.pubkey),
                valid_from: 0,
                valid_until: None,
            }),
            _ => None,
        })
        .collect();
    assert!(!history.is_empty(), "the chain carries the root KSK set");
    let anchors = TrustAnchors::parse_dns_root(&dns_root_v1(&history)).map(|k| TrustAnchors::default().with_dns_root(k)).unwrap();
    verify_dnssec_proof_for_domain_with_anchors(MINGO_FIXTURE, "mingo.place", &anchors, Some(MINGO_T)).unwrap();

    let other = SyntheticRoot::generate();
    assert!(matches!(
        verify_dnssec_proof_for_domain_with_anchors(MINGO_FIXTURE, "mingo.place", &pinned(&other), Some(MINGO_T)),
        Err(AttributionError::EvidenceInvalid(_))
    ));
}

// ───────────────────────── D6: the pinned root is THE anchor ─────────────────────────

/// AUDIT-2026-11 D6: a chain rooted at a non-IANA key validates when that key is
/// pinned in `/sys/trust/dns-root` and is rejected when it is not.
#[test]
fn d6_non_iana_root_validates_when_pinned_and_rejects_when_not() {
    let root = SyntheticRoot::generate();
    let provider = browserid_core::KeyPair::generate();
    let chain = root.browserid_chain("example.test", &browserid_txt(&provider.public_key()), T0, T2);

    let (key, ..) = extract_provider_key_with_anchors(&chain, "example.test", &pinned(&root), Some(T1)).unwrap();
    assert_eq!(key.as_bytes(), provider.public_key().as_bytes());

    // Not pinned: the library's IANA set does not know this root.
    assert!(matches!(
        extract_provider_key_with_anchors(&chain, "example.test", &TrustAnchors::default(), Some(T1)),
        Err(AttributionError::EvidenceInvalid(_))
    ));
    // Pinned to a different root: rejected.
    let other = SyntheticRoot::generate();
    assert!(extract_provider_key_with_anchors(&chain, "example.test", &pinned(&other), Some(T1)).is_err());
    // Pinned history with no key active at the inclusion time: fail closed.
    let expired = TrustAnchors::default().with_dns_root(vec![root.root_ksk(0, Some(T0 - 1))]);
    assert!(matches!(
        extract_provider_key_with_anchors(&chain, "example.test", &expired, Some(T1)),
        Err(AttributionError::NoActiveRootAnchor(_))
    ));
}

/// AUDIT-2026-11 D6: a rollover history spans old and new evidence — each chain
/// validates only at inclusion times inside its root's activation window.
#[test]
fn d6_rollover_history_spans_old_and_new_evidence() {
    let old_root = SyntheticRoot::generate();
    let new_root = SyntheticRoot::generate();
    let provider = browserid_core::KeyPair::generate();
    let txt = browserid_txt(&provider.public_key());
    let old_chain = old_root.browserid_chain("example.test", &txt, T0, T2);
    let new_chain = new_root.browserid_chain("example.test", &txt, T0, T2);

    // Old key retired at T1, new key current from T1 on.
    let history = TrustAnchors::default()
        .with_dns_root(vec![old_root.root_ksk(0, Some(T1 - 1)), new_root.root_ksk(T1, None)]);

    let before = Some(T1 - 10);
    let after = Some(T1 + 10);
    assert!(extract_provider_key_with_anchors(&old_chain, "example.test", &history, before).is_ok());
    assert!(extract_provider_key_with_anchors(&new_chain, "example.test", &history, after).is_ok());
    assert!(extract_provider_key_with_anchors(&old_chain, "example.test", &history, after).is_err(), "retired root");
    assert!(extract_provider_key_with_anchors(&new_chain, "example.test", &history, before).is_err(), "not yet active");
}

/// AUDIT-2026-11 D6: domain self-certification (Identity Rule 4) uses the
/// pinned root too.
#[test]
fn d6_domain_self_cert_uses_pinned_root() {
    let root = SyntheticRoot::generate();
    let provider = browserid_core::KeyPair::generate();
    let chain = root.browserid_chain("example.test", &browserid_txt(&provider.public_key()), T0, T2);
    let domain_key = provider.public_key().to_base64();
    verify_domain_self_cert_with_anchors(&domain_key, &chain, "example.test", T1, &pinned(&root)).unwrap();
    assert!(verify_domain_self_cert_with_anchors(&domain_key, &chain, "example.test", T1, &TrustAnchors::default()).is_err());
    // Window is still enforced at the inclusion time.
    assert!(matches!(
        verify_domain_self_cert_with_anchors(&domain_key, &chain, "example.test", T2 + 1, &pinned(&root)),
        Err(AttributionError::EvidenceWindowMismatch { .. })
    ));
}

// ───────────────────────── D33: monotonic refresh ─────────────────────────

/// AUDIT-2026-11 D33 (Q16 (a)): a refresh may not lower the incumbent's RRSIG
/// expiration; equal or newer is fine.
#[test]
fn d33_refresh_cannot_lower_rrsig_expiration() {
    let root = SyntheticRoot::generate();
    let txt = browserid_txt(&browserid_core::KeyPair::generate().public_key());
    let anchors = pinned(&root);
    let incumbent = dnssec_proof_freshness(&root.browserid_chain("example.test", &txt, T0, T2), "example.test", &anchors, Some(T1)).unwrap();
    let older = dnssec_proof_freshness(&root.browserid_chain("example.test", &txt, T0, T2 - 1), "example.test", &anchors, Some(T1)).unwrap();
    let same = dnssec_proof_freshness(&root.browserid_chain("example.test", &txt, T0, T2), "example.test", &anchors, Some(T1)).unwrap();
    let newer = dnssec_proof_freshness(&root.browserid_chain("example.test", &txt, T0, T2 + 1), "example.test", &anchors, Some(T1)).unwrap();
    assert!(matches!(check_dnssec_refresh_monotonic(&older, &incumbent), Err(AttributionError::RefreshRollback(_))));
    check_dnssec_refresh_monotonic(&same, &incumbent).unwrap();
    check_dnssec_refresh_monotonic(&newer, &incumbent).unwrap();
}

/// AUDIT-2026-11 D33 (Q16 (a)): a proof carrying a pre-rotation DNSKEY set —
/// still inside its RRSIG window, even with a later expiration — is older than
/// the incumbent's rotated set and is rejected.
#[test]
fn d33_refresh_cannot_carry_an_older_dnskey_set() {
    let root = SyntheticRoot::generate();
    let txt = browserid_txt(&browserid_core::KeyPair::generate().public_key());
    let anchors = pinned(&root);
    // Incumbent: the zone rotated its key at T1 (DNSKEY RRset re-signed then).
    let rotated = ChainSpec::new("example.test", &txt)
        .window(T0, T2)
        .leaf_key(ZoneKey::generate("example.test."))
        .leaf_dnskey_window(T1, T2)
        .build(&root);
    let incumbent = dnssec_proof_freshness(&rotated, "example.test", &anchors, Some(T1 + 1)).unwrap();
    assert_eq!(incumbent.dnskey_inception, T1);
    // Attacker: the pre-rotation key set, signed at T0, with a LATER expiration.
    let pre_rotation = ChainSpec::new("example.test", &txt)
        .window(T0, T2 + 100)
        .leaf_key(ZoneKey::generate("example.test."))
        .leaf_dnskey_window(T0, T2 + 100)
        .build(&root);
    let stale = dnssec_proof_freshness(&pre_rotation, "example.test", &anchors, Some(T1 + 1)).unwrap();
    assert!(stale.expiration > incumbent.expiration);
    assert!(matches!(check_dnssec_refresh_monotonic(&stale, &incumbent), Err(AttributionError::RefreshRollback(_))));
    assert_ne!(stale.key_tags, incumbent.key_tags);
}
