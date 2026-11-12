//! Security audit 2026-11, WS3: property tests over the URI parser, the `_sbo`
//! DNS record parser, email/identity splitting and the one-identity-rule
//! decision (threat model I5, I23; WS1 leads D13, D14, D54; decision Q5).

mod audit_2026_11_ws3_support;
use audit_2026_11_ws3_support::*;

use proptest::prelude::*;
use sbo_core::dns::{parse_email, parse_record};
use sbo_core::message::Id;
use sbo_core::uri::{ChainId, SboRawUri, UriError};

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

fn chain() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["avail:turing", "avail:mainnet", "polkadot:abc123", "eip155:1"]).prop_map(String::from)
}

proptest! {
    #![proptest_config(cfg())]

    /// parse → render → parse is a fixed point for every URI the grammar
    /// admits, in both the friendly and the canonical rendering.
    #[test]
    fn uri_render_parse_is_a_fixed_point(chain in chain(), app in any::<u32>(), anchor in prop::option::of(any::<u64>()), segs in prop::collection::vec(plain_id_str(), 0..4), as_of in prop::option::of(any::<u64>()), genesis in prop::option::of("sha256:[0-9a-f]{8}")) {
        let mut s = format!("sbo+raw://{chain}:{app}");
        if let Some(a) = anchor { s.push_str(&format!("@{a}")); }
        s.push('/');
        if !segs.is_empty() { s.push_str(&segs.join("/")); s.push('/'); }
        let mut q = vec![];
        if let Some(g) = &genesis { q.push(format!("genesis={g}")); }
        if let Some(a) = as_of { q.push(format!("as_of={a}")); }
        if !q.is_empty() { s.push('?'); s.push_str(&q.join("&")); }
        let u = SboRawUri::parse(&s).unwrap();
        prop_assert_eq!(SboRawUri::parse(&u.to_uri_string()).unwrap(), u.clone());
        let c = SboRawUri::parse(&u.to_canonical_string()).unwrap();
        prop_assert_eq!(c.to_canonical_string(), u.to_canonical_string());
        prop_assert_eq!(c.chain.resolve(), u.chain.resolve());
        prop_assert_eq!(u.first_block, anchor);
        prop_assert_eq!(u.is_bare(), segs.is_empty() && q.is_empty());
        prop_assert_eq!(u.query.as_of, as_of);
    }

    /// The parser is total and rejects `sbo://` with the DNS-needed error.
    #[test]
    fn uri_parser_is_total(s in "[a-z+:/@?=&.0-9]{0,48}") {
        let _ = SboRawUri::parse(&s);
        let _ = ChainId::parse(&s);
        if s.starts_with("sbo://") {
            prop_assert!(matches!(SboRawUri::parse(&s), Err(UriError::NeedsDnsResolution(_))));
        }
    }

    /// Chain aliases resolve idempotently and `is_avail` is alias-invariant.
    #[test]
    fn chain_alias_resolution_is_idempotent(chain in chain()) {
        let c = ChainId::parse(&chain).unwrap();
        let r = c.resolve();
        prop_assert_eq!(r.resolve(), r.clone());
        prop_assert_eq!(c.is_avail(), r.is_avail());
        prop_assert_eq!(ChainId::parse(&r.display_name()).unwrap().resolve(), r);
    }

    /// `compose` inherits the anchor, drops the query, and `id()` is the last
    /// segment for ids without `:` (the `:` case is D14 below).
    #[test]
    fn compose_inherits_anchor_and_drops_query(anchor in prop::option::of(1u64..1000), segs in prop::collection::vec("[a-z0-9]{1,6}", 1..4)) {
        let base = SboRawUri::parse(&format!("sbo+raw://avail:turing:506{}/?genesis=sha256:ab", anchor.map(|a| format!("@{a}")).unwrap_or_default())).unwrap();
        let path = format!("/{}", segs.join("/"));
        let c = base.compose(&path);
        prop_assert_eq!(c.first_block, anchor);
        prop_assert!(c.query.is_empty());
        prop_assert_eq!(c.id(), Some(segs.last().unwrap().as_str()));
        prop_assert_eq!(c.creator(), None);
    }

    /// `_sbo` TXT parsing: total, requires `v=sbo1` and a BARE `repo=`;
    /// unknown keys are ignored; duplicated keys take the LAST value (pinned —
    /// browserid-ng W2-6 class; WS2 decides whether that is the rule).
    #[test]
    fn dns_record_parsing(junk in "[a-z=0-9 ]{0,24}", bare in any::<bool>(), version in prop::sample::select(vec!["sbo1", "sbo2", ""])) {
        // WS9: junk must not carry a key the record reads (last-wins would honour it).
        prop_assume!(!junk.split(' ').any(|t| t.starts_with("v=") || t.starts_with("repo=") || t.starts_with("genesis=")));
        let _ = parse_record(&junk);
        let repo = if bare { "sbo+raw://avail:turing:506@1/" } else { "sbo+raw://avail:turing:506/x/" };
        let v = if version.is_empty() { String::new() } else { format!("v={version} ") };
        let txt = format!("{v}repo={repo} {junk} genesis=sha256:aa");
        let r = parse_record(&txt);
        prop_assert_eq!(r.is_ok(), version == "sbo1" && bare, "{:?} -> {:?}", txt, r);
        let dup = "v=sbo1 repo=sbo+raw://avail:turing:1/ repo=sbo+raw://avail:turing:2/";
        prop_assert_eq!(parse_record(dup).unwrap().repo, "sbo+raw://avail:turing:2/");
    }

    /// `parse_email` splits at the FIRST `@` and requires both halves; the
    /// `check_authority` rule in `device_attribution` takes the segment
    /// between the first and second `@`. For an identity with one `@` they
    /// agree (pinned); the disagreement for several `@` is D54 below.
    #[test]
    fn email_split_rules_agree_on_one_at(local in "[a-z+.]{1,8}", domain in "[a-z.]{1,8}") {
        let e = format!("{local}@{domain}");
        prop_assert_eq!(parse_email(&e), Some((local.as_str(), domain.clone())));
        prop_assert_eq!(e.split('@').nth(1), Some(domain.as_str()));
        prop_assert!(parse_email(&local).is_none());
        let at_d = format!("@{}", domain);
        prop_assert!(parse_email(&at_d).is_none());
        let l_at = format!("{}@", local);
        prop_assert!(parse_email(&l_at).is_none());
    }
}

// ---------------------------------------------------------------------------
// Findings: fail today
// ---------------------------------------------------------------------------

/// D54 / D13 (Low → folds into Q5): the `Id` grammar admits several `@`, and
/// the two domain-extraction rules in the tree then disagree:
/// `a@mingo.place@evil` is in domain `mingo.place` for `check_authority`
/// (`split('@').nth(1)`) and in `mingo.place@evil` for `resolve_controller`
/// (`split_once`). Decided (Q5): exactly one `@`; the parser must reject.
#[test]
fn d54_identity_has_exactly_one_at() {
    proptest!(cfg(), |(a in "[a-z]{1,4}", b in "[a-z.]{1,6}", c in "[a-z.]{1,6}")| {
        let two = format!("{a}@{b}@{c}");
        // Today the two rules disagree on this very string:
        prop_assert_eq!(parse_email(&two), None);
        prop_assert!(Id::new(&two).is_err(), "Id::new({:?}) accepted", two);
    });
}

/// Q5 (decided 2026-11-04): the canonical on-chain form of an email-rooted
/// identity has a lowercase domain, and a header carrying an uppercase domain
/// is invalid, so `/u/alice@Example.com/` cannot alias `/u/alice@example.com/`.
#[test]
fn d13_uppercase_domain_is_not_a_valid_identity_reference() {
    proptest!(cfg(), |(local in "[a-z]{1,6}", domain in "[a-z]{1,5}\\.[a-z]{2,3}", flip in 0usize..8)| {
        let mut d: Vec<u8> = domain.clone().into_bytes();
        let i = flip % d.len();
        if d[i] == b'.' { return Ok(()); }
        d[i] = d[i].to_ascii_uppercase();
        let mixed = format!("{local}@{}", String::from_utf8(d).unwrap());
        prop_assert!(Id::new(&mixed).is_err(), "Id::new({:?}) accepted", mixed);
    });
}

/// D14 (Low): an object id containing `:` (legal: `role:moderator`,
/// `ed25519:…`) is mis-split by `SboRawUri::creator`/`id`, which treat the
/// part before the first `:` as a creator prefix; and the URI layer has no
/// percent-decoding, so a percent-encoded id does not round-trip to its
/// decoded form.
#[test]
fn d14_colon_ids_round_trip_through_the_uri() {
    proptest!(cfg(), |(ns in "[a-z]{1,5}", name in "[a-z]{1,5}")| {
        let id = format!("{ns}:{name}");
        prop_assert!(Id::new(&id).is_ok());
        let u = SboRawUri::parse("sbo+raw://avail:turing:506/").unwrap().compose(&format!("/things/{id}"));
        prop_assert_eq!(u.id(), Some(id.as_str()), "id() lost the namespace");
        prop_assert_eq!(u.creator(), None, "creator() invented a creator from the id");
    });
}
