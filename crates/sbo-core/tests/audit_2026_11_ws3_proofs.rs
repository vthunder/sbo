//! Security audit 2026-11, WS3: property tests over the SBOP / SBOQ proof
//! message parsers, the JWT identity objects, and the genesis hash
//! (threat model I4; WS1 lead D40).

mod audit_2026_11_ws3_support;
use audit_2026_11_ws3_support::*;

use proptest::prelude::*;
use sbo_core::crypto::SigningKey;
use sbo_core::jwt;
use sbo_core::proof::{parse_sbop, parse_sboq, serialize_sbop, serialize_sboq, SbopMessage, SboqMessage};
use sbo_core::{genesis_hash, genesis_hash_from_wire, wire, TrieProof, TrieProofStep};
use std::collections::BTreeMap;

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 128, ..ProptestConfig::default() }
}

fn hash32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn steps() -> impl Strategy<Value = Vec<TrieProofStep>> {
    prop::collection::vec(
        (prop::option::of("[a-z0-9_.-]{1,6}"), prop::collection::btree_map("[a-z0-9]{1,4}", hash32(), 0..3)),
        0..4,
    )
    .prop_map(|v| v.into_iter().map(|(segment, siblings)| TrieProofStep { segment, siblings }).collect())
}

proptest! {
    #![proptest_config(cfg())]

    /// SBOP: serialize → parse recovers every field; the parser is total.
    #[test]
    fn sbop_roundtrip_and_totality(from in any::<u64>(), to in any::<u64>(), kind in "[a-z]{1,8}", receipt in prop::collection::vec(any::<u8>(), 0..200), junk in prop::collection::vec(any::<u8>(), 0..128)) {
        let m = SbopMessage { version: "0.1".into(), block_from: from, block_to: to, receipt_kind: kind.clone(), receipt_bytes: receipt.clone() };
        let p = parse_sbop(&serialize_sbop(&m)).unwrap();
        prop_assert_eq!((p.block_from, p.block_to, p.receipt_kind, p.receipt_bytes), (from, to, kind, receipt));
        let _ = parse_sbop(&junk);
        let mut pfx = b"SBOP-Version: 0.1\n".to_vec();
        pfx.extend_from_slice(&junk);
        let _ = parse_sbop(&pfx);
    }

    /// SBOQ: serialize → parse recovers headers, proof steps and the attached
    /// object; the parser is total on junk after a valid header prefix.
    #[test]
    fn sboq_roundtrip_and_totality(block in any::<u64>(), root in hash32(), oh in prop::option::of(hash32()), steps in steps(), object in prop::option::of(prop::collection::vec(any::<u8>(), 1..64)), junk in prop::collection::vec(any::<u8>(), 0..96)) {
        let proof = TrieProof { state_root: root, path_segments: steps.iter().filter_map(|s| s.segment.clone()).collect(), object_hash: oh, proof: steps.clone() };
        let m = SboqMessage { version: "0.2".into(), path: "/a/b/".into(), id: "x".into(), creator: "c".into(), block, state_root: root, object_hash: oh, trie_proof: proof, object: object.clone() };
        let bytes = serialize_sboq(&m);
        let p = parse_sboq(&bytes).unwrap();
        prop_assert_eq!(p.block, block);
        prop_assert_eq!(p.state_root, root);
        prop_assert_eq!(p.object_hash, oh);
        prop_assert_eq!(p.trie_proof.proof, steps);
        prop_assert_eq!(p.object, object);
        let _ = parse_sboq(&junk);
        let mut pfx = b"SBOQ-Version: 0.2\nPath: /\nId: x\nCreator: c\nBlock: 1\n".to_vec();
        pfx.extend_from_slice(&junk);
        let _ = parse_sboq(&pfx);
    }

    /// Genesis hash: `genesis_hash_from_wire` ≡ `genesis_hash ∘ parse_batch`,
    /// and it is order-sensitive.
    #[test]
    fn genesis_hash_is_over_the_ordered_batch(ids in prop::collection::vec(plain_id_str(), 2..4), payload in payload()) {
        let key = key_from_seed(2);
        let msgs: Vec<_> = ids.iter().map(|id| signed("/sys/", id, payload.clone(), &key)).collect();
        let batch: Vec<u8> = msgs.iter().flat_map(|m| wire::serialize(m)).collect();
        prop_assert_eq!(genesis_hash_from_wire(&batch).unwrap(), genesis_hash(&msgs));
        let mut rev = msgs.clone();
        rev.reverse();
        if ids.first() != ids.last() {
            prop_assert_ne!(genesis_hash(&rev), genesis_hash(&msgs));
        }
    }

    /// JWT identity objects: create → verify succeeds; any change to the
    /// payload or a foreign key fails; decoding is total on junk tokens.
    #[test]
    fn jwt_sign_verify(subject in "[a-z]{1,8}", domain in "[a-z]{1,6}\\.test", junk in "[A-Za-z0-9._-]{0,64}") {
        let key = SigningKey::generate();
        let tok = jwt::create_self_signed_identity(&key, &subject, None).unwrap();
        let claims = jwt::verify_self_signed_identity(&tok).unwrap();
        prop_assert_eq!(claims.sub, subject.clone());
        // Tamper with the payload segment: verification must fail.
        let mut parts: Vec<&str> = tok.split('.').collect();
        let mut p = parts[1].to_string();
        p.push('A');
        parts[1] = &p;
        prop_assert!(jwt::verify_self_signed_identity(&parts.join(".")).is_err());
        // Domain-certified: verify under the right key only.
        let dkey = SigningKey::generate();
        let dtok = jwt::create_domain_certified_identity(&dkey, &domain, &subject, &key.public_key(), None).unwrap();
        prop_assert!(jwt::verify_domain_certified_identity(&dtok, &dkey.public_key()).is_ok());
        prop_assert!(jwt::verify_domain_certified_identity(&dtok, &key.public_key()).is_err());
        let _ = jwt::decode_identity_claims(&junk);
        let _ = jwt::verify_self_signed_identity(&junk);
        let _ = jwt::verify_domain(&junk);
    }
}

// ---------------------------------------------------------------------------
// Findings: fail today
// ---------------------------------------------------------------------------

/// W3-6 (Low): the SBOP parser computes `((Receipt-Length + 2) / 3) * 4` with
/// unchecked arithmetic, so a header `Receipt-Length: 18446744073709551615`
/// panics (overflow) in a debug build and wraps in release. SBOP messages are
/// read off the chain by every light-mode node (D40 class).
#[test]
fn w3_6_sbop_huge_receipt_length_does_not_panic() {
    let img = format!("SBOP-Version: 0.1\nBlock-From: 1\nBlock-To: 2\nReceipt-Kind: k\nReceipt-Length: {}\nContent-Encoding: base64\n\nAAAA", usize::MAX - 1);
    let r = std::panic::catch_unwind(|| parse_sbop(img.as_bytes()).is_err());
    assert!(matches!(r, Ok(true)), "parse_sbop panicked or accepted an impossible length");
}

/// W3-6 (Low→Medium): the SBOQ parser computes `obj_start + Object-Length`
/// unchecked; a large `Object-Length` wraps in release so the bounds check
/// passes and the slice `data[obj_start..obj_end]` panics with
/// `obj_end < obj_start`. SBOQ messages are what an untrusted indexer serves
/// to a client asking for a proof, so a hostile indexer crashes the client.
#[test]
fn w3_6_sboq_huge_object_length_does_not_panic() {
    let mut img = format!(
        "SBOQ-Version: 0.2\nPath: /a/\nId: x\nCreator: c\nBlock: 1\nState-Root: {}\nObject-Hash: null\nProof-Format: trie\nProof-Length: 1\nObject-Length: {}\n\n",
        "00".repeat(32), usize::MAX - 10
    ).into_bytes();
    img.extend_from_slice(b"[{\"segment\":null,\"siblings\":{}}]\n");
    let r = std::panic::catch_unwind(|| parse_sboq(&img).is_err());
    assert!(matches!(r, Ok(true)), "parse_sboq panicked or accepted an impossible length");
}

/// Pinned: the SBOQ `Proof-Length` header is parsed but never checked against
/// the number of steps (the JSON array is self-delimiting), so a mismatch is
/// accepted today. Recorded as an observation, not a finding.
#[test]
fn sboq_proof_length_header_is_advisory_today() {
    let proof = TrieProof { state_root: [0; 32], path_segments: vec![], object_hash: None, proof: vec![TrieProofStep { segment: None, siblings: BTreeMap::new() }] };
    let m = SboqMessage { version: "0.2".into(), path: "/".into(), id: "x".into(), creator: "c".into(), block: 1, state_root: [0; 32], object_hash: None, trie_proof: proof, object: None };
    let img = String::from_utf8(serialize_sboq(&m)).unwrap().replace("Proof-Length: 1", "Proof-Length: 99");
    assert!(parse_sboq(img.as_bytes()).is_ok());
}

/// W3-9 (Medium): found by the `proof_parse` fuzz target. `parse_sbop` walks
/// header lines with `pos = line_end + 1`; when the image has no blank line
/// and its last line has no trailing newline, `pos` ends one past the end
/// and `&bytes[pos..]` panics. SBOP messages are read off the chain by every
/// light-mode node, so one DA submission carrying the five headers and no terminator panics the sync task of every light node.
#[test]
fn w3_9_sbop_without_blank_line_does_not_panic() {
    let img = b"SBOP-Version: 0.1\nBlock-From: 1\nBlock-To: 9\nReceipt-Kind: k\nReceipt-Length: 6";
    let r = std::panic::catch_unwind(|| parse_sbop(img).is_err());
    assert!(matches!(r, Ok(true)), "parse_sbop panicked or accepted a header-only image");
}
