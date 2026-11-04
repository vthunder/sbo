//! Security audit 2026-11, WS3: property tests over the wire parser, the
//! serializer, the envelope signature path and the identifier grammar
//! (threat model I1, I2, I3, I4, I5, I7; WS1 leads D1, D2, D3, D21, D30).
//!
//! Tests marked `#[ignore]` with an `AUDIT-2026-11` comment FAIL today and are
//! the acceptance tests for the corresponding fix. Everything else passes and
//! pins what the audit re-verified.

mod audit_2026_11_ws3_support;
use audit_2026_11_ws3_support::*;

use proptest::prelude::*;
use sbo_core::crypto::ContentHash;
use sbo_core::message::{verify_message, Id, Path};
use sbo_core::wire;

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

// ---------------------------------------------------------------------------
// Round trips and totality (pass today)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    /// serialize → parse → serialize is the identity on the wire image, and the
    /// parsed message verifies under the key that signed it.
    #[test]
    fn serialize_parse_roundtrip_is_identity(path in path_str(), id in id_str(), payload in payload(), seed in any::<u8>()) {
        let key = key_from_seed(seed);
        let msg = signed(&path, &id, payload, &key);
        let w1 = wire::serialize(&msg);
        let parsed = wire::parse(&w1).expect("own wire parses");
        let w2 = wire::serialize(&parsed);
        prop_assert_eq!(&w1, &w2);
        prop_assert!(verify_message(&parsed).is_ok());
        prop_assert_eq!(parsed.path.to_string(), path);
        prop_assert_eq!(parsed.id.as_str(), id.as_str());
    }

    /// A batch of N serialized messages splits back into exactly N, in order,
    /// each byte-identical to its source (the splitter honours Content-Length).
    #[test]
    fn batch_split_is_exact(items in prop::collection::vec((plain_id_str(), payload(), any::<u8>()), 1..6)) {
        let mut batch = Vec::new();
        let mut wires = Vec::new();
        for (id, payload, seed) in &items {
            let w = wire::serialize(&signed("/b/", id, payload.clone(), &key_from_seed(*seed)));
            batch.extend_from_slice(&w);
            wires.push(w);
        }
        let msgs = wire::parse_batch(&batch).expect("batch parses");
        prop_assert_eq!(msgs.len(), items.len());
        for (m, w) in msgs.iter().zip(wires.iter()) {
            prop_assert_eq!(&wire::serialize(m), w);
        }
    }

    /// Arbitrary bytes never panic the parser, the batch splitter, or the
    /// header-line splitter.
    #[test]
    fn parser_is_total(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = wire::parse(&bytes);
        let _ = wire::parse_batch(&bytes);
        let _ = wire::split_message(&bytes);
    }

    /// A truncated wire image (Content-Length larger than what follows) is an
    /// error, never a panic or a short read.
    #[test]
    fn truncated_payload_rejects(payload in prop::collection::vec(any::<u8>(), 1..128), cut in 0usize..128) {
        let w = wire::serialize(&signed("/t/", "x", payload.clone(), &key_from_seed(1)));
        let (head, body) = split_wire(&w);
        let cut = cut.min(body.len().saturating_sub(1));
        let mut short = head.to_vec();
        short.push(b'\n');
        short.extend_from_slice(&body[..cut]);
        prop_assert!(wire::parse(&short).is_err());
        prop_assert!(wire::parse_batch(&short).is_err());
    }

    /// Signature path: any single-bit flip in the signed header block (not the
    /// payload — see `d1_*`) breaks verification.
    #[test]
    fn header_bit_flip_breaks_signature(id in plain_id_str(), payload in payload(), bit in 0usize..4096) {
        let key = key_from_seed(3);
        let msg = signed("/s/", &id, payload, &key);
        let w = wire::serialize(&msg);
        // Flip a bit inside a header VALUE that is part of the signing content
        // (Path/ID line), by editing the parsed message instead of raw bytes so
        // the image stays parseable.
        let mut parsed = wire::parse(&w).unwrap();
        let mut idb = parsed.id.as_str().as_bytes().to_vec();
        let i = bit % idb.len();
        // stay inside the grammar: toggle case for letters, else swap digit
        idb[i] = match idb[i] { b'a'..=b'z' => idb[i] - 32, b'A'..=b'Z' => idb[i] + 32, b'0'..=b'8' => idb[i] + 1, _ => b'0' };
        let new_id = String::from_utf8(idb).unwrap();
        if new_id == parsed.id.as_str() { return Ok(()); }
        parsed.id = Id::new(&new_id).unwrap();
        prop_assert!(verify_message(&parsed).is_err());
    }

    /// Both ed25519 wrappers (`sbo-core::crypto` and `sbo-crypto`) return the
    /// same verdict on the same (key, message, signature) — I7.
    #[test]
    fn two_ed25519_wrappers_agree(seed in any::<u8>(), msg in payload(), tamper in any::<bool>(), bit in 0usize..512) {
        let key = key_from_seed(seed);
        let mut sig = key.sign(&msg);
        if tamper {
            sig.0[bit % 64] ^= 1 << (bit % 8);
        }
        let core_pk = key.public_key();
        let core_ok = sbo_core::crypto::verify(&core_pk, &msg, &sig).is_ok();
        let new_pk = sbo_crypto::ed25519::PublicKey { bytes: core_pk.bytes };
        let new_sig = sbo_crypto::ed25519::Signature(sig.0);
        let new_ok = sbo_crypto::ed25519::verify(&new_pk, &msg, &new_sig).is_ok();
        prop_assert_eq!(core_ok, new_ok);
        prop_assert_eq!(core_ok, !tamper || core_ok);
    }

    /// A signature whose `S` half is non-canonical (high bit set ⇒ S ≥ L) is
    /// rejected by both wrappers: no S-malleability through either path.
    #[test]
    fn non_canonical_s_is_rejected_by_both(seed in any::<u8>(), msg in payload()) {
        let key = key_from_seed(seed);
        let mut sig = key.sign(&msg);
        sig.0[63] |= 0x80;
        let core_pk = key.public_key();
        prop_assert!(sbo_core::crypto::verify(&core_pk, &msg, &sig).is_err());
        let new_pk = sbo_crypto::ed25519::PublicKey { bytes: core_pk.bytes };
        prop_assert!(sbo_crypto::ed25519::verify(&new_pk, &msg, &sbo_crypto::ed25519::Signature(sig.0)).is_err());
    }

    /// Identifier grammar (core §Identifier Syntax): `sbo-core::Id` accepts
    /// exactly the documented character set and length, and `Path::parse`
    /// round-trips every path built from valid ids.
    #[test]
    fn id_grammar_and_path_roundtrip(segs in prop::collection::vec(id_str(), 1..5)) {
        for s in &segs {
            prop_assert!(Id::new(s).is_ok(), "{:?}", s);
        }
        let p = format!("/{}/", segs.join("/"));
        let parsed = Path::parse(&p).unwrap();
        prop_assert_eq!(parsed.to_string(), p);
        prop_assert_eq!(parsed.segments().len(), segs.len());
    }

    /// Characters outside the grammar reject (space, slash, unicode, control).
    #[test]
    fn id_rejects_out_of_grammar(prefix in plain_id_str(), bad in prop::sample::select(vec![' ', '/', '\u{e9}', '\n', '\0', '%', '*', '\\'])) {
        let s = format!("{prefix}{bad}");
        prop_assert!(Id::new(&s).is_err(), "{:?}", s);
    }

    /// The `sbo-types::Id` grammar is a strict subset of `sbo-core::Id`
    /// (D30: two grammars; the core one additionally admits `@ + :`). Pinned
    /// so the relationship is at least one-directional until WS2 unifies them.
    #[test]
    fn sbo_types_id_is_subset_of_core_id(s in id_str()) {
        if sbo_types::id::Id::new(&s).is_ok() {
            prop_assert!(Id::new(&s).is_ok());
        }
        if s.contains(['@', '+', ':']) {
            prop_assert!(sbo_types::id::Id::new(&s).is_err(), "sbo-types admits {:?} — grammars converged, update WS2", s);
        }
    }
}

// ---------------------------------------------------------------------------
// Findings: fail today
// ---------------------------------------------------------------------------

/// D1 (Critical): the payload is bound to the signed headers ONLY through
/// `Content-Hash`, and the parser never checks it. A signature-valid envelope
/// carrying an arbitrary swapped payload parses and verifies.
#[test]
#[ignore] // AUDIT-2026-11 D1: fails today — Content-Hash is never verified against the payload
fn d1_swapped_payload_is_rejected() {
    proptest!(cfg(), |(payload in prop::collection::vec(any::<u8>(), 1..64), flip in 0usize..64)| {
        let key = key_from_seed(9);
        let msg = signed("/d1/", "obj", payload.clone(), &key);
        let w = wire::serialize(&msg);
        let (_, body) = split_wire(&w);
        // Same signed headers (same Content-Length), one payload byte changed.
        let mut other = body.to_vec();
        let i = flip % other.len();
        other[i] ^= 0x01;
        let img = join_wire(&header_lines(&w), &other);
        match wire::parse(&img) {
            Err(_) => {}
            Ok(parsed) => {
                // The envelope signature still verifies (headers untouched), so the
                // only thing binding the payload is Content-Hash: it must match.
                prop_assert!(verify_message(&parsed).is_ok());
                let declared = parsed.content_hash.clone().unwrap();
                let actual = ContentHash::sha256(parsed.payload.as_deref().unwrap());
                prop_assert_eq!(declared, actual, "parser accepted a payload that does not hash to Content-Hash");
            }
        }
    });
}

/// D2 (High): the signature is verified over a RECONSTRUCTION of the parsed
/// fields, so a wire image with the headers in a non-canonical order parses to
/// the same message and verifies, although the signer never produced those
/// bytes and the Wire spec says non-canonical order is invalid (I2).
#[test]
#[ignore] // AUDIT-2026-11 D2: fails today — non-canonical header order is accepted
fn d2_non_canonical_header_order_is_rejected() {
    proptest!(cfg(), |(id in plain_id_str(), payload in payload(), seed in any::<u8>(), swap in (0usize..9, 0usize..9))| {
        let msg = signed("/d2/", &id, payload, &key_from_seed(seed));
        let w = wire::serialize(&msg);
        let (_, body) = split_wire(&w);
        let mut hs = header_lines(&w);
        let (a, b) = (swap.0 % hs.len(), swap.1 % hs.len());
        prop_assume!(a != b);
        hs.swap(a, b);
        let img = join_wire(&hs, body);
        prop_assert!(wire::parse(&img).is_err(), "reordered headers parsed: {:?}", hs);
    });
}

/// D2 (High): a duplicated header is accepted and the LAST value wins
/// (`HashMap` collect), so two different byte-strings share one signature.
#[test]
#[ignore] // AUDIT-2026-11 D2: fails today — duplicate headers are accepted, last wins
fn d2_duplicate_header_is_rejected() {
    proptest!(cfg(), |(id in plain_id_str(), other in plain_id_str(), payload in payload())| {
        prop_assume!(id != other);
        let msg = signed("/d2/", &id, payload, &key_from_seed(4));
        let w = wire::serialize(&msg);
        let (_, body) = split_wire(&w);
        let mut hs = header_lines(&w);
        // Insert a second ID line right after the first one.
        let pos = hs.iter().position(|(n, _)| n == "ID").unwrap();
        hs.insert(pos + 1, ("ID".into(), other.clone()));
        let img = join_wire(&hs, body);
        prop_assert!(wire::parse(&img).is_err(), "duplicate ID header parsed (last-wins)");
    });
}

/// D2 / S22: `Content-Length` is parsed with `usize::from_str`, which accepts
/// `+5` and leading zeros; the Wire spec's Encoding Rules require canonical
/// decimal integers.
#[test]
#[ignore] // AUDIT-2026-11 D2: fails today — non-canonical Content-Length accepted
fn d2_non_canonical_content_length_is_rejected() {
    proptest!(cfg(), |(payload in prop::collection::vec(any::<u8>(), 1..64), form in 0u8..3)| {
        let msg = signed("/d2/", "len", payload.clone(), &key_from_seed(5));
        let w = wire::serialize(&msg);
        let n = payload.len();
        let bad = match form { 0 => format!("+{n}"), 1 => format!("0{n}"), _ => format!("00{n}") };
        let img = set_header(&w, "Content-Length", &bad);
        prop_assert!(wire::parse(&img).is_err(), "Content-Length {:?} accepted", bad);
    });
}

/// D3 (High): headers the parser does not model (`Attestation`, `Origin`,
/// `Proof`, …) are dropped, so `serialize(parse(x)) != x` and an
/// `object_hash` taken over the re-serialization differs from the hash of the
/// received bytes (I4). The parser must either reject the unknown header or
/// preserve it; today it silently loses it.
#[test]
#[ignore] // AUDIT-2026-11 D3: fails today — unknown headers are dropped on parse
fn d3_unknown_header_survives_or_rejects() {
    proptest!(cfg(), |(id in plain_id_str(), payload in payload(), name in prop::sample::select(vec!["Attestation", "Origin", "Proof", "Proof-Type", "Registry-Path", "Object-Path"]), val in "[a-z]{1,8}")| {
        let msg = signed("/d3/", &id, payload, &key_from_seed(6));
        let w = wire::serialize(&msg);
        let (_, body) = split_wire(&w);
        let mut hs = header_lines(&w);
        let pos = hs.iter().position(|(n, _)| n == "Public-Key").unwrap();
        hs.insert(pos, (name.to_string(), val.clone()));
        let img = join_wire(&hs, body);
        match wire::parse(&img) {
            Err(_) => {}
            Ok(parsed) => prop_assert_eq!(wire::serialize(&parsed), img, "unknown header {} dropped by parse→serialize", name),
        }
    });
}

/// D21 (High): `.` and `..` are inside the identifier character set and
/// nothing rejects them, so `Path: /../../` is a valid on-chain path. The
/// daemon's filesystem mirror resolves it outside the repo directory. The core
/// spec's grammar must exclude dot-only segments (I5).
#[test]
#[ignore] // AUDIT-2026-11 D21: fails today — "." and ".." are accepted as ids / path segments
fn d21_dot_segments_are_rejected() {
    proptest!(cfg(), |(dots in 1usize..4, prefix in prop::collection::vec(plain_id_str(), 0..2))| {
        let seg = ".".repeat(dots);
        prop_assert!(Id::new(&seg).is_err(), "Id::new({:?}) accepted", seg);
        let mut segs = prefix.clone();
        segs.push(seg.clone());
        let p = format!("/{}/", segs.join("/"));
        prop_assert!(Path::parse(&p).is_err(), "Path::parse({:?}) accepted", p);
    });
}
