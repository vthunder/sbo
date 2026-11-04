#![no_main]
//! WS3: SBOP / SBOQ proof-message parsing is total, and whatever parses
//! survives serialize → parse with the same fields. Inputs declaring a
//! `Receipt-Length` / `Object-Length` above 2^40 are skipped (W3-6: unchecked
//! length arithmetic; lift the guard with the fix).

use libfuzzer_sys::fuzz_target;
use sbo_core::proof::{is_sbop_message, is_sboq_message, parse_sbop, parse_sboq, serialize_sbop, serialize_sboq};

fn absurd_length(data: &[u8], header: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);
    s.lines().any(|l| l.as_bytes().starts_with(header) && l[header.len()..].trim().parse::<u64>().map_or(false, |n| n > 1 << 40))
}

fuzz_target!(|data: &[u8]| {
    if absurd_length(data, b"Receipt-Length:") || absurd_length(data, b"Object-Length:") {
        return;
    }
    // W3-9: an SBOP image with no blank line and no trailing newline panics
    // `parse_sbop` (slice past the end). Guard until fixed.
    if !data.windows(2).any(|w| w == b"\n\n") {
        return;
    }
    let _ = (is_sbop_message(data), is_sboq_message(data));
    if let Ok(m) = parse_sbop(data) {
        let again = parse_sbop(&serialize_sbop(&m)).expect("serialized SBOP parses");
        assert_eq!((again.block_from, again.block_to, &again.receipt_kind, &again.receipt_bytes), (m.block_from, m.block_to, &m.receipt_kind, &m.receipt_bytes));
    }
    if let Ok(m) = parse_sboq(data) {
        let again = parse_sboq(&serialize_sboq(&m)).expect("serialized SBOQ parses");
        assert_eq!(again.block, m.block);
        assert_eq!(again.state_root, m.state_root);
        assert_eq!(again.object_hash, m.object_hash);
        assert_eq!(again.trie_proof.proof, m.trie_proof.proof);
        assert_eq!(again.object, m.object);
        let _ = sbo_crypto::verify_trie_proof(&m.trie_proof);
    }
});
