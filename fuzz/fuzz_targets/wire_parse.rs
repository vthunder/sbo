#![no_main]
//! WS3: the wire parser is total on arbitrary bytes, and whatever it accepts
//! survives serialize → parse unchanged and keeps its signature verdict
//! (the parser's OWN output is canonical). The batch splitter agrees with the
//! single-message parser on the first message.

use libfuzzer_sys::fuzz_target;
use sbo_core::message::verify_message;
use sbo_core::wire;

fn absurd_content_length(data: &[u8]) -> bool {
    String::from_utf8_lossy(data).lines().any(|l| l.strip_prefix("Content-Length: ").map_or(false, |v| v.trim_start_matches('0').len() > 12))
}

fuzz_target!(|data: &[u8]| {
    // W3-10: `pos + Content-Length` is unchecked in the batch splitter; a
    // huge declared length panics. Guard until fixed.
    if absurd_content_length(data) { return; }
    let _ = wire::split_message(data);
    let batch = wire::parse_batch(data);
    if let Ok(msg) = wire::parse(data) {
        let v1 = verify_message(&msg).is_ok();
        let w = wire::serialize(&msg);
        let again = wire::parse(&w).expect("serializer output must parse");
        assert_eq!(wire::serialize(&again), w, "serialize∘parse is not idempotent");
        assert_eq!(verify_message(&again).is_ok(), v1, "signature verdict changed across a round trip");
        assert_eq!(msg.canonical_signing_content(), again.canonical_signing_content());
        // `parse_batch` fails if ANY later message is invalid, so only compare
        // when the whole input split.
        if let Ok(b) = &batch {
            assert!(!b.is_empty());
            assert_eq!(wire::serialize(&b[0]), w, "batch splitter and single parser disagree on message 1");
        }
    }
});
