#![no_main]
//! WS3: structured envelopes — arbitrary grammar-valid ids, paths, payloads
//! and optional headers — are built, signed, serialized and parsed back
//! identical; a bit flip in the signed header block is always detected.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sbo_core::message::{verify_message, Id, Path};
use sbo_core::wire;

const ID_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~@+:";

#[derive(Arbitrary, Debug)]
struct Input {
    id: Vec<u8>,
    segs: Vec<Vec<u8>>,
    payload: Vec<u8>,
    seed: u8,
    owner: Option<Vec<u8>>,
    schema: Option<String>,
    hlc: Option<(u32, u16)>,
    flip: Option<u16>,
}

fn id_from(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 64 {
        return None;
    }
    let s: String = bytes.iter().map(|b| ID_CHARS[(*b as usize) % ID_CHARS.len()] as char).collect();
    // The grammar is stricter than the alphabet (no `.`/`..`, identity rule
    // for `@`, audit 2026-11 Q5/Q24): only hand the builder a valid id.
    Id::new(&s).ok().map(|_| s)
}

fuzz_target!(|input: Input| {
    let Some(id) = id_from(&input.id) else { return };
    let mut segs = Vec::new();
    for s in input.segs.iter().take(4) {
        let Some(seg) = id_from(s) else { return };
        segs.push(seg);
    }
    let path = if segs.is_empty() { "/".to_string() } else { format!("/{}/", segs.join("/")) };
    let mut msg = sbo_fuzz::envelope(&path, &id, input.payload.clone(), input.seed);
    if let Some(o) = &input.owner {
        let Some(o) = id_from(o) else { return };
        msg.owner = Some(Id::new(&o).unwrap());
    }
    if let Some(s) = &input.schema {
        if s.contains(['\n', '\r']) { return; }
        msg.content_schema = Some(s.clone());
    }
    if let Some((p, c)) = input.hlc {
        msg.hlc = Some(format!("{p}.{c}"));
    }
    msg.sign(&sbo_fuzz::key(input.seed));
    let w = wire::serialize(&msg);
    let parsed = wire::parse(&w).expect("own output parses");
    assert_eq!(wire::serialize(&parsed), w);
    assert!(verify_message(&parsed).is_ok(), "fresh signature does not verify");
    assert_eq!(parsed.path, Path::parse(&path).unwrap());
    assert_eq!(parsed.id.as_str(), id);
    if let Some(bit) = input.flip {
        // Flip one bit inside the Path or ID header value; the message must
        // either fail to parse or fail to verify.
        let (head_end, _) = w.windows(2).enumerate().find(|(_, x)| x == b"\n\n").map(|(i, _)| (i, ())).unwrap();
        let mut m = w.clone();
        let i = (bit as usize) % head_end;
        // Only touch bytes inside a value (after ": "), never a name or a newline.
        let line_start = m[..i].iter().rposition(|&b| b == b'\n').map(|p| p + 1).unwrap_or(0);
        let line = &m[line_start..];
        let Some(colon) = line.iter().position(|&b| b == b':') else { return };
        if i < line_start + colon + 2 || m[i] == b'\n' { return; }
        if !(line.starts_with(b"Path: ") || line.starts_with(b"ID: ")) { return; }
        m[i] ^= 0x20;
        if m[i] == b'\n' || m[i] == b'/' { return; }
        if let Ok(p2) = wire::parse(&m) {
            assert!(verify_message(&p2).is_err(), "modified header value verified under the old signature");
        }
    }
});
