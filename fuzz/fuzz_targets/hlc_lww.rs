#![no_main]
//! WS3: `Hlc::parse` ∘ `to_wire` is the identity and parse accepts exactly
//! the canonical form; the LWW key is a strict total order; the validity
//! bound is the spec interval. Bound arithmetic is exercised on |x| < 2^53
//! (I24: unchecked arithmetic overflows outside; lift with the fix).

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sbo_core::hlc::{lww_wins, Hlc, LwwKey};

#[derive(Arbitrary, Debug)]
struct Input {
    text: String,
    a: (i64, u64, u8, u8),
    b: (i64, u64, u8, u8),
    c: (i64, u64, u8, u8),
    t_b: i64,
    w: i64,
    eps: i64,
}

const LIM: i64 = 1 << 53;

fuzz_target!(|input: Input| {
    let s = &input.text;
    let parsed = Hlc::parse(s);
    let canonical = s.split_once('.').is_some_and(|(p, c)| !c.contains('.') && p.parse::<i64>().is_ok_and(|v| v >= 0) && c.parse::<u64>().is_ok());
    assert_eq!(parsed.is_ok(), canonical, "{s:?}");
    if let Ok(h) = parsed {
        assert_eq!(Hlc::parse(&h.to_wire()).unwrap(), h);
        // `+0` and leading zeros parse via i64/u64 FromStr; the wire form
        // re-renders canonically, so to_wire is idempotent even then.
        assert_eq!(Hlc::parse(&Hlc::parse(&h.to_wire()).unwrap().to_wire()).unwrap(), h);
    }
    let signers = ["s0", "s1", "s2"];
    let hashes = [[0u8; 32], [1u8; 32], [2u8; 32]];
    let key = |t: &(i64, u64, u8, u8)| LwwKey { hlc: Hlc { physical: t.0, counter: t.1 }, signer: signers[(t.2 % 3) as usize], object_hash: &hashes[(t.3 % 3) as usize] };
    let (ka, kb, kc) = (key(&input.a), key(&input.b), key(&input.c));
    assert!(!(lww_wins(ka, kb) && lww_wins(kb, ka)));
    assert_eq!(lww_wins(ka, kb) || lww_wins(kb, ka), ka != kb);
    if lww_wins(ka, kb) && lww_wins(kb, kc) { assert!(lww_wins(ka, kc)); }
    let (t_b, w, eps, phys) = (input.t_b % LIM, input.w.rem_euclid(LIM), input.eps.rem_euclid(LIM), input.a.0 % LIM);
    let h = Hlc { physical: phys, counter: 0 };
    assert_eq!(h.within_bound(t_b, w, eps), phys >= t_b - w && phys <= t_b + eps);
});
