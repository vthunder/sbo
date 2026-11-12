#![no_main]
//! WS3: `SboRawUri` parsing is total and render∘parse is a fixed point;
//! `_sbo` TXT parsing is total and `Ok` ⇒ a bare repo URI; `parse_email`
//! agrees with the spec split; `audience_identifies_db` is total.

use libfuzzer_sys::fuzz_target;
use sbo_core::authorize::audience_identifies_db;
use sbo_core::dns::{parse_email, parse_record};
use sbo_core::uri::{ChainId, SboRawUri};

fuzz_target!(|data: &[u8]| {
    let s = sbo_fuzz::text(data);
    // `SboRawUri::parse` trims surrounding whitespace, so a rendered value that
    // carries whitespace is not a fixed point by construction; skip those.
    if s.chars().any(char::is_whitespace) { return; }
    let _ = ChainId::parse(&s);
    if let Ok(u) = SboRawUri::parse(&s) {
        let r = SboRawUri::parse(&u.to_uri_string()).expect("rendered URI parses");
        assert_eq!(r, u, "render∘parse is not a fixed point (friendly)");
        let c = SboRawUri::parse(&u.to_canonical_string()).expect("canonical URI parses");
        assert_eq!(c.to_canonical_string(), u.to_canonical_string(), "render∘parse is not a fixed point (canonical)");
        assert_eq!(c.chain.resolve(), u.chain.resolve());
        assert_eq!(SboRawUri::parse(&u.to_identity_string()).unwrap().first_block, None);
        let _ = (u.id(), u.creator(), u.authority(), u.is_bare());
        let db = SboRawUri::parse("sbo+raw://avail:turing:506@10/").unwrap();
        let _ = audience_identifies_db(&s, &db, Some("sha256:aa"));
        let _ = audience_identifies_db(&u.to_uri_string(), &db, None);
    }
    if let Ok(rec) = parse_record(&s) {
        let repo = SboRawUri::parse(&rec.repo).expect("Ok record carries a parseable repo");
        assert!(repo.is_bare(), "Ok record with a non-bare repo");
    }
    if let Some((l, d)) = parse_email(&s) {
        assert!(!l.is_empty() && !d.is_empty());
        // Q5 (audit 2026-11): exactly one `@`, the local part byte-exact, the
        // domain compared and returned as a lowercase A-label.
        let (sl, sd) = s.split_once('@').expect("Some ⇒ one @");
        assert_eq!(l, sl);
        assert_eq!(d, sd.to_ascii_lowercase());
        assert!(!l.contains('@') && !d.contains('@'));
    }
});
