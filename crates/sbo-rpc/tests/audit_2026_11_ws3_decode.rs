//! Security audit 2026-11, WS3: property tests over the Avail app-data
//! decoders in `sbo-rpc` (SCALE compact integers, extrinsic unwrapping,
//! IEC 9797-1 unpadding, gzip inflation) — WS1 lead D40, D50 class.

use proptest::prelude::*;
use sbo_rpc::{decode_app_extrinsics, decode_compact, extract_data_from_encoded_extrinsic, unpad_iec_9797_1};
use std::io::Write;

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

/// Reference SCALE compact encoder for the value ranges the decoder supports.
fn encode_compact(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![(v as u8) << 2]
    } else if v < 1 << 14 {
        ((v as u16) << 2 | 0b01).to_le_bytes().to_vec()
    } else if v < 1 << 30 {
        ((v as u32) << 2 | 0b10).to_le_bytes().to_vec()
    } else {
        let bytes = v.to_le_bytes();
        let n = 8 - bytes.iter().rev().take_while(|&&b| b == 0).count();
        let mut out = vec![((n as u8 - 4) << 2) | 0b11];
        out.extend_from_slice(&bytes[..n]);
        out
    }
}

proptest! {
    #![proptest_config(cfg())]

    /// `decode_compact` inverts the reference encoder and reports the exact
    /// byte count, for every mode; junk never panics.
    #[test]
    fn compact_roundtrip_and_totality(v in any::<u64>(), junk in prop::collection::vec(any::<u8>(), 0..12)) {
        let enc = encode_compact(v);
        let (got, used) = decode_compact(&enc).expect("decodes");
        prop_assert_eq!(got as u64, v);
        prop_assert_eq!(used, enc.len());
        let _ = decode_compact(&junk);
    }

    /// Unpadding removes exactly one `0x80` and the zeros after it, or
    /// nothing when the marker is absent.
    #[test]
    fn unpad_removes_only_the_marker(data in prop::collection::vec(any::<u8>(), 0..32), zeros in 0usize..8, padded in any::<bool>()) {
        let mut buf = data.clone();
        if padded { buf.push(0x80); }
        buf.extend(std::iter::repeat(0u8).take(zeros));
        let n = unpad_iec_9797_1(&buf);
        if padded {
            prop_assert_eq!(n, data.len());
        } else {
            let stripped = { let mut i = buf.len(); while i > 0 && buf[i-1] == 0 { i -= 1; } if i > 0 && buf[i-1] == 0x80 { i - 1 } else { buf.len() } };
            prop_assert_eq!(n, stripped);
        }
    }

    /// A well-formed unsigned extrinsic `[version=0x04][pallet][call][Vec<u8>]`
    /// yields its blob; arbitrary bytes never panic any decoder.
    #[test]
    fn extrinsic_unwrap_and_totality(blob in prop::collection::vec(any::<u8>(), 0..200), junk in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assume!(!(blob.len() >= 2 && blob[0] == 0x1f && blob[1] == 0x8b));
        let mut ext = vec![0x04u8, 29, 1];
        ext.extend(encode_compact(blob.len() as u64));
        ext.extend_from_slice(&blob);
        prop_assert_eq!(extract_data_from_encoded_extrinsic(&ext), Some(blob.clone()));
        let mut outer = encode_compact(1);
        outer.extend(encode_compact(ext.len() as u64));
        outer.extend_from_slice(&ext);
        prop_assert_eq!(decode_app_extrinsics(&outer).unwrap(), vec![blob]);
        let _ = extract_data_from_encoded_extrinsic(&junk);
        let _ = decode_app_extrinsics(&junk);
    }
}

/// W3-7 (Medium): a gzip-flagged blob inside an extrinsic is inflated with
/// `read_to_end` and no cap. Avail app data is bounded (a few MiB per block)
/// but gzip's ratio is ~1000:1, so a 1 MiB submission inflates to ~1 GiB on
/// every node that syncs the app id, before any SBO parsing can reject it.
/// Expected: inflation is capped (e.g. 16 MiB) and an over-cap blob is
/// dropped as undecodable.
#[test]
fn w3_7_gzip_inflation_is_capped() {
    const CAP: usize = 16 << 20;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let chunk = vec![0u8; 1 << 20];
    for _ in 0..64 { enc.write_all(&chunk).unwrap(); } // 64 MiB of zeros
    let gz = enc.finish().unwrap();
    assert!(gz.len() < 128 << 10, "bomb should compress to under 128 KiB, got {}", gz.len());
    let mut ext = vec![0x04u8, 29, 1];
    ext.extend(encode_compact(gz.len() as u64));
    ext.extend_from_slice(&gz);
    match extract_data_from_encoded_extrinsic(&ext) {
        None => {}
        Some(out) => assert!(out.len() <= CAP, "inflated {} bytes from a {} byte blob", out.len(), gz.len()),
    }
}
