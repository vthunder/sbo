// One-off signed-wire builder (offline). Env:
//   SYS_KEY_FILE (ed25519:<hex seed>), PAYLOAD_FILE, OUT_FILE, HLC_MS,
//   OBJ_PATH (default /sys/policies/), OBJ_ID (default root),
//   OBJ_SCHEMA (default policy.v2), OBJ_CT (default application/json).
// Key-rooted (no Owner) — signer authorized via policy (admin grant or to:*).
use sbo_core::crypto::SigningKey;
use sbo_core::presets;

fn env(k: &str, d: &str) -> String { std::env::var(k).unwrap_or_else(|_| d.to_string()) }

fn main() {
    let key_str = std::fs::read_to_string(std::env::var("SYS_KEY_FILE").unwrap()).unwrap();
    let hex_seed = key_str.trim().strip_prefix("ed25519:").expect("ed25519: prefix");
    let seed = hex::decode(hex_seed).expect("hex seed");
    let arr: [u8; 32] = seed.try_into().expect("32-byte seed");
    let key = SigningKey::from_bytes(&arr);

    let payload = std::fs::read(std::env::var("PAYLOAD_FILE").unwrap()).unwrap();
    let hlc = format!("{}.0", std::env::var("HLC_MS").unwrap());
    let wire = presets::signed_object(
        &key,
        &env("OBJ_PATH", "/sys/policies/"),
        &env("OBJ_ID", "root"),
        &env("OBJ_SCHEMA", "policy.v2"),
        &env("OBJ_CT", "application/json"),
        payload,
        None,
        Some(&hlc),
        None,
    );
    std::fs::write(std::env::var("OUT_FILE").unwrap(), &wire).unwrap();
    let pk = key.public_key().to_string();
    eprintln!("wrote {} bytes; pubkey={}; hlc={}", wire.len(), pk, hlc);
}
