//! Fast-sync client bootstrap (State Commitment §Bootstrap and Fast-Sync).
//!
//! Fetch a snapshot from a serving node, verify it reconstructs a root, and
//! load it into a state DB — reaching a recent height without replaying from
//! genesis. **The serving node is never a trust root** (audit 2026-11 D26/D27,
//! Q12 (a)): a checkpoint root counts only when a `checkpoint.v1` object
//! **signed by a pinned key** is read and verified — either carried in the
//! manifest (and re-verified here by signature) or observed on the DA chain
//! during walk-forward replay ([`crate::trust`]). The checkpoint authority is
//! not a name: it is simply one of the pinned public keys in the client's
//! [`TrustPolicy`] (D34).
//!
//! Three outcomes, in order of preference:
//! - [`RootTrust::SignedCheckpoints`]: the manifest carried signed checkpoint
//!   objects for the chosen height and `threshold` distinct pinned keys verified
//!   — trusted immediately, no gating.
//! - [`RootTrust::Provisional`]: the snapshot was loaded against its own
//!   computed root only; the caller persists a [`crate::trust::PendingAnchor`]
//!   and reads stay gated until the walk-forward observes enough pinned claims.
//! - [`RootTrust::ServingNode`]: the node's own advertised root, only through
//!   [`bootstrap_trust_serving_node`] (explicit `--trust-serving-node`).

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;

use sbo_core::state::{StateDb, StoredObject};

use crate::http::SyncPointsView;
use crate::snapshot;
use crate::trust::{claim_from_message, ClaimKind, ObservedClaim};

/// The one trust policy, shared with the walk-forward gate: pinned attestor
/// **public keys** and a threshold. There is no name-based authority (D34).
pub use crate::trust::TrustPolicy;

/// How the root a snapshot was verified against was obtained — i.e. what the
/// bootstrap ultimately trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootTrust {
    /// `backers` distinct pinned keys signed `checkpoint.v1` objects for this
    /// `(block, root)`, carried in the manifest and re-verified by signature.
    SignedCheckpoints { backers: usize },
    /// Loaded against its own computed root only; NOT trusted until the
    /// walk-forward observes `threshold` pinned claims (reads gated meanwhile).
    Provisional,
    /// The serving node's advertised root, trusted explicitly by the operator.
    ServingNode,
}

/// Count how many distinct pinned keys in `policy` back `(block, root)` among
/// `claims` — signed `checkpoint.v1` / `checkpoint-attestation.v1` objects whose
/// signatures were already verified by the caller. Returns the distinct backer
/// count, or `None` if below `threshold`. A non-enforcing policy (no pinned
/// keys or threshold 0) backs nothing: with no signature there is no trust.
pub fn evaluate_trust(
    policy: &TrustPolicy,
    block: u64,
    checkpoint_root: &str,
    claims: &[ObservedClaim],
) -> Option<usize> {
    use std::collections::HashSet;
    if !policy.is_enforcing() {
        return None;
    }
    let root = crate::trust::parse_state_root(checkpoint_root)?;
    let mut backers: HashSet<String> = HashSet::new();
    for c in claims {
        if c.block == block && c.state_root == root && policy.attestors.iter().any(|k| *k == c.signing_key) {
            backers.insert(c.signing_key.to_string());
        }
    }
    (backers.len() >= policy.threshold).then_some(backers.len())
}

/// The signed claims a manifest carries: each `checkpoints[].wire` is parsed,
/// its signature verified, and accepted as a claim only if it is a
/// `checkpoint.v1` at `/sys/checkpoints/<id>` signed by a pinned key. Entries
/// without a wire, or that fail any check, yield nothing — a bare
/// `(block, state_root)` in the manifest is never a claim.
pub fn verified_manifest_claims(manifest: &SyncPointsView, policy: &TrustPolicy) -> Vec<ObservedClaim> {
    let mut out = Vec::new();
    for cp in &manifest.checkpoints {
        let Some(wire_b64) = cp.wire.as_deref() else { continue };
        let Ok(wire) = base64::engine::general_purpose::STANDARD.decode(wire_b64) else { continue };
        let Ok(msg) = sbo_core::wire::parse(&wire) else { continue };
        if sbo_core::message::verify_message(&msg).is_err() {
            continue;
        }
        if msg.path.to_string() != "/sys/checkpoints/" || msg.id.as_str() != cp.id {
            continue;
        }
        let Some(claim) = claim_from_message(&msg) else { continue };
        if claim.kind != ClaimKind::Checkpoint || claim.block != cp.block {
            continue;
        }
        if !policy.attestors.iter().any(|k| *k == claim.signing_key) {
            continue;
        }
        out.push(claim);
    }
    out
}

#[derive(Debug)]
pub struct BootstrapResult {
    pub block: u64,
    pub state_root: [u8; 32],
    pub object_count: usize,
    pub trust: RootTrust,
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    crate::trust::parse_state_root(s)
        .ok_or_else(|| anyhow!("state root {s:?} is not sha256:<hex> / 32-byte hex"))
}

/// Verify `objects` reconstruct `trusted_root`, then load them into `db`. The
/// verification (rebuild the trie → compare root) happens BEFORE any write, so a
/// mismatched/forged snapshot never touches the DB.
pub fn verify_and_load(
    db: &StateDb,
    objects: &[StoredObject],
    trusted_root: [u8; 32],
) -> Result<()> {
    verify_and_load_payload(
        db,
        &snapshot::SnapshotPayload { objects: objects.to_vec(), policy_versions: Vec::new() },
        trusted_root,
    )
}

/// Verify a full snapshot payload reconstructs `trusted_root`, then load it:
/// objects into the object CF, the derived policy index rebuilt from the loaded
/// `policy.v2` objects, and the still-pinned historical policy versions + their
/// pin refcounts (P2, cf mingo-cy17) so the fast-synced node can authorize
/// writes under a pinned child.
///
/// Pinned policy versions are **reconstructed from covered objects** (audit
/// 2026-11 D27, Q12 (a)): an entry `(hash, _)` is loaded only from a snapshot
/// object (hence covered by the verified root) whose `content_hash` is that
/// hash, parsed from that object's own payload; the policy value the payload
/// carries is never trusted. An entry no covered object backs is dropped (a
/// pin whose version is no longer in state cannot be verified from a snapshot
/// and is left for a full replay).
pub fn verify_and_load_payload(
    db: &StateDb,
    payload: &snapshot::SnapshotPayload,
    trusted_root: [u8; 32],
) -> Result<()> {
    let objects = &payload.objects;
    let root = snapshot::compute_snapshot_root(objects);
    if root != trusted_root {
        return Err(anyhow!(
            "snapshot root {} does not match trusted root {} — refusing to load",
            hex::encode(root),
            hex::encode(trusted_root)
        ));
    }

    use std::collections::HashMap;
    let mut versions: HashMap<String, sbo_core::policy::Policy> = HashMap::new();
    for (hash, _untrusted) in &payload.policy_versions {
        let covered = objects
            .iter()
            .find(|o| o.content_schema.as_deref() == Some("policy.v2") && o.content_hash.to_string() == *hash);
        let Some(obj) = covered else {
            tracing::warn!("snapshot policy version {hash} is not backed by a covered object — dropped");
            continue;
        };
        let policy: sbo_core::policy::Policy = serde_json::from_slice(&obj.payload)
            .map_err(|e| anyhow!("covered policy object {}/{} does not parse: {e}", obj.path, obj.id.as_str()))?;
        db.put_policy_version(hash, &policy)
            .map_err(|e| anyhow!("put_policy_version: {e}"))?;
        versions.insert(hash.clone(), policy);
    }

    for o in objects {
        db.put_object(o).map_err(|e| anyhow!("put_object: {e}"))?;
        // Rebuild the derived policy index from head policy objects (the policies
        // CF is not part of the trie-committed object set).
        if o.content_schema.as_deref() == Some("policy.v2") {
            if let Ok(policy) = serde_json::from_slice::<sbo_core::policy::Policy>(&o.payload) {
                let ch = o.content_hash.to_string();
                db.put_policy_at(&o.path, &policy, &ch, o.block_number)
                    .map_err(|e| anyhow!("put_policy_at: {e}"))?;
            }
        }
    }

    // Rebuild pin refcounts by scanning the loaded head policy objects' pins.
    for o in objects {
        if o.content_schema.as_deref() != Some("policy.v2") {
            continue;
        }
        if let Ok(policy) = serde_json::from_slice::<sbo_core::policy::Policy>(&o.payload) {
            if let Some(pin) = policy.pin {
                if let Some(version) = versions.get(&pin.hash) {
                    db.pin_incref(&pin.hash, version)
                        .map_err(|e| anyhow!("pin_incref: {e}"))?;
                }
            }
        }
    }
    Ok(())
}

/// Cap on a fetched sync-point manifest body.
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
/// Cap on a fetched (compressed) snapshot body.
const MAX_SNAPSHOT_GZ_BYTES: usize = 16 * 1024 * 1024;

/// The bootstrap fetch client (W5-5): no redirects — a serving node must
/// answer where the operator pointed, never bounce the bootstrapper to
/// another host — and a short timeout.
fn fetch_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("bootstrap http client")
}

/// Refuse a node URL whose hostname resolves to a non-global address unless
/// the operator named that address explicitly (a literal IP or `localhost`):
/// a local dev node is a legitimate target, a DNS name quietly pointing at a
/// metadata or internal service is not.
async fn check_node_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("parse {url}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("node url {url}: scheme must be http or https"));
    }
    let hostname = parsed
        .host_str()
        .ok_or_else(|| anyhow!("node url {url} has no host"))?
        .to_string();
    let literal = hostname.trim_start_matches('[').trim_end_matches(']');
    if literal.parse::<std::net::IpAddr>().is_ok() || hostname.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addrs = tokio::net::lookup_host((hostname.as_str(), port))
        .await
        .with_context(|| format!("resolve node host {hostname}"))?;
    let mut any = false;
    for a in addrs {
        any = true;
        if !crate::status::is_global_ip(a.ip()) {
            return Err(anyhow!(
                "node host {hostname} resolves to non-global address {}; refusing",
                a.ip()
            ));
        }
    }
    if !any {
        return Err(anyhow!("node host {hostname} did not resolve"));
    }
    Ok(())
}

async fn fetch_capped(url: &str, cap: usize) -> Result<Vec<u8>> {
    check_node_url(url).await?;
    let resp = fetch_client()?
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("GET {url} -> {}", resp.status()));
    }
    crate::status::read_capped(resp, cap)
        .await
        .map_err(|e| anyhow!("read {url}: {e}"))
}

/// Fetch the sync-point manifest from a serving node.
pub async fn fetch_manifest(node_url: &str) -> Result<SyncPointsView> {
    let url = format!("{}/v1/sync-points", node_url.trim_end_matches('/'));
    let body = fetch_capped(&url, MAX_MANIFEST_BYTES).await?;
    serde_json::from_slice::<SyncPointsView>(&body).with_context(|| format!("decode {url}"))
}

/// Download + decompress the snapshot at `block` into its full payload.
/// The inflate is capped at `uncompressed_cap` (the manifest's advertised
/// `uncompressed_bytes`), itself clamped to [`snapshot::MAX_SNAPSHOT_BYTES`].
pub async fn fetch_snapshot_capped(
    node_url: &str,
    block: u64,
    uncompressed_cap: usize,
) -> Result<snapshot::SnapshotPayload> {
    let url = format!("{}/v1/snapshot?block={}", node_url.trim_end_matches('/'), block);
    let gz = fetch_capped(&url, MAX_SNAPSHOT_GZ_BYTES).await?;
    snapshot::decode_snapshot_payload_capped(&gz, uncompressed_cap).context("decode snapshot")
}

/// [`fetch_snapshot_capped`] at the hard ceiling.
pub async fn fetch_snapshot(node_url: &str, block: u64) -> Result<snapshot::SnapshotPayload> {
    fetch_snapshot_capped(node_url, block, snapshot::MAX_SNAPSHOT_BYTES).await
}

/// Bootstrap under a key-pinned [`TrustPolicy`] (must be enforcing). Prefers
/// the **freshest snapshot whose height is backed by `threshold` pinned keys'
/// signed checkpoints carried in the manifest** (§Checkpoint Attestations —
/// freshest already-attested; trusted immediately). Otherwise loads the
/// freshest snapshot **provisionally**: verified only against its own computed
/// root, returned as [`RootTrust::Provisional`] for the caller to persist as a
/// pending anchor that the on-chain walk-forward must confirm before reads
/// are served. The manifest's roots are hints, never trust.
pub async fn bootstrap_with_policy(
    db: &StateDb,
    node_url: &str,
    policy: &TrustPolicy,
) -> Result<BootstrapResult> {
    if !policy.is_enforcing() {
        return Err(anyhow!(
            "fast-sync needs a key-pinned trust policy ([trust] attestors + threshold); \
             to trust the serving node's own root explicitly, pass --trust-serving-node"
        ));
    }
    let manifest = fetch_manifest(node_url).await?;
    if manifest.snapshots.is_empty() {
        return Err(anyhow!("node advertises no snapshots"));
    }

    // Signed checkpoints the manifest carries, verified here (signature + pinned key).
    let claims = verified_manifest_claims(&manifest, policy);

    // Snapshots are newest-first; take the freshest one whose checkpoint root is
    // backed by enough pinned keys.
    let mut chosen: Option<(u64, String, usize)> = None;
    for snap in &manifest.snapshots {
        let Some(cp) = manifest.checkpoints.iter().find(|c| c.block == snap.block) else {
            continue;
        };
        if let Some(backers) = evaluate_trust(policy, snap.block, &cp.state_root, &claims) {
            chosen = Some((snap.block, cp.state_root.clone(), backers));
            break;
        }
    }

    if let Some((block, root_hex, backers)) = chosen {
        let trusted_root = hex_to_32(&root_hex)?;
        let payload = fetch_snapshot(node_url, block).await?;
        let object_count = payload.objects.len();
        verify_and_load_payload(db, &payload, trusted_root)?;
        return Ok(BootstrapResult { block, state_root: trusted_root, object_count, trust: RootTrust::SignedCheckpoints { backers } });
    }

    // Provisional: the freshest snapshot (prefer one a checkpoint is listed for,
    // so the walk-forward is likely to meet on-chain claims for it), verified
    // against the root computed from its own bytes. Nothing is trusted yet.
    let with_checkpoint = |block: u64| manifest.checkpoints.iter().any(|c| c.block == block);
    let snap = manifest
        .snapshots
        .iter()
        .find(|s| with_checkpoint(s.block))
        .unwrap_or(&manifest.snapshots[0]);
    let block = snap.block;
    let payload = fetch_snapshot(node_url, block).await?;
    let computed = snapshot::compute_snapshot_root(&payload.objects);
    let object_count = payload.objects.len();
    verify_and_load_payload(db, &payload, computed)?;
    Ok(BootstrapResult { block, state_root: computed, object_count, trust: RootTrust::Provisional })
}

/// Trust-the-serving-node bootstrap: adopt the node's freshest advertised
/// snapshot root as-is. Only for an operator who explicitly chose to trust that
/// node (`--trust-serving-node`); never the default.
pub async fn bootstrap_trust_serving_node(db: &StateDb, node_url: &str) -> Result<BootstrapResult> {
    let manifest = fetch_manifest(node_url).await?;
    let snap = manifest.snapshots.first().ok_or_else(|| anyhow!("node advertises no snapshots"))?;
    let trusted_root = hex_to_32(&snap.state_root)?;
    let payload = fetch_snapshot(node_url, snap.block).await?;
    let object_count = payload.objects.len();
    verify_and_load_payload(db, &payload, trusted_root)?;
    Ok(BootstrapResult { block: snap.block, state_root: trusted_root, object_count, trust: RootTrust::ServingNode })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbo_core::crypto::{PublicKey, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn policy(keys: &[&SigningKey], threshold: usize) -> TrustPolicy {
        TrustPolicy { attestors: keys.iter().map(|k| k.public_key()).collect::<Vec<PublicKey>>(), threshold }
    }

    fn claim(block: u64, root: [u8; 32], k: &SigningKey) -> ObservedClaim {
        ObservedClaim { kind: ClaimKind::Checkpoint, block, state_root: root, signing_key: k.public_key() }
    }

    // D26: with no signed claim nothing backs a root — not under the default
    // (open) policy, not under a pinned one.
    #[test]
    fn nothing_backs_a_root_without_a_signed_claim() {
        let root = hex::encode([7u8; 32]);
        assert_eq!(evaluate_trust(&TrustPolicy::default(), 100, &root, &[]), None);
        assert_eq!(evaluate_trust(&policy(&[&key(1)], 1), 100, &root, &[]), None);
    }

    // Only pinned keys count, only on the same (block, root), each once.
    #[test]
    fn threshold_counts_only_pinned_agreeing_keys() {
        let (a, b, mallory) = (key(1), key(2), key(9));
        let root = [7u8; 32];
        let hexroot = hex::encode(root);
        let p = policy(&[&a, &b], 2);
        assert_eq!(evaluate_trust(&p, 100, &hexroot, &[claim(100, root, &a), claim(100, root, &b)]), Some(2));
        assert_eq!(evaluate_trust(&p, 100, &hexroot, &[claim(100, root, &a)]), None);
        assert_eq!(evaluate_trust(&p, 100, &hexroot, &[claim(100, root, &a), claim(100, root, &a)]), None);
        assert_eq!(evaluate_trust(&p, 100, &hexroot, &[claim(100, root, &a), claim(100, [8u8; 32], &b)]), None);
        assert_eq!(evaluate_trust(&p, 100, &hexroot, &[claim(100, root, &a), claim(99, root, &b)]), None);
        assert_eq!(evaluate_trust(&p, 100, &hexroot, &[claim(100, root, &a), claim(100, root, &mallory)]), None);
        // A `sha256:`-prefixed root hex (checkpoint object convention) is accepted.
        assert_eq!(evaluate_trust(&policy(&[&a], 1), 100, &format!("sha256:{hexroot}"), &[claim(100, root, &a)]), Some(1));
    }

    // Bootstrap's core: a snapshot loads only if it reconstructs the trusted root,
    // and a wrong root is refused before any write.
    #[test]
    fn verify_and_load_accepts_matching_rejects_forged() {
        let src = tempfile::tempdir().unwrap();
        let src_db = StateDb::open(src.path()).unwrap();
        for (path, creator, id, hash) in [
            ("/communities/cooks/", "sys@mingo.place", "community", [7u8; 32]),
            ("/u/dan@mingo.place/", "dan@mingo.place", "profile", [8u8; 32]),
        ] {
            src_db
                .put_object(&StoredObject {
                    path: sbo_core::message::Path::parse(path).unwrap(),
                    id: sbo_core::message::Id::new(id).unwrap(),
                    creator: sbo_core::message::Id::new(creator).unwrap(),
                    owner: sbo_core::message::Id::new(creator).unwrap(),
                    content_type: "application/json".into(),
                    content_hash: sbo_core::crypto::ContentHash::sha256(b"{}"),
                    payload: b"{}".to_vec(),
                    policy_ref: None, related: None,
                    content_schema: Some("x.v1".into()),
                    owner_ref: None,
                    block_number: 5,
                    object_hash: hash,
                    hlc: None,
                    prev: None,
                })
                .unwrap();
        }
        let root = src_db.compute_trie_state_root().unwrap();
        let objects = src_db.list_objects_by_path_prefix("/").unwrap();

        // Fresh target DB, correct root → loads, root matches, objects present.
        let dst = tempfile::tempdir().unwrap();
        let dst_db = StateDb::open(dst.path()).unwrap();
        verify_and_load(&dst_db, &objects, root).unwrap();
        assert_eq!(dst_db.compute_trie_state_root().unwrap(), root);
        assert_eq!(dst_db.list_objects_by_path_prefix("/").unwrap().len(), objects.len());

        // Wrong root → refused, and (since verify precedes writes) nothing loaded.
        let dst2 = tempfile::tempdir().unwrap();
        let dst2_db = StateDb::open(dst2.path()).unwrap();
        assert!(verify_and_load(&dst2_db, &objects, [0u8; 32]).is_err());
        assert!(dst2_db.list_objects_by_path_prefix("/").unwrap().is_empty());
    }

    // D27: a policy version loads only from a covered object with that content
    // hash, parsed from the object's payload — not from the payload's claim.
    #[test]
    fn policy_versions_are_reconstructed_from_covered_objects() {
        let honest = br#"{"grants":[{"to":"owner","can":["update"],"on":"/c/**"}]}"#;
        let obj = StoredObject {
            path: sbo_core::message::Path::parse("/c/").unwrap(),
            id: sbo_core::message::Id::new("root").unwrap(),
            creator: sbo_core::message::Id::new("sys").unwrap(),
            owner: sbo_core::message::Id::new("sys").unwrap(),
            content_type: "application/json".into(),
            content_hash: sbo_core::crypto::ContentHash::sha256(honest),
            payload: honest.to_vec(),
            policy_ref: None, related: None,
            content_schema: Some("policy.v2".into()),
            owner_ref: None,
            block_number: 5,
            object_hash: [3u8; 32],
            hlc: None,
            prev: None,
        };
        let hash = obj.content_hash.to_string();
        let objects = vec![obj];
        let root = snapshot::compute_snapshot_root(&objects);
        let forged: sbo_core::policy::Policy =
            serde_json::from_value(serde_json::json!({"grants": [{"to": "*", "can": ["*"], "on": "/**"}]})).unwrap();
        let payload = snapshot::SnapshotPayload {
            objects,
            policy_versions: vec![(hash.clone(), forged.clone()), ("sha256:not-the-hash".into(), forged.clone())],
        };
        let dst = tempfile::tempdir().unwrap();
        let db = StateDb::open(dst.path()).unwrap();
        verify_and_load_payload(&db, &payload, root).unwrap();
        // The covered hash loads the OBJECT's policy, not the forged claim.
        let loaded = db.get_policy_version(&hash).unwrap().unwrap();
        let expected: sbo_core::policy::Policy = serde_json::from_slice(honest).unwrap();
        assert_eq!(serde_json::to_value(&loaded).unwrap(), serde_json::to_value(&expected).unwrap());
        assert_ne!(serde_json::to_value(&loaded).unwrap(), serde_json::to_value(&forged).unwrap());
        assert!(db.get_policy_version("sha256:not-the-hash").unwrap().is_none());
    }
}
