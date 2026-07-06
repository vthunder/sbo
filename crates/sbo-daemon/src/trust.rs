//! Trustless fast-sync verification (State Commitment §Bootstrap and Fast-Sync).
//!
//! A fast-syncing client loads a snapshot at height `h` and computes its root
//! `R`. That snapshot came from a *serving node* over HTTP, so `R` — and the
//! manifest's `checkpoints[]`/`attestations[]` that appear to back it — are
//! **untrusted**: a malicious node can fabricate all of them and a snapshot that
//! hashes to a forged root. The only trustless anchor is the DA chain itself.
//!
//! So trust is established by *walking forward from `h`*, replaying blocks from
//! Avail DA (the daemon's own RPC, not the serving node), and observing the
//! **signed** `checkpoint.v1` / `checkpoint-attestation.v1` objects as they land
//! on chain. Each such object's signature is verified by the normal sync path
//! (`verify_message`) before it reaches here; this module then matches the
//! **signing key** against a config-pinned attestor set and, once `threshold`
//! distinct pinned keys have vouched for `(h, R)`, promotes the anchor.
//!
//! Identities are pinned by **public key**, never by name: name/owner resolution
//! runs through on-chain `/sys/names`, which during fast-sync came from the
//! untrusted snapshot — trusting it would be circular. Signature verification is
//! pure ed25519 with no on-chain dependency, so a pinned key is the only
//! non-circular anchor. (Email-rooted attestors — verifiable via the DNSSEC
//! chain without per-attestor pinning — are a separate follow-up.)

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context, Result};
use sbo_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// A client's local trust policy: a root at height `block` is accepted once
/// `threshold` distinct pinned attestor keys have signed a matching
/// `(block, state_root)` claim on chain. The checkpoint authority is not special
/// — its key is simply one of `attestors`.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub attestors: Vec<PublicKey>,
    pub threshold: usize,
}

impl TrustPolicy {
    /// A policy that gates nothing: no pinned attestors. A fast-sync client with
    /// no `[trust]` config keeps the legacy trust-the-serving-node behaviour.
    pub fn open() -> Self {
        Self { attestors: Vec::new(), threshold: 0 }
    }

    /// Whether this policy actually constrains trust (has pinned attestors and a
    /// positive threshold). An unconstrained policy never gates reads.
    pub fn is_enforcing(&self) -> bool {
        self.threshold > 0 && !self.attestors.is_empty()
    }

    /// Build from config strings of the form `ed25519:<hex>`.
    pub fn from_config(attestors: &[String], threshold: usize) -> Result<Self> {
        let keys = attestors
            .iter()
            .map(|s| PublicKey::parse(s).map_err(|e| anyhow!("invalid trust attestor key {s:?}: {e:?}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { attestors: keys, threshold })
    }
}

/// The sanctioned on-chain claim shapes we count. A pinned key's signature only
/// counts toward a threshold when it signs one of these at the anchor path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// A `checkpoint.v1` under `/sys/checkpoints/`.
    Checkpoint,
    /// A `checkpoint-attestation.v1` under `…/attestations/checkpoints/`.
    Attestation,
}

/// A signed `(block, state_root)` claim observed during walk-forward replay,
/// captured from the raw wire message (which — unlike the stored object — still
/// carries the signing key). Emitted by the sync loop for every validated
/// checkpoint/attestation object; the [`TrustGate`] filters by anchor.
#[derive(Debug, Clone)]
pub struct ObservedClaim {
    pub kind: ClaimKind,
    pub block: u64,
    pub state_root: [u8; 32],
    pub signing_key: PublicKey,
}

/// Extract a trust claim from a validated wire message, if it is a
/// `checkpoint.v1` or `checkpoint-attestation.v1` object. Returns `None` for any
/// other object. The caller must only invoke this on messages that already
/// passed signature + authorization validation, so the `signing_key` is verified.
pub fn claim_from_message(msg: &sbo_core::message::Message) -> Option<ObservedClaim> {
    let kind = match msg.content_schema.as_deref() {
        Some("checkpoint.v1") => ClaimKind::Checkpoint,
        Some("checkpoint-attestation.v1") => ClaimKind::Attestation,
        _ => return None,
    };
    let payload = msg.payload.as_ref()?;
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let block = v.get("block")?.as_u64()?;
    let root_hex = v.get("state_root")?.as_str()?;
    let root_vec = hex::decode(root_hex).ok()?;
    let state_root: [u8; 32] = root_vec.as_slice().try_into().ok()?;
    Some(ObservedClaim { kind, block, state_root, signing_key: msg.signing_key.clone() })
}

/// The anchor a fast-sync client loaded provisionally and must verify on chain
/// before its state may be trusted. Persisted across the bootstrap → start CLI
/// boundary as `pending_trust.json` in the state dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAnchor {
    pub block: u64,
    /// Hex of the snapshot's computed root `R` that attestors must agree on.
    pub state_root: String,
    /// Pinned attestor keys (`ed25519:<hex>`).
    pub attestors: Vec<String>,
    pub threshold: usize,
}

impl PendingAnchor {
    pub fn root_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.state_root).context("decode anchor root")?;
        v.as_slice().try_into().map_err(|_| anyhow!("anchor root not 32 bytes"))
    }

    pub fn policy(&self) -> Result<TrustPolicy> {
        TrustPolicy::from_config(&self.attestors, self.threshold)
    }

    fn file(state_dir: &Path) -> PathBuf {
        state_dir.join("pending_trust.json")
    }

    /// Persist to `<state_dir>/pending_trust.json`.
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        let path = Self::file(state_dir);
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Load a pending anchor if one is persisted (returns `None` if the file is
    /// absent — the common case for a full-replay node, which is never gated).
    pub fn load(state_dir: &Path) -> Result<Option<Self>> {
        let path = Self::file(state_dir);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).context("parse pending_trust.json")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!("read {}: {e}", path.display())),
        }
    }

    pub fn clear(state_dir: &Path) -> Result<()> {
        let path = Self::file(state_dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow!("remove {}: {e}", path.display())),
        }
    }
}

/// Shared handle: written by the sync loop (observe/promote), read by the HTTP
/// read handlers (gating). Mirrors the `SharedPending` pattern.
pub type SharedTrustGate = Arc<RwLock<TrustGate>>;

/// Runtime trust state for the daemon. When there is a pending anchor and the
/// policy is enforcing, reads are gated until `threshold` distinct pinned keys
/// have vouched for the anchor root on chain.
#[derive(Debug)]
pub struct TrustGate {
    /// The state dir, so promotion can delete the persisted anchor.
    state_dir: PathBuf,
    anchor: Option<PendingAnchor>,
    policy: TrustPolicy,
    /// Distinct pinned keys observed backing the anchor root, as `ed25519:<hex>`.
    backers: HashSet<String>,
    promoted: bool,
}

/// Outcome of feeding an observed claim to the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Promotion {
    /// Nothing changed (not relevant, or already promoted, or below threshold).
    Pending { backers: usize, threshold: usize },
    /// This observation crossed the threshold — the anchor is now trusted.
    Promoted { backers: usize },
    /// Not gating (no anchor, or non-enforcing policy).
    NotGating,
}

impl TrustGate {
    /// A gate that never gates — for full-replay nodes with no pending anchor.
    pub fn open(state_dir: PathBuf) -> Self {
        Self { state_dir, anchor: None, policy: TrustPolicy::open(), backers: HashSet::new(), promoted: true }
    }

    /// Construct from a loaded pending anchor. Errors only on a malformed policy.
    pub fn with_anchor(state_dir: PathBuf, anchor: PendingAnchor) -> Result<Self> {
        let policy = anchor.policy()?;
        // A non-enforcing policy (no pinned keys) can't be verified trustlessly;
        // treat as already-open rather than gating forever.
        let promoted = !policy.is_enforcing();
        Ok(Self { state_dir, anchor: Some(anchor), policy, backers: HashSet::new(), promoted })
    }

    /// True while reads must be refused (enforcing anchor not yet promoted).
    pub fn is_gated(&self) -> bool {
        !self.promoted
    }

    pub fn anchor(&self) -> Option<&PendingAnchor> {
        self.anchor.as_ref()
    }

    pub fn backer_count(&self) -> usize {
        self.backers.len()
    }

    pub fn threshold(&self) -> usize {
        self.policy.threshold
    }

    /// Feed a claim observed during replay. Counts it toward the anchor iff it is
    /// at the anchor height, agrees on the anchor root, and is signed by a pinned
    /// attestor key. Promotes (and clears the persisted anchor) at threshold.
    pub fn observe(&mut self, claim: &ObservedClaim) -> Promotion {
        if self.promoted {
            return if self.anchor.is_some() {
                Promotion::Pending { backers: self.backers.len(), threshold: self.policy.threshold }
            } else {
                Promotion::NotGating
            };
        }
        let Some(anchor) = &self.anchor else {
            return Promotion::NotGating;
        };
        let anchor_root = match anchor.root_bytes() {
            Ok(r) => r,
            Err(_) => return Promotion::Pending { backers: self.backers.len(), threshold: self.policy.threshold },
        };

        // Height + root must match the anchor, and the signer must be pinned.
        let matches = claim.block == anchor.block
            && claim.state_root == anchor_root
            && self.policy.attestors.iter().any(|k| *k == claim.signing_key);
        if matches {
            self.backers.insert(claim.signing_key.to_string());
        }

        if self.backers.len() >= self.policy.threshold {
            self.promoted = true;
            // Best-effort: drop the persisted anchor so a restart is un-gated.
            let _ = PendingAnchor::clear(&self.state_dir);
            Promotion::Promoted { backers: self.backers.len() }
        } else {
            Promotion::Pending { backers: self.backers.len(), threshold: self.policy.threshold }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbo_core::crypto::SigningKey;

    fn key(seed: u8) -> PublicKey {
        SigningKey::from_bytes(&[seed; 32]).public_key()
    }

    fn anchor(block: u64, root: [u8; 32], attestors: &[PublicKey], threshold: usize) -> PendingAnchor {
        PendingAnchor {
            block,
            state_root: hex::encode(root),
            attestors: attestors.iter().map(|k| k.to_string()).collect(),
            threshold,
        }
    }

    fn claim(kind: ClaimKind, block: u64, root: [u8; 32], k: &PublicKey) -> ObservedClaim {
        ObservedClaim { kind, block, state_root: root, signing_key: k.clone() }
    }

    #[test]
    fn promotes_at_threshold_with_distinct_pinned_keys() {
        let (sys, att) = (key(1), key(2));
        let root = [7u8; 32];
        let mut gate = TrustGate::with_anchor("/tmp/x".into(), anchor(100, root, &[sys.clone(), att.clone()], 2)).unwrap();
        assert!(gate.is_gated());
        // First backer: still gated.
        assert_eq!(gate.observe(&claim(ClaimKind::Checkpoint, 100, root, &sys)), Promotion::Pending { backers: 1, threshold: 2 });
        assert!(gate.is_gated());
        // Second distinct backer: promotes.
        assert_eq!(gate.observe(&claim(ClaimKind::Attestation, 100, root, &att)), Promotion::Promoted { backers: 2 });
        assert!(!gate.is_gated());
    }

    #[test]
    fn same_key_twice_does_not_double_count() {
        let sys = key(1);
        let root = [7u8; 32];
        let mut gate = TrustGate::with_anchor("/tmp/x".into(), anchor(100, root, &[sys.clone(), key(2)], 2)).unwrap();
        gate.observe(&claim(ClaimKind::Checkpoint, 100, root, &sys));
        assert_eq!(gate.observe(&claim(ClaimKind::Attestation, 100, root, &sys)), Promotion::Pending { backers: 1, threshold: 2 });
        assert!(gate.is_gated());
    }

    #[test]
    fn unpinned_key_never_counts() {
        let sys = key(1);
        let attacker = key(99);
        let root = [7u8; 32];
        let mut gate = TrustGate::with_anchor("/tmp/x".into(), anchor(100, root, &[sys.clone()], 1)).unwrap();
        assert_eq!(gate.observe(&claim(ClaimKind::Attestation, 100, root, &attacker)), Promotion::Pending { backers: 0, threshold: 1 });
        assert!(gate.is_gated());
    }

    #[test]
    fn wrong_root_does_not_count() {
        let sys = key(1);
        let root = [7u8; 32];
        let forged = [8u8; 32];
        let mut gate = TrustGate::with_anchor("/tmp/x".into(), anchor(100, root, &[sys.clone()], 1)).unwrap();
        assert_eq!(gate.observe(&claim(ClaimKind::Checkpoint, 100, forged, &sys)), Promotion::Pending { backers: 0, threshold: 1 });
        assert!(gate.is_gated());
    }

    #[test]
    fn wrong_block_does_not_count() {
        let sys = key(1);
        let root = [7u8; 32];
        let mut gate = TrustGate::with_anchor("/tmp/x".into(), anchor(100, root, &[sys.clone()], 1)).unwrap();
        assert_eq!(gate.observe(&claim(ClaimKind::Checkpoint, 101, root, &sys)), Promotion::Pending { backers: 0, threshold: 1 });
        assert!(gate.is_gated());
    }

    fn checkpoint_msg(schema: &str, block: u64, root: [u8; 32], signer: &SigningKey) -> sbo_core::message::Message {
        use sbo_core::crypto::{ContentHash, Signature};
        use sbo_core::message::{Action, Id, Message, ObjectType, Path};
        let payload = serde_json::to_vec(&serde_json::json!({
            "block": block,
            "state_root": hex::encode(root),
        }))
        .unwrap();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/checkpoints/").unwrap(),
            id: Id::new(&format!("block-{block}")).unwrap(),
            object_type: ObjectType::Object,
            signing_key: signer.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("application/json".into()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some(schema.into()),
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
        };
        msg.sign(signer);
        msg
    }

    #[test]
    fn claim_extracted_from_checkpoint_message_carries_signing_key() {
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let root = [9u8; 32];
        let msg = checkpoint_msg("checkpoint.v1", 4242, root, &signer);
        let claim = claim_from_message(&msg).expect("checkpoint.v1 yields a claim");
        assert_eq!(claim.kind, ClaimKind::Checkpoint);
        assert_eq!(claim.block, 4242);
        assert_eq!(claim.state_root, root);
        assert_eq!(claim.signing_key, signer.public_key());

        // And it drives a gate to promotion end-to-end.
        let mut gate = TrustGate::with_anchor("/tmp/x".into(), anchor(4242, root, &[signer.public_key()], 1)).unwrap();
        assert_eq!(gate.observe(&claim), Promotion::Promoted { backers: 1 });
    }

    #[test]
    fn non_claim_message_is_ignored() {
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let msg = checkpoint_msg("some-other.v1", 1, [0u8; 32], &signer);
        assert!(claim_from_message(&msg).is_none());
    }

    #[test]
    fn non_enforcing_policy_is_open() {
        let root = [7u8; 32];
        let gate = TrustGate::with_anchor("/tmp/x".into(), anchor(100, root, &[], 0)).unwrap();
        assert!(!gate.is_gated());
    }
}
