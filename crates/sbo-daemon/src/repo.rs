//! Repository management
//!
//! Handles the set of followed SBO repositories.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use sbo_core::uri::{ChainId, AppId, SboRawUri};

/// A followed repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    /// Unique identifier (hash of URI)
    pub id: String,
    /// The SBO URI
    pub uri: SboRawUri,
    /// Display URI (may be sbo:// DNS-based or sbo+raw://)
    pub display_uri: String,
    /// Local filesystem path
    pub path: PathBuf,
    /// Last synced block number
    pub head: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Last DNS check timestamp (None if never checked, or sbo+raw://)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_checked_at: Option<u64>,
    /// Expected genesis hash (`sha256:...`) from the `_sbo` record's `genesis=` field
    /// or a `?genesis=` URI selector. When set, the daemon verifies the reconstructed
    /// genesis against it once the genesis block is processed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_genesis: Option<String>,
}

impl Repo {
    /// Create a new repo with optional starting block
    pub fn new(display_uri: String, uri: SboRawUri, path: PathBuf, from_block: Option<u64>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let id = Self::compute_id(&uri);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // head is set to from_block - 1 so syncing starts AT from_block
        // (sync processes blocks from head+1 onwards)
        let head = from_block.map(|b| b.saturating_sub(1)).unwrap_or(0);

        // Set dns_checked_at to now if display_uri is sbo://, None for sbo+raw://
        let dns_checked_at = if display_uri.starts_with("sbo://") {
            Some(now)
        } else {
            None
        };

        Self {
            id,
            uri,
            display_uri,
            path,
            head,
            created_at: now,
            dns_checked_at,
            expected_genesis: None,
        }
    }

    /// Verify reconstructed genesis-batch wire bytes against `expected_genesis`.
    /// No-op (Ok) when no expected hash is set. Returns the mismatch detail otherwise.
    pub fn verify_genesis(&self, genesis_wire: &[u8]) -> Result<(), String> {
        let Some(expected) = self.expected_genesis.as_deref() else {
            return Ok(());
        };
        let actual = sbo_core::genesis_hash_from_wire(genesis_wire)
            .map_err(|e| format!("cannot parse genesis batch: {e}"))?
            .to_string();
        if actual == expected {
            Ok(())
        } else {
            Err(format!("genesis hash mismatch: expected {expected}, got {actual}"))
        }
    }

    fn compute_id(uri: &SboRawUri) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(uri.to_string().as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }

    /// Get the state database for this repo
    pub fn state_db(&self) -> crate::Result<std::sync::Arc<sbo_core::state::StateDb>> {
        let state_dir = crate::repo_dir_for_uri(&self.uri.to_string()).join("state");
        crate::shared_state_db(&state_dir)
    }
}

/// Manages the set of followed repositories
pub struct RepoManager {
    repos: HashMap<String, Repo>,
    index_path: PathBuf,
}

impl RepoManager {
    /// Load repos from index file
    pub fn load(index_path: PathBuf) -> crate::Result<Self> {
        let repos = if index_path.exists() {
            let content = std::fs::read_to_string(&index_path)?;
            let list: Vec<Repo> = serde_json::from_str(&content)
                .map_err(|e| crate::DaemonError::Repo(format!("Failed to parse repos index: {}", e)))?;
            list.into_iter().map(|r| (r.id.clone(), r)).collect()
        } else {
            HashMap::new()
        };

        Ok(Self {
            repos,
            index_path,
        })
    }

    /// Save repos to index file
    pub fn save(&self) -> crate::Result<()> {
        let list: Vec<&Repo> = self.repos.values().collect();
        let content = serde_json::to_string_pretty(&list)
            .map_err(|e| crate::DaemonError::Repo(format!("Failed to serialize repos: {}", e)))?;

        if let Some(parent) = self.index_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.index_path, content)?;
        Ok(())
    }

    /// Add a new repo with optional starting block
    pub fn add(&mut self, display_uri: String, uri: SboRawUri, path: PathBuf, from_block: Option<u64>) -> crate::Result<&Repo> {
        // Create repo directory first (needed for canonicalization)
        std::fs::create_dir_all(&path)?;

        // Canonicalize path so ./foo and /full/path/to/foo are treated the same
        let canonical_path = path.canonicalize().map_err(|e| {
            crate::DaemonError::Repo(format!("Cannot canonicalize path {}: {}", path.display(), e))
        })?;

        // Check if path is already used
        for repo in self.repos.values() {
            if repo.path == canonical_path {
                return Err(crate::DaemonError::Repo(format!(
                    "Path already used by repo {}: {}",
                    repo.uri.to_string(),
                    canonical_path.display()
                )));
            }
        }

        let repo = Repo::new(display_uri, uri.clone(), canonical_path, from_block);
        let id = repo.id.clone();

        // Create repo metadata directory using sanitized URI
        let repo_dir = crate::repo_dir_for_uri(&uri.to_string());
        std::fs::create_dir_all(&repo_dir)?;

        // Write repo config
        let config_path = repo_dir.join("config.json");
        let config_content = serde_json::to_string_pretty(&repo)
            .map_err(|e| crate::DaemonError::Repo(format!("Failed to serialize repo config: {}", e)))?;
        std::fs::write(config_path, config_content)?;

        self.repos.insert(id.clone(), repo);
        self.save()?;

        Ok(self.repos.get(&id).unwrap())
    }

    /// Record the expected genesis hash for a repo (from the `_sbo` record / `?genesis=`),
    /// to be verified once the genesis block is processed.
    pub fn set_expected_genesis(&mut self, id: &str, genesis: Option<String>) -> crate::Result<()> {
        if genesis.is_none() {
            return Ok(());
        }
        if let Some(repo) = self.repos.get_mut(id) {
            repo.expected_genesis = genesis;
            self.save()?;
        }
        Ok(())
    }

    /// Remove a repo by path
    pub fn remove(&mut self, path: &Path) -> crate::Result<Repo> {
        // Canonicalize path for consistent lookup (stored paths are canonical)
        let canonical = path.canonicalize().map_err(|e| {
            crate::DaemonError::Repo(format!("Cannot canonicalize path {}: {}", path.display(), e))
        })?;

        let id = self
            .repos
            .iter()
            .find(|(_, r)| r.path == canonical)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| crate::DaemonError::Repo(format!("No repo at path: {}", canonical.display())))?;

        let repo = self.repos.remove(&id).unwrap();

        // Remove repo directory (includes config.json and state/)
        let repo_dir = crate::repo_dir_for_uri(&repo.uri.to_string());
        if repo_dir.exists() {
            tracing::info!("Removing repo directory at {}", repo_dir.display());
            std::fs::remove_dir_all(&repo_dir)?;
        }

        self.save()?;
        Ok(repo)
    }

    /// Remove a repo by URI
    pub fn remove_by_uri(&mut self, uri: &str) -> crate::Result<Repo> {
        // Parse and normalize the URI
        let parsed = SboRawUri::parse(uri)?;
        let normalized = parsed.to_string();

        let id = self
            .repos
            .iter()
            .find(|(_, r)| r.uri.to_string() == normalized)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| crate::DaemonError::Repo(format!("No repo with URI: {}", uri)))?;

        let repo = self.repos.remove(&id).unwrap();

        // Remove repo directory (includes config.json and state/)
        let repo_dir = crate::repo_dir_for_uri(&repo.uri.to_string());
        if repo_dir.exists() {
            tracing::info!("Removing repo directory at {}", repo_dir.display());
            std::fs::remove_dir_all(&repo_dir)?;
        }

        self.save()?;
        Ok(repo)
    }

    /// List all repos
    pub fn list(&self) -> impl Iterator<Item = &Repo> {
        self.repos.values()
    }

    /// Get repo by path
    pub fn get_by_path(&self, path: &Path) -> Option<&Repo> {
        self.repos.values().find(|r| r.path == path)
    }

    /// Find repo by path (alternative name for consistency with plan)
    pub fn find_by_path(&self, path: &Path) -> Option<&Repo> {
        self.get_by_path(path)
    }

    /// Get repo by path (mutable)
    pub fn get_by_path_mut(&mut self, path: &Path) -> Option<&mut Repo> {
        self.repos.values_mut().find(|r| r.path == path)
    }

    /// Get repos by app_id
    pub fn get_by_app_id(&self, app_id: u32) -> Vec<&Repo> {
        self.repos
            .values()
            .filter(|r| r.uri.app_id.0 == app_id)
            .collect()
    }

    /// Update repo head and save
    pub fn update_head(&mut self, path: &Path, head: u64) -> crate::Result<()> {
        // Find the repo and get its ID and URI first
        let repo_info = self
            .repos
            .values()
            .find(|r| r.path == path)
            .map(|r| (r.id.clone(), r.uri.to_string()));

        if let Some((id, uri)) = repo_info {
            // Now we can mutate
            if let Some(repo) = self.repos.get_mut(&id) {
                repo.head = head;
            }

            // Update metadata file using URI-based path
            let repo_dir = crate::repo_dir_for_uri(&uri);
            let head_path = repo_dir.join("head");
            std::fs::write(head_path, head.to_string())?;

            self.save()?;
        }
        Ok(())
    }

    /// Get all unique app_ids being followed
    pub fn followed_app_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.repos.values().map(|r| r.uri.app_id.0).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Update a repo's resolved URI (for DNS relink)
    pub fn update_uri(&mut self, id: &str, display_uri: String, new_uri: SboRawUri) -> crate::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let repo = self.repos.get_mut(id)
            .ok_or_else(|| crate::DaemonError::Repo(format!("Repo not found: {}", id)))?;

        // A relink only warrants a full re-sync if it points at a *different*
        // chain/path. If the resolved URI differs only by the mutable
        // `@firstBlock` anchor (DNS records often omit it), it's the same synced
        // chain — keep our head so we don't re-backfill from genesis (mingo-stho).
        let same_identity = repo.uri.to_identity_string() == new_uri.to_identity_string();

        let mut new_uri = new_uri;
        // Preserve the genesis anchor if the relink dropped it — it's part of our
        // synced identity and is used to seed from the correct first block.
        if new_uri.first_block.is_none() {
            new_uri.first_block = repo.uri.first_block;
        }

        repo.display_uri = display_uri;
        repo.uri = new_uri;
        if !same_identity {
            repo.head = 0; // Different chain — re-sync from scratch
        }
        repo.dns_checked_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_with_expected(expected: Option<String>) -> Repo {
        let uri = SboRawUri::parse("sbo+raw://avail:turing:506@1/").unwrap();
        let mut r = Repo::new("sbo+raw://avail:turing:506@1/".into(), uri, PathBuf::from("/tmp/x"), Some(1));
        r.expected_genesis = expected;
        r
    }

    #[test]
    fn verify_genesis_noop_when_unset() {
        assert!(repo_with_expected(None).verify_genesis(b"anything").is_ok());
    }

    #[test]
    fn verify_genesis_matches_and_mismatches() {
        // Build a tiny genesis batch and its true hash.
        use sbo_core::crypto::{ContentHash, Signature, SigningKey};
        use sbo_core::message::{Action, Id, Message, ObjectType, Path};
        let key = SigningKey::generate();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/test/").unwrap(),
            id: Id::new("a").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("text/plain".into()),
            content_hash: Some(ContentHash::sha256(b"hi")),
            payload: Some(b"hi".to_vec()),
            owner: None, creator: None, content_encoding: None, content_schema: None,
            policy_ref: None, related: None, hlc: None, prev: None,
            auth_cert: None, auth_evidence: None, auth_warrant: None,
        };
        msg.sign(&key);
        let wire = sbo_core::wire::serialize(&msg);
        let true_hash = sbo_core::genesis_hash_from_wire(&wire).unwrap().to_string();

        assert!(repo_with_expected(Some(true_hash)).verify_genesis(&wire).is_ok());
        let err = repo_with_expected(Some("sha256:deadbeef".into()))
            .verify_genesis(&wire)
            .unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn test_parse_sbo_uri_with_alias() {
        // Test with sbo+raw:// (correct format)
        let uri = SboRawUri::parse("sbo+raw://avail:turing:13/").unwrap();
        assert_eq!(uri.chain.namespace, "avail");
        assert_eq!(uri.chain.reference, "turing");
        assert_eq!(uri.app_id, AppId(13));
        assert!(uri.path.is_none());

        // Verify alias resolution
        let resolved = uri.chain.resolve();
        assert_eq!(resolved.namespace, "polkadot");
        assert_eq!(resolved.reference, "d3d2f3a3495dc597434a99d7d449ebad");
    }

    #[test]
    fn test_sbo_dns_uri_requires_resolution() {
        // sbo:// URIs are DNS-based and require resolution - they should not parse directly
        let err = SboRawUri::parse("sbo://myapp.com/path").unwrap_err();
        assert!(matches!(err, sbo_core::uri::UriError::NeedsDnsResolution(_)));
    }

    #[test]
    fn test_parse_sbo_uri_with_caip2() {
        let uri = SboRawUri::parse("sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:42/nft/").unwrap();
        assert_eq!(uri.chain.namespace, "polkadot");
        assert_eq!(uri.chain.reference, "d3d2f3a3495dc597434a99d7d449ebad");
        assert_eq!(uri.app_id, AppId(42));
        assert_eq!(uri.path, Some("/nft/".to_string()));
    }

    #[test]
    fn test_sbo_uri_roundtrip() {
        // Alias should display as alias with sbo+raw://
        let uri = SboRawUri::parse("sbo+raw://avail:turing:13/").unwrap();
        assert_eq!(uri.to_string(), "sbo+raw://avail:turing:13/");

        // Full CAIP-2 for known chain should display as alias
        let uri = SboRawUri::parse("sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:42/").unwrap();
        assert_eq!(uri.to_string(), "sbo+raw://avail:turing:42/");

        // Unknown chain should display as full CAIP-2
        let uri = SboRawUri::parse("sbo+raw://eip155:1:99/").unwrap();
        assert_eq!(uri.to_string(), "sbo+raw://eip155:1:99/");
    }

    #[test]
    fn test_canonical_string() {
        let uri = SboRawUri::parse("sbo+raw://avail:turing:13/nft/").unwrap();
        assert_eq!(
            uri.to_canonical_string(),
            "sbo+raw://polkadot:d3d2f3a3495dc597434a99d7d449ebad:13/nft/"
        );
    }

    #[test]
    fn test_chain_is_avail() {
        let turing = ChainId::parse("avail:turing").unwrap();
        assert!(turing.is_avail());

        let mainnet = ChainId::parse("avail:mainnet").unwrap();
        assert!(mainnet.is_avail());

        let eth = ChainId::parse("eip155:1").unwrap();
        assert!(!eth.is_avail());
    }
}
