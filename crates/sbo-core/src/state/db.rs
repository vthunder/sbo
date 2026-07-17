//! RocksDB state storage

use std::path::Path;
use crate::error::DbError;
use super::objects::StoredObject;
use crate::policy::Policy;

/// State database backed by RocksDB
pub struct StateDb {
    db: rocksdb::DB,
}

// Column family names
const CF_OBJECTS: &str = "objects";
const CF_BY_OWNER: &str = "by_owner";
const CF_POLICIES: &str = "policies";
const CF_NAMES: &str = "names";
const CF_META: &str = "meta";
const CF_STATE_ROOTS: &str = "state_roots";
const CF_PROOFS: &str = "proofs";
/// P2 — retained historical policy versions, keyed by content-hash
/// (`"sha256:<hex>"`). A version lives here as long as some live policy PINS it;
/// GC'd when its pin refcount reaches zero. Serves pin-aware govern resolution.
const CF_POLICY_VERSIONS: &str = "policy_versions";
/// P2 — pin refcounts, keyed by content-hash → little-endian u64.
const CF_POLICY_PINREFS: &str = "policy_pinrefs";

/// A policy indexed in the `policies` CF: the parsed policy plus the on-chain
/// content-hash and block of the version it came from. The content-hash is what
/// a child policy PINS (P2) and what creation-pin validation compares against.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyEntry {
    pub policy: Policy,
    /// The on-chain content-hash (`"sha256:<hex>"`) of this policy version.
    pub content_hash: String,
    /// Block the version was applied at (locator hint for pins).
    pub block: u64,
}

/// A verified proof stored in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProof {
    /// Block range start
    pub block_from: u64,
    /// Block range end
    pub block_to: u64,
    /// Receipt kind (composite, succinct, groth16)
    pub receipt_kind: String,
    /// The raw receipt bytes
    pub receipt_bytes: Vec<u8>,
    /// Block number where this proof was received
    pub received_at_block: u64,
    /// Whether this proof was verified
    pub verified: bool,
}

impl StateDb {
    /// Open or create the database at the given path
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            rocksdb::ColumnFamilyDescriptor::new(CF_OBJECTS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_BY_OWNER, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_POLICIES, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_NAMES, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_META, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_STATE_ROOTS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_PROOFS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_POLICY_VERSIONS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_POLICY_PINREFS, rocksdb::Options::default()),
        ];

        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| DbError::RocksDb(e.to_string()))?;

        Ok(Self { db })
    }

    /// Get the object occupying the `(path, id)` slot, if any.
    ///
    /// Object identity is globally unique on `(path, id)` (creator is an
    /// immutable attribute, not part of the key), so this is a point lookup.
    pub fn get_object(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<Option<StoredObject>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = encode_object_key(path, id);

        match self.db.get_cf(&cf, &key) {
            Ok(Some(bytes)) => {
                let obj: StoredObject = serde_json::from_slice(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(obj))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Store an object
    pub fn put_object(&self, obj: &StoredObject) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = encode_object_key(&obj.path, &obj.id);
        let value = serde_json::to_vec(obj)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        self.db.put_cf(&cf, &key, &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Delete the object occupying the `(path, id)` slot.
    pub fn delete_object(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = encode_object_key(path, id);

        self.db.delete_cf(&cf, &key)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Collect all stored objects whose encoded key begins with `path_prefix`
    /// (a path-string prefix, e.g. `/alice/attestations/`). Used to enumerate
    /// attestations under an issuer's namespace for policy evaluation.
    pub fn list_objects_by_path_prefix(&self, path_prefix: &str) -> Result<Vec<StoredObject>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let mut out = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, path_prefix.as_bytes());
        for item in iter {
            let (key, value) = item.map_err(|e| DbError::RocksDb(e.to_string()))?;
            // prefix_iterator may overscan past the prefix; stop when it does.
            if !key.starts_with(path_prefix.as_bytes()) {
                break;
            }
            let obj: StoredObject = serde_json::from_slice(&value)
                .map_err(|e| DbError::Serialization(e.to_string()))?;
            out.push(obj);
        }
        Ok(out)
    }

    /// Collect all stored objects with the given `content_schema` (a full scan).
    /// Used to enumerate attestations across all issuers when a policy's
    /// `attested` source omits `by`.
    pub fn list_objects_by_schema(&self, schema: &str) -> Result<Vec<StoredObject>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_key, value) = item.map_err(|e| DbError::RocksDb(e.to_string()))?;
            let obj: StoredObject = serde_json::from_slice(&value)
                .map_err(|e| DbError::Serialization(e.to_string()))?;
            if obj.content_schema.as_deref() == Some(schema) {
                out.push(obj);
            }
        }
        Ok(out)
    }

    /// Store a policy at a path (test/bootstrap convenience — computes a
    /// placeholder content-hash from the serialized policy). Real applies use
    /// [`put_policy_at`] with the on-chain content-hash + block so that pins
    /// (P2) resolve deterministically.
    pub fn put_policy(&self, path: &crate::message::Path, policy: &Policy) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(policy).map_err(|e| DbError::Serialization(e.to_string()))?;
        let content_hash = crate::crypto::ContentHash::sha256(&bytes).to_string();
        self.put_policy_at(path, policy, &content_hash, 0)
    }

    /// Index a policy version at a path with its on-chain content-hash + block.
    /// This is the [`PolicyEntry`] the resolver returns; the `content_hash` is
    /// what a child policy PINS (P2).
    pub fn put_policy_at(
        &self,
        path: &crate::message::Path,
        policy: &Policy,
        content_hash: &str,
        block: u64,
    ) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_POLICIES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let key = path.to_string();
        let entry = PolicyEntry {
            policy: policy.clone(),
            content_hash: content_hash.to_string(),
            block,
        };
        let value = serde_json::to_vec(&entry)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        self.db.put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Resolve policy by walking up the path hierarchy (see [`resolve_policy_entry`]).
    pub fn resolve_policy(&self, path: &crate::message::Path) -> Result<Option<Policy>, DbError> {
        Ok(self.resolve_policy_entry(path)?.map(|e| e.policy))
    }

    /// Resolve the applicable [`PolicyEntry`] (policy + content-hash + block) by
    /// walking up the path hierarchy, falling back to the root policy at
    /// `/sys/policies/`. Returns the NEAREST ancestor policy (latest version) —
    /// pin-aware historical substitution is applied by the caller (the daemon)
    /// via [`get_policy_version`].
    pub fn resolve_policy_entry(&self, path: &crate::message::Path) -> Result<Option<PolicyEntry>, DbError> {
        let cf = self.db.cf_handle(CF_POLICIES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Walk up the path hierarchy for path-specific policies.
        for ancestor in path.ancestors() {
            let key = ancestor.to_string();
            if let Some(bytes) = self.db.get_cf(&cf, key.as_bytes())
                .map_err(|e| DbError::RocksDb(e.to_string()))? {
                return Ok(Some(decode_policy_entry(&bytes)?));
            }
        }

        // Fall back to the root policy at /sys/policies/ (genesis root policy).
        if let Some(bytes) = self.db.get_cf(&cf, b"/sys/policies/")
            .map_err(|e| DbError::RocksDb(e.to_string()))? {
            return Ok(Some(decode_policy_entry(&bytes)?));
        }

        Ok(None)
    }

    // ========== P2: policy-version history store + pin refcounts ==========

    /// Store a retained historical policy version keyed by its content-hash.
    pub fn put_policy_version(&self, content_hash: &str, policy: &Policy) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_POLICY_VERSIONS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let value = serde_json::to_vec(policy).map_err(|e| DbError::Serialization(e.to_string()))?;
        self.db.put_cf(&cf, content_hash.as_bytes(), &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Fetch a retained historical policy version by content-hash.
    pub fn get_policy_version(&self, content_hash: &str) -> Result<Option<Policy>, DbError> {
        let cf = self.db.cf_handle(CF_POLICY_VERSIONS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        match self.db.get_cf(&cf, content_hash.as_bytes()) {
            Ok(Some(bytes)) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| DbError::Serialization(e.to_string()))?)),
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    fn delete_policy_version(&self, content_hash: &str) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_POLICY_VERSIONS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        self.db.delete_cf(&cf, content_hash.as_bytes()).map_err(|e| DbError::RocksDb(e.to_string()))
    }

    fn get_pin_ref(&self, content_hash: &str) -> Result<u64, DbError> {
        let cf = self.db.cf_handle(CF_POLICY_PINREFS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        match self.db.get_cf(&cf, content_hash.as_bytes()) {
            Ok(Some(b)) => Ok(u64::from_le_bytes(b.as_slice().try_into().unwrap_or([0; 8]))),
            Ok(None) => Ok(0),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    fn set_pin_ref(&self, content_hash: &str, count: u64) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_POLICY_PINREFS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        self.db.put_cf(&cf, content_hash.as_bytes(), &count.to_le_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Increment the pin refcount for `content_hash`, storing `version` under it
    /// if this is the first pin (so the retained version is available for
    /// pin-aware govern resolution).
    pub fn pin_incref(&self, content_hash: &str, version: &Policy) -> Result<(), DbError> {
        let count = self.get_pin_ref(content_hash)?;
        if count == 0 {
            self.put_policy_version(content_hash, version)?;
        }
        self.set_pin_ref(content_hash, count + 1)
    }

    /// Decrement the pin refcount for `content_hash`; GC the retained version
    /// when it reaches zero.
    pub fn pin_decref(&self, content_hash: &str) -> Result<(), DbError> {
        let count = self.get_pin_ref(content_hash)?;
        if count <= 1 {
            self.set_pin_ref(content_hash, 0)?;
            self.delete_policy_version(content_hash)?;
        } else {
            self.set_pin_ref(content_hash, count - 1)?;
        }
        Ok(())
    }

    /// All retained historical policy versions `(content_hash, policy)` — used to
    /// carry still-pinned versions in a state snapshot (P2, cf mingo-cy17).
    pub fn list_policy_versions(&self) -> Result<Vec<(String, Policy)>, DbError> {
        let cf = self.db.cf_handle(CF_POLICY_VERSIONS).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| DbError::RocksDb(e.to_string()))?;
            let hash = String::from_utf8(key.to_vec()).map_err(|e| DbError::Serialization(e.to_string()))?;
            let policy: Policy = serde_json::from_slice(&value).map_err(|e| DbError::Serialization(e.to_string()))?;
            out.push((hash, policy));
        }
        Ok(out)
    }

    /// Get the last processed block number
    pub fn get_last_block(&self) -> Result<Option<u64>, DbError> {
        let cf = self.db.cf_handle(CF_META).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, b"last_block") {
            Ok(Some(bytes)) => {
                let block = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Set the last processed block number
    pub fn set_last_block(&self, block: u64) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_META).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.put_cf(&cf, b"last_block", &block.to_le_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Store a name claim mapping: pubkey -> name
    /// This is called when a name claim object is stored at /sys/names/<name>
    pub fn put_name_claim(&self, pubkey: &str, name: &str) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_NAMES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Store pubkey -> name mapping
        self.db.put_cf(&cf, pubkey.as_bytes(), name.as_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Look up a name for a public key
    /// Returns the claimed name if this pubkey has one, None otherwise
    pub fn get_name_for_pubkey(&self, pubkey: &str) -> Result<Option<String>, DbError> {
        let cf = self.db.cf_handle(CF_NAMES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, pubkey.as_bytes()) {
            Ok(Some(bytes)) => {
                let name = String::from_utf8(bytes.to_vec())
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(name))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Delete a name claim mapping
    pub fn delete_name_claim(&self, pubkey: &str) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_NAMES).ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.delete_cf(&cf, pubkey.as_bytes())
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    // ========== State Root Tracking ==========

    /// Record the state root after processing a block
    pub fn record_state_root(&self, block: u64, state_root: [u8; 32]) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        self.db.put_cf(&cf, &block.to_be_bytes(), &state_root)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Get the state root at a specific block
    pub fn get_state_root_at_block(&self, block: u64) -> Result<Option<[u8; 32]>, DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        match self.db.get_cf(&cf, &block.to_be_bytes()) {
            Ok(Some(bytes)) => {
                let root: [u8; 32] = bytes.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid state root length".to_string()))?;
                Ok(Some(root))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Get the latest recorded state root and its block number
    pub fn get_latest_state_root(&self) -> Result<Option<(u64, [u8; 32])>, DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Iterate in reverse to find latest
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_last();

        if iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                let block = u64::from_be_bytes(key.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid block key".to_string()))?);
                let root: [u8; 32] = value.try_into()
                    .map_err(|_| DbError::RocksDb("Invalid state root".to_string()))?;
                return Ok(Some((block, root)));
            }
        }

        Ok(None)
    }

    /// Get the state root at or before a specific block
    /// Returns the most recent state root recorded at or before the given block.
    /// This handles the case where a state root was recorded at block N,
    /// and we're verifying a proof for block N+k where nothing changed.
    pub fn get_state_root_at_or_before(&self, block: u64) -> Result<Option<(u64, [u8; 32])>, DbError> {
        let cf = self.db.cf_handle(CF_STATE_ROOTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut iter = self.db.raw_iterator_cf(&cf);

        // seek_for_prev finds the largest key <= target
        // This handles both exact matches and "nothing after" cases correctly
        iter.seek_for_prev(&block.to_be_bytes());

        if iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if let Ok(found_block_bytes) = <[u8; 8]>::try_from(key) {
                    let found_block = u64::from_be_bytes(found_block_bytes);
                    // Verify this is actually <= the requested block
                    if found_block <= block {
                        if let Ok(root) = <[u8; 32]>::try_from(value) {
                            return Ok(Some((found_block, root)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    // ========== Proof Storage ==========

    /// Store a verified proof
    /// Key is block_from:block_to for easy range queries
    pub fn put_proof(&self, proof: &StoredProof) -> Result<(), DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let key = format!("{}:{}", proof.block_from, proof.block_to);
        let value = serde_json::to_vec(proof)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        self.db.put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| DbError::RocksDb(e.to_string()))
    }

    /// Get a proof by block range
    pub fn get_proof(&self, block_from: u64, block_to: u64) -> Result<Option<StoredProof>, DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let key = format!("{}:{}", block_from, block_to);

        match self.db.get_cf(&cf, key.as_bytes()) {
            Ok(Some(bytes)) => {
                let proof: StoredProof = serde_json::from_slice(&bytes)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DbError::RocksDb(e.to_string())),
        }
    }

    /// Get a proof that covers a specific block number
    pub fn get_proof_for_block(&self, block: u64) -> Result<Option<StoredProof>, DbError> {
        let cf = self.db.cf_handle(CF_PROOFS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        // Iterate through all proofs to find one covering this block
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            match item {
                Ok((_key, value)) => {
                    let proof: StoredProof = serde_json::from_slice(&value)
                        .map_err(|e| DbError::Serialization(e.to_string()))?;
                    if proof.block_from <= block && block <= proof.block_to {
                        return Ok(Some(proof));
                    }
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }
        Ok(None)
    }

    // ========== Trie State Root ==========

    /// Convert an object's path and id to trie path segments.
    /// E.g., path="/sys/names/", id="alice" -> ["sys", "names", "alice"].
    /// `creator` is an immutable object attribute, not a trie segment: identity
    /// is globally unique on `(path, id)`.
    pub fn object_to_segments(
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Vec<String> {
        let mut segments: Vec<String> = path.segments()
            .iter()
            .map(|id| id.as_str().to_string())
            .collect();
        segments.push(id.as_str().to_string());
        segments
    }

    /// Check if any objects exist in the database (genesis has been processed)
    pub fn has_objects(&self) -> Result<bool, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();
        Ok(iter.valid())
    }

    /// Get all objects for computing trie state root
    /// Returns list of (path_segments, object_hash) tuples
    pub fn get_all_objects_for_trie(&self) -> Result<Vec<(Vec<String>, [u8; 32])>, DbError> {
        let cf = self.db.cf_handle(CF_OBJECTS)
            .ok_or_else(|| DbError::RocksDb("Missing CF".to_string()))?;

        let mut objects: Vec<(Vec<String>, [u8; 32])> = Vec::new();

        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            match item {
                Ok((_key, value)) => {
                    let obj: StoredObject = serde_json::from_slice(&value)
                        .map_err(|e| DbError::Serialization(e.to_string()))?;

                    let segments = Self::object_to_segments(&obj.path, &obj.id);
                    objects.push((segments, obj.object_hash));
                }
                Err(e) => return Err(DbError::RocksDb(e.to_string())),
            }
        }

        Ok(objects)
    }

    /// Compute trie state root from all objects
    /// Returns [0u8; 32] if no objects exist
    pub fn compute_trie_state_root(&self) -> Result<[u8; 32], DbError> {
        let objects = self.get_all_objects_for_trie()?;
        if objects.is_empty() {
            return Ok([0u8; 32]);
        }
        Ok(sbo_crypto::compute_trie_root(&objects))
    }

    /// Generate a trie proof for a specific object
    /// Returns TrieProof or None if object doesn't exist
    pub fn generate_trie_proof(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<Option<sbo_crypto::TrieProof>, DbError> {
        // Get the object first to verify it exists
        if self.get_object(path, id)?.is_none() {
            return Ok(None);
        }

        // Build trie from all objects
        let all_objects = self.get_all_objects_for_trie()?;
        let mut trie = sbo_crypto::SparseTrie::new();
        for (segments, object_hash) in &all_objects {
            trie.insert(segments.clone(), *object_hash);
        }

        // Generate proof for target object
        let target_segments = Self::object_to_segments(path, id);
        match trie.generate_proof(&target_segments) {
            Ok(proof) => Ok(Some(proof)),
            Err(_) => Ok(None),
        }
    }

    /// Generate a trie proof for the object occupying `(path, id)`.
    /// Returns `(creator, TrieProof)` (creator is the occupant's immutable
    /// attribute, carried on the SBOQ `Creator` header) or `None` if the slot is
    /// empty. This is now a point lookup — there is no creator to auto-detect.
    pub fn generate_trie_proof_auto(
        &self,
        path: &crate::message::Path,
        id: &crate::message::Id,
    ) -> Result<Option<(crate::message::Id, sbo_crypto::TrieProof)>, DbError> {
        let obj = match self.get_object(path, id)? {
            Some(o) => o,
            None => return Ok(None),
        };

        match self.generate_trie_proof(path, id)? {
            Some(proof) => Ok(Some((obj.creator, proof))),
            None => Ok(None),
        }
    }
}

/// Decode a `policies` CF value into a [`PolicyEntry`], tolerating the legacy
/// encoding where the value was a bare `Policy` (no content-hash/block wrapper).
/// A legacy entry resolves as unpinned/tracking with a placeholder hash — which
/// is exactly the pre-P2 behavior — so an old DB keeps working until reindexed.
fn decode_policy_entry(bytes: &[u8]) -> Result<PolicyEntry, DbError> {
    if let Ok(entry) = serde_json::from_slice::<PolicyEntry>(bytes) {
        return Ok(entry);
    }
    let policy: Policy = serde_json::from_slice(bytes)
        .map_err(|e| DbError::Serialization(e.to_string()))?;
    let content_hash = crate::crypto::ContentHash::sha256(bytes).to_string();
    Ok(PolicyEntry { policy, content_hash, block: 0 })
}

fn encode_object_key(
    path: &crate::message::Path,
    id: &crate::message::Id,
) -> Vec<u8> {
    // Delimiter is ASCII Unit Separator (0x1F): outside the Id/Path charset
    // (which now includes '@' and '/'), so keys stay unambiguous.
    format!("{}\x1f{}", path, id).into_bytes()
}
