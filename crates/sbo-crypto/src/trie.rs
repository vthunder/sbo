//! Sparse Path-Segment Trie for SBO State Commitment (`state-commitment/v2`)
//!
//! Implements a hierarchical trie where tree structure mirrors path structure.
//! Each node has children keyed by segment name; an object may sit at any
//! node, including one that also has children (the object-versus-container
//! rule, State Commitment spec §Object Versus Container).
//!
//! Domain separation (State Commitment spec §Domain Separation):
//!
//! ```text
//! leaf_hash(object_hash) = sha256(0x00 ‖ object_hash_bytes)
//! node_hash(node)        = sha256(0x01 ‖ canonical_json(node))
//! ```
//!
//! Node serialization format (canonical JSON, keys `children` then `object`):
//! ```json
//! {"children":{"segment1":"sha256:...","segment2":"sha256:..."}}
//! {"children":{"b":"sha256:..."},"object":"sha256:..."}
//! ```
//!
//! A node whose `children` is empty and which carries an object is a leaf and
//! commits as `leaf_hash`; a node that has children commits as `node_hash`,
//! with its own object (if any) in the `object` member. The two forms never
//! share a preimage, and the root is a function of the object set alone.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::sha256;

/// Domain byte prefixed to a leaf preimage.
pub const LEAF_DOMAIN: u8 = 0x00;
/// Domain byte prefixed to an internal-node preimage.
pub const NODE_DOMAIN: u8 = 0x01;

/// `leaf_hash(object_hash) = sha256(0x00 ‖ object_hash)` (33-byte preimage).
pub fn leaf_hash(object_hash: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 33];
    preimage[0] = LEAF_DOMAIN;
    preimage[1..].copy_from_slice(object_hash);
    sha256(&preimage)
}

/// Error type for trie operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieError {
    InvalidProof,
    PathNotFound,
    RootMismatch,
    InvalidSegment(String),
    EmptyPath,
}

impl core::fmt::Display for TrieError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "Invalid trie proof"),
            Self::PathNotFound => write!(f, "Path not found in trie"),
            Self::RootMismatch => write!(f, "Trie root mismatch"),
            Self::InvalidSegment(s) => write!(f, "Invalid segment: {}", s),
            Self::EmptyPath => write!(f, "Empty path"),
        }
    }
}

/// A node in the sparse path-segment trie, in its hashed (serialized) form.
///
/// `children` maps a segment name to the **commitment** of the child (a leaf
/// hash or a node hash). `object` is the object hash of the object sitting
/// exactly at this node, present only when the node also has children; a
/// node with no children and an object is a leaf and is never serialized.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrieNode {
    /// Map of segment name to child commitment
    pub children: BTreeMap<String, [u8; 32]>,
    /// Object hash of the object at this node (object-versus-container)
    pub object: Option<[u8; 32]>,
}

impl TrieNode {
    pub fn new() -> Self {
        Self { children: BTreeMap::new(), object: None }
    }

    /// Serialize to deterministic JSON for hashing
    /// Format: {"children":{"a":"sha256:...","b":"sha256:..."}[,"object":"sha256:..."]}
    /// Keys are sorted lexicographically (BTreeMap guarantees this)
    /// No whitespace
    pub fn to_canonical_json(&self) -> Vec<u8> {
        let mut json = String::from(r#"{"children":{"#);
        let mut first = true;
        for (segment, hash) in &self.children {
            if !first {
                json.push(',');
            }
            first = false;
            json.push('"');
            json.push_str(&escape_json_string(segment));
            json.push_str(r#"":"sha256:"#);
            json.push_str(&hex_encode(hash));
            json.push('"');
        }
        json.push('}');
        if let Some(object) = &self.object {
            json.push_str(r#","object":"sha256:"#);
            json.push_str(&hex_encode(object));
            json.push('"');
        }
        json.push('}');
        json.into_bytes()
    }

    /// Internal-node hash = sha256(0x01 ‖ canonical_json)
    pub fn hash(&self) -> [u8; 32] {
        let json = self.to_canonical_json();
        let mut preimage = Vec::with_capacity(json.len() + 1);
        preimage.push(NODE_DOMAIN);
        preimage.extend_from_slice(&json);
        sha256(&preimage)
    }

    /// The commitment this node contributes to its parent: a leaf hash when
    /// the node has an object and no children (the collapsed-leaf rule), the
    /// internal-node hash otherwise.
    pub fn commitment(&self) -> [u8; 32] {
        match (&self.object, self.children.is_empty()) {
            (Some(object), true) => leaf_hash(object),
            _ => self.hash(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.children.is_empty() && self.object.is_none()
    }
}

/// A single step in a trie proof.
///
/// Step `i` describes the node at depth `i` (the root for `i == 0`): its
/// other children (`siblings`), the object sitting at that node if any
/// (`object`), and — on the final step of an inclusion proof whose target is
/// also a container — the target node's own children (`children`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrieProofStep {
    /// The segment taken at this level (None for non-existence proof at this level)
    pub segment: Option<String>,
    /// Sibling commitments at this level (other children of the node)
    pub siblings: BTreeMap<String, [u8; 32]>,
    /// Object hash of the object sitting at this level's node, if any
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub object: Option<[u8; 32]>,
    /// Final step only: the target node's children when the proven object is
    /// also a container
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub children: Option<BTreeMap<String, [u8; 32]>>,
}

impl TrieProofStep {
    /// A plain step (no object at this level, no target children).
    pub fn new(segment: Option<String>, siblings: BTreeMap<String, [u8; 32]>) -> Self {
        Self { segment, siblings, object: None, children: None }
    }
}

/// Complete trie proof for object inclusion/non-existence
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrieProof {
    /// State root this proof is anchored to
    pub state_root: [u8; 32],
    /// Path segments being proven
    pub path_segments: Vec<String>,
    /// Object hash at the path (None for non-existence proof)
    pub object_hash: Option<[u8; 32]>,
    /// Proof steps from root to leaf
    pub proof: Vec<TrieProofStep>,
}

// ============================================================================
// Witness Types for State Transitions
// ============================================================================

/// Witness for a single object state change
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ObjectWitness {
    /// Object created - didn't exist before
    Create {
        path_segments: Vec<String>,
        new_object_hash: [u8; 32],
        /// Proves path wasn't in prev_state
        nonexistence_proof: TrieProof,
    },

    /// Object updated - existed with old hash
    Update {
        path_segments: Vec<String>,
        old_object_hash: [u8; 32],
        new_object_hash: [u8; 32],
        /// Proves old object was in prev_state
        inclusion_proof: TrieProof,
    },

    /// Object deleted - existed before
    Delete {
        path_segments: Vec<String>,
        old_object_hash: [u8; 32],
        /// Proves old object was in prev_state
        inclusion_proof: TrieProof,
    },
}

impl ObjectWitness {
    /// Get the path segments for this witness
    pub fn path_segments(&self) -> &[String] {
        match self {
            ObjectWitness::Create { path_segments, .. } => path_segments,
            ObjectWitness::Update { path_segments, .. } => path_segments,
            ObjectWitness::Delete { path_segments, .. } => path_segments,
        }
    }

    /// Get the new object hash (None for Delete)
    pub fn new_hash(&self) -> Option<[u8; 32]> {
        match self {
            ObjectWitness::Create { new_object_hash, .. } => Some(*new_object_hash),
            ObjectWitness::Update { new_object_hash, .. } => Some(*new_object_hash),
            ObjectWitness::Delete { .. } => None,
        }
    }
}

/// Hint for reconstructing sibling hashes when multiple witnesses share path prefixes
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SiblingHint {
    /// The path to the parent node containing this sibling
    pub parent_path: Vec<String>,
    /// The sibling's segment name
    pub sibling_segment: String,
    /// The sibling's hash
    pub sibling_hash: [u8; 32],
}

/// Complete witness for a state transition
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateTransitionWitness {
    /// State root before the transition
    pub prev_state_root: [u8; 32],
    /// Individual object witnesses
    pub witnesses: Vec<ObjectWitness>,
    /// Additional sibling hints for shared path prefixes
    pub sibling_hints: Vec<SiblingHint>,
}

impl Default for StateTransitionWitness {
    fn default() -> Self {
        Self {
            prev_state_root: [0u8; 32],
            witnesses: Vec::new(),
            sibling_hints: Vec::new(),
        }
    }
}

// ============================================================================
// Partial Trie for Witness Verification
// ============================================================================

/// A partial trie that can be constructed from proofs and incrementally updated
#[derive(Debug, Clone)]
pub struct PartialTrie {
    root: Option<PartialNode>,
    known_root_hash: [u8; 32],
}

/// Node in a partial trie
#[derive(Debug, Clone)]
enum PartialNode {
    /// A node with some children expanded and the others known by commitment
    Partial {
        known_children: BTreeMap<String, PartialNode>,
        sibling_hashes: BTreeMap<String, [u8; 32]>,
        /// Object sitting at this node, if any
        object: Option<[u8; 32]>,
    },
    /// An unexpanded subtree represented only by its commitment
    Stub {
        hash: [u8; 32],
    },
}

impl PartialNode {
    fn partial(object: Option<[u8; 32]>) -> Self {
        PartialNode::Partial {
            known_children: BTreeMap::new(),
            sibling_hashes: BTreeMap::new(),
            object,
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            PartialNode::Partial { known_children, sibling_hashes, object } => {
                known_children.is_empty() && sibling_hashes.is_empty() && object.is_none()
            }
            PartialNode::Stub { .. } => false,
        }
    }
}

impl PartialTrie {
    /// Create an empty partial trie
    pub fn new(known_root_hash: [u8; 32]) -> Self {
        if known_root_hash == [0u8; 32] {
            Self {
                root: None,
                known_root_hash,
            }
        } else {
            Self {
                root: Some(PartialNode::Stub { hash: known_root_hash }),
                known_root_hash,
            }
        }
    }

    /// Expand a path in the trie using proof data
    /// This merges the proof path into the existing partial trie structure
    pub fn expand_from_proof(&mut self, proof: &TrieProof) -> Result<(), TrieError> {
        if proof.state_root != self.known_root_hash {
            return Err(TrieError::RootMismatch);
        }

        if proof.proof.is_empty() {
            return Ok(());
        }

        // Build the path structure from the proof
        let new_path = Self::build_path_from_proof(&proof.proof, proof.object_hash, 0)?;

        // Merge into existing structure instead of replacing
        match &mut self.root {
            None => {
                self.root = Some(new_path);
            }
            Some(existing) => {
                Self::merge_nodes(existing, new_path);
            }
        }

        Ok(())
    }

    /// Merge two partial nodes, combining their children
    fn merge_nodes(existing: &mut PartialNode, new_node: PartialNode) {
        match (existing, new_node) {
            (
                PartialNode::Partial {
                    known_children: existing_children,
                    sibling_hashes: existing_siblings,
                    object: existing_object,
                },
                PartialNode::Partial {
                    known_children: new_children,
                    sibling_hashes: new_siblings,
                    object: new_object,
                },
            ) => {
                if existing_object.is_none() {
                    *existing_object = new_object;
                }
                // Merge sibling hashes, but never shadow an expanded child
                for (seg, hash) in new_siblings {
                    if !existing_children.contains_key(&seg) {
                        existing_siblings.insert(seg, hash);
                    }
                }
                // Merge known children recursively
                for (seg, new_child) in new_children {
                    existing_siblings.remove(&seg);
                    if let Some(existing_child) = existing_children.get_mut(&seg) {
                        Self::merge_nodes(existing_child, new_child);
                    } else {
                        existing_children.insert(seg, new_child);
                    }
                }
            }
            // Existing is a Stub - replace with new detailed structure
            (existing @ PartialNode::Stub { .. }, new_node) => {
                *existing = new_node;
            }
            // New is a Stub but existing has detail - keep existing
            (_, PartialNode::Stub { .. }) => {}
        }
    }

    /// Build a partial path from proof steps. Step `depth` describes the node
    /// at that depth; a `segment: None` step is the last one and describes
    /// the node where the path stops.
    fn build_path_from_proof(
        steps: &[TrieProofStep],
        object_hash: Option<[u8; 32]>,
        depth: usize,
    ) -> Result<PartialNode, TrieError> {
        let step = steps.get(depth).ok_or(TrieError::InvalidProof)?;
        let last = depth + 1 == steps.len();

        match &step.segment {
            None => {
                if !last {
                    return Err(TrieError::InvalidProof);
                }
                Ok(PartialNode::Partial {
                    known_children: BTreeMap::new(),
                    sibling_hashes: step.siblings.clone(),
                    object: step.object,
                })
            }
            Some(segment) => {
                let child = if last {
                    // The target node itself: the proven object plus any
                    // children it has as a container.
                    let hash = object_hash.ok_or(TrieError::InvalidProof)?;
                    PartialNode::Partial {
                        known_children: BTreeMap::new(),
                        sibling_hashes: step.children.clone().unwrap_or_default(),
                        object: Some(hash),
                    }
                } else {
                    Self::build_path_from_proof(steps, object_hash, depth + 1)?
                };

                let mut known_children = BTreeMap::new();
                known_children.insert(segment.clone(), child);

                Ok(PartialNode::Partial {
                    known_children,
                    sibling_hashes: step.siblings.clone(),
                    object: step.object,
                })
            }
        }
    }

    /// Insert or update an object at the given path
    pub fn insert(&mut self, segments: &[String], object_hash: [u8; 32]) {
        if segments.is_empty() {
            return;
        }

        match &mut self.root {
            None => {
                let mut root = PartialNode::partial(None);
                Self::insert_into_node(&mut root, segments, object_hash);
                self.root = Some(root);
            }
            Some(node) => {
                Self::insert_into_node(node, segments, object_hash);
            }
        }
    }

    /// Insert into an existing node
    fn insert_into_node(node: &mut PartialNode, segments: &[String], object_hash: [u8; 32]) {
        if let PartialNode::Stub { .. } = node {
            // Unexpanded subtree: the witness did not open it, so all we can
            // do is start a fresh node here (proofs for valid witnesses
            // always expand the path they touch).
            *node = PartialNode::partial(None);
        }
        let PartialNode::Partial { known_children, sibling_hashes, object } = node else {
            unreachable!()
        };

        let Some((segment, rest)) = segments.split_first() else {
            *object = Some(object_hash);
            return;
        };

        // The segment is now expanded, so it is no longer a bare sibling
        sibling_hashes.remove(segment);
        let child = known_children
            .entry(segment.clone())
            .or_insert_with(|| PartialNode::partial(None));
        Self::insert_into_node(child, rest, object_hash);
    }

    /// Delete an object at the given path
    pub fn delete(&mut self, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }

        match &mut self.root {
            None => false,
            Some(node) => {
                let deleted = Self::delete_from_node(node, segments);
                if node.is_empty() {
                    self.root = None;
                }
                deleted
            }
        }
    }

    /// Delete from a node; prunes nodes left with nothing in them
    fn delete_from_node(node: &mut PartialNode, segments: &[String]) -> bool {
        let PartialNode::Partial { known_children, object, .. } = node else {
            return false;
        };
        let Some((segment, rest)) = segments.split_first() else {
            return object.take().is_some();
        };
        let Some(child) = known_children.get_mut(segment) else {
            return false;
        };
        let deleted = Self::delete_from_node(child, rest);
        if child.is_empty() {
            known_children.remove(segment);
        }
        deleted
    }

    /// Compute the root hash of the partial trie
    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            None => [0u8; 32],
            Some(node) => Self::compute_node_hash(node),
        }
    }

    /// Compute the commitment of a partial node
    fn compute_node_hash(node: &PartialNode) -> [u8; 32] {
        match node {
            PartialNode::Stub { hash } => *hash,
            PartialNode::Partial {
                known_children,
                sibling_hashes,
                object,
            } => {
                let mut trie_node = TrieNode::new();
                for (segment, hash) in sibling_hashes {
                    trie_node.children.insert(segment.clone(), *hash);
                }
                for (segment, child) in known_children {
                    trie_node
                        .children
                        .insert(segment.clone(), Self::compute_node_hash(child));
                }
                trie_node.object = *object;
                trie_node.commitment()
            }
        }
    }
}

// ============================================================================
// State Transition Verification
// ============================================================================

/// Verify a state transition and compute the new state root
///
/// This function:
/// 1. Verifies each object witness against prev_state_root
/// 2. Applies all changes to a partial trie
/// 3. Returns the new state root
pub fn verify_state_transition(witness: &StateTransitionWitness) -> Result<[u8; 32], TrieError> {
    // For empty witness, return the same state root
    if witness.witnesses.is_empty() {
        return Ok(witness.prev_state_root);
    }

    // Step 1: Verify all proofs against prev_state_root
    for obj_witness in &witness.witnesses {
        verify_object_witness(obj_witness, witness.prev_state_root)?;
    }

    // Step 2: Build partial trie and apply changes
    let new_root = apply_witness_changes(witness)?;

    Ok(new_root)
}

/// Verify a single object witness against the expected state root
fn verify_object_witness(witness: &ObjectWitness, expected_root: [u8; 32]) -> Result<(), TrieError> {
    match witness {
        ObjectWitness::Create {
            nonexistence_proof, ..
        } => {
            // Verify path didn't exist
            if nonexistence_proof.state_root != expected_root {
                return Err(TrieError::RootMismatch);
            }
            if nonexistence_proof.object_hash.is_some() {
                return Err(TrieError::InvalidProof);
            }
            let valid = verify_trie_proof(nonexistence_proof)?;
            if !valid {
                return Err(TrieError::InvalidProof);
            }
        }
        ObjectWitness::Update {
            old_object_hash,
            inclusion_proof,
            ..
        }
        | ObjectWitness::Delete {
            old_object_hash,
            inclusion_proof,
            ..
        } => {
            // Verify old object was present
            if inclusion_proof.state_root != expected_root {
                return Err(TrieError::RootMismatch);
            }
            if inclusion_proof.object_hash != Some(*old_object_hash) {
                return Err(TrieError::InvalidProof);
            }
            let valid = verify_trie_proof(inclusion_proof)?;
            if !valid {
                return Err(TrieError::InvalidProof);
            }
        }
    }
    Ok(())
}

/// Apply all witness changes to compute the new state root
fn apply_witness_changes(witness: &StateTransitionWitness) -> Result<[u8; 32], TrieError> {
    let mut partial_trie = PartialTrie::new(witness.prev_state_root);

    // First, expand all proofs into the partial trie
    for obj_witness in &witness.witnesses {
        let proof = match obj_witness {
            ObjectWitness::Create {
                nonexistence_proof, ..
            } => nonexistence_proof,
            ObjectWitness::Update {
                inclusion_proof, ..
            } => inclusion_proof,
            ObjectWitness::Delete {
                inclusion_proof, ..
            } => inclusion_proof,
        };
        partial_trie.expand_from_proof(proof)?;
    }

    // Sibling hints are reserved: proof expansion carries every sibling a
    // valid witness needs.
    let _ = &witness.sibling_hints;

    // Then, apply all changes
    for obj_witness in &witness.witnesses {
        match obj_witness {
            ObjectWitness::Create {
                path_segments,
                new_object_hash,
                ..
            }
            | ObjectWitness::Update {
                path_segments,
                new_object_hash,
                ..
            } => {
                partial_trie.insert(path_segments, *new_object_hash);
            }
            ObjectWitness::Delete { path_segments, .. } => {
                partial_trie.delete(path_segments);
            }
        }
    }

    Ok(partial_trie.root_hash())
}

/// In-memory sparse trie for building and proof generation
#[derive(Debug, Clone, Default)]
pub struct SparseTrie {
    root: Option<Node>,
}

/// A fully known trie node: children by segment plus the object sitting here,
/// if any. A node with an object and no children is a leaf; a node with
/// neither is never kept (it is pruned on delete).
#[derive(Debug, Clone, Default)]
struct Node {
    children: BTreeMap<String, Node>,
    object: Option<[u8; 32]>,
}

impl Node {
    fn is_empty(&self) -> bool {
        self.children.is_empty() && self.object.is_none()
    }

    /// Commitment of this node (leaf hash or node hash)
    fn commitment(&self) -> [u8; 32] {
        let mut trie_node = TrieNode::new();
        for (segment, child) in &self.children {
            trie_node.children.insert(segment.clone(), child.commitment());
        }
        trie_node.object = self.object;
        trie_node.commitment()
    }

    /// Commitments of every child
    fn child_hashes(&self) -> BTreeMap<String, [u8; 32]> {
        self.children
            .iter()
            .map(|(segment, child)| (segment.clone(), child.commitment()))
            .collect()
    }

    /// Commitments of every child except `except`
    fn siblings_of(&self, except: &str) -> BTreeMap<String, [u8; 32]> {
        self.children
            .iter()
            .filter(|(segment, _)| segment.as_str() != except)
            .map(|(segment, child)| (segment.clone(), child.commitment()))
            .collect()
    }

    fn get(&self, segments: &[String]) -> Option<&Node> {
        let mut node = self;
        for segment in segments {
            node = node.children.get(segment)?;
        }
        Some(node)
    }

    fn insert(&mut self, segments: &[String], object_hash: [u8; 32]) {
        let mut node = self;
        for segment in segments {
            node = node.children.entry(segment.clone()).or_default();
        }
        node.object = Some(object_hash);
    }

    /// Remove the object at `segments`; prunes emptied nodes. Returns whether
    /// an object was there.
    fn delete(&mut self, segments: &[String]) -> bool {
        let Some((segment, rest)) = segments.split_first() else {
            return self.object.take().is_some();
        };
        let Some(child) = self.children.get_mut(segment) else {
            return false;
        };
        let deleted = child.delete(rest);
        if child.is_empty() {
            self.children.remove(segment);
        }
        deleted
    }
}

impl SparseTrie {
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Insert or update an object at the given path segments
    pub fn insert(&mut self, segments: Vec<String>, object_hash: [u8; 32]) {
        if segments.is_empty() {
            return;
        }
        self.root
            .get_or_insert_with(Node::default)
            .insert(&segments, object_hash);
    }

    /// Delete an object at the given path segments
    /// Returns true if something was deleted
    pub fn delete(&mut self, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }
        let Some(root) = &mut self.root else {
            return false;
        };
        let deleted = root.delete(segments);
        if root.is_empty() {
            self.root = None;
        }
        deleted
    }

    /// Compute the root hash of the trie
    /// Returns [0u8; 32] for empty trie
    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            None => [0u8; 32],
            Some(node) => node.commitment(),
        }
    }

    /// Generate an inclusion proof for an existing object
    pub fn generate_proof(&self, segments: &[String]) -> Result<TrieProof, TrieError> {
        if segments.is_empty() {
            return Err(TrieError::EmptyPath);
        }

        let root = self.root.as_ref().ok_or(TrieError::PathNotFound)?;
        let state_root = self.root_hash();

        let mut proof_steps = Vec::with_capacity(segments.len());
        let mut node = root;
        for segment in segments {
            let child = node.children.get(segment).ok_or(TrieError::PathNotFound)?;
            proof_steps.push(TrieProofStep {
                segment: Some(segment.clone()),
                siblings: node.siblings_of(segment),
                object: node.object,
                children: None,
            });
            node = child;
        }
        let object_hash = node.object.ok_or(TrieError::PathNotFound)?;
        if !node.children.is_empty() {
            // The object is also a container: the final step carries its
            // children so the verifier can rebuild the internal node.
            if let Some(last) = proof_steps.last_mut() {
                last.children = Some(node.child_hashes());
            }
        }

        Ok(TrieProof {
            state_root,
            path_segments: segments.to_vec(),
            object_hash: Some(object_hash),
            proof: proof_steps,
        })
    }

    /// Generate a non-existence proof
    pub fn generate_nonexistence_proof(&self, segments: &[String]) -> Result<TrieProof, TrieError> {
        if segments.is_empty() {
            return Err(TrieError::EmptyPath);
        }

        let state_root = self.root_hash();
        let mut proof_steps = Vec::new();

        match &self.root {
            None => {
                // Empty trie - path trivially doesn't exist
                proof_steps.push(TrieProofStep::new(None, BTreeMap::new()));
            }
            Some(root) => {
                let mut node = root;
                let mut diverged = false;
                for segment in segments {
                    match node.children.get(segment) {
                        Some(child) => {
                            proof_steps.push(TrieProofStep {
                                segment: Some(segment.clone()),
                                siblings: node.siblings_of(segment),
                                object: node.object,
                                children: None,
                            });
                            node = child;
                        }
                        None => {
                            // Path diverges here: this node (possibly a leaf)
                            // has no such child.
                            proof_steps.push(TrieProofStep {
                                segment: None,
                                siblings: node.child_hashes(),
                                object: node.object,
                                children: None,
                            });
                            diverged = true;
                            break;
                        }
                    }
                }
                if !diverged {
                    // The node exists; it must carry no object.
                    if node.object.is_some() {
                        return Err(TrieError::InvalidProof);
                    }
                    proof_steps.push(TrieProofStep {
                        segment: None,
                        siblings: node.child_hashes(),
                        object: None,
                        children: None,
                    });
                }
            }
        }

        Ok(TrieProof {
            state_root,
            path_segments: segments.to_vec(),
            object_hash: None,
            proof: proof_steps,
        })
    }

    /// Check if an object exists at the path in the trie
    pub fn contains(&self, segments: &[String]) -> bool {
        if segments.is_empty() {
            return false;
        }
        self.root
            .as_ref()
            .and_then(|root| root.get(segments))
            .map(|node| node.object.is_some())
            .unwrap_or(false)
    }
}

/// Compute trie root from a collection of objects
/// Each object is represented as (path_segments, object_hash)
pub fn compute_trie_root(objects: &[(Vec<String>, [u8; 32])]) -> [u8; 32] {
    let mut trie = SparseTrie::new();
    for (segments, object_hash) in objects {
        trie.insert(segments.clone(), *object_hash);
    }
    trie.root_hash()
}

/// Verify a trie proof
pub fn verify_trie_proof(proof: &TrieProof) -> Result<bool, TrieError> {
    // Special case: empty proof against empty state
    // If state_root is all zeros (empty state), any path trivially doesn't exist
    if proof.proof.is_empty() {
        if proof.state_root == [0u8; 32] && proof.object_hash.is_none() {
            // Valid non-existence proof for empty state
            return Ok(true);
        }
        return Err(TrieError::InvalidProof);
    }

    if proof.path_segments.is_empty() {
        return Err(TrieError::InvalidProof);
    }

    match &proof.object_hash {
        Some(object_hash) => verify_inclusion_proof(proof, *object_hash),
        None => verify_nonexistence_proof(proof),
    }
}

/// Rebuild the node a step describes, with `current` as the followed child
/// (or none at a divergence), and return its commitment.
fn step_commitment(step: &TrieProofStep, followed: Option<(&str, [u8; 32])>) -> [u8; 32] {
    let mut node = TrieNode::new();
    for (sib_seg, sib_hash) in &step.siblings {
        node.children.insert(sib_seg.clone(), *sib_hash);
    }
    if let Some((segment, hash)) = followed {
        node.children.insert(String::from(segment), hash);
    }
    node.object = step.object;
    node.commitment()
}

/// Verify an inclusion proof
fn verify_inclusion_proof(proof: &TrieProof, object_hash: [u8; 32]) -> Result<bool, TrieError> {
    if proof.proof.len() != proof.path_segments.len() {
        return Err(TrieError::InvalidProof);
    }
    let last = proof.proof.len() - 1;

    // Start at the target node: a leaf, or a container carrying the object
    let mut current_hash = match &proof.proof[last].children {
        None => leaf_hash(&object_hash),
        Some(children) => {
            let node = TrieNode { children: children.clone(), object: Some(object_hash) };
            node.commitment()
        }
    };

    // Process proof steps from bottom to top (reverse order)
    for (i, step) in proof.proof.iter().enumerate().rev() {
        let segment = step.segment.as_ref().ok_or(TrieError::InvalidProof)?;

        // Verify segment matches expected path
        if segment != &proof.path_segments[i] {
            return Err(TrieError::InvalidProof);
        }
        // Only the final step may describe the target's children
        if i != last && step.children.is_some() {
            return Err(TrieError::InvalidProof);
        }
        // The followed child is not also a sibling
        if step.siblings.contains_key(segment) {
            return Err(TrieError::InvalidProof);
        }

        current_hash = step_commitment(step, Some((segment, current_hash)));
    }

    // Final hash must match state root
    Ok(current_hash == proof.state_root)
}

/// Verify a non-existence proof
fn verify_nonexistence_proof(proof: &TrieProof) -> Result<bool, TrieError> {
    // The first `segment: null` step is the divergence point and must be the
    // last step. (W3-8: every index below is bounds-checked; an indexer's
    // proof for a missing top-level object arrives with an empty segment
    // list and is rejected above.)
    let idx = proof
        .proof
        .iter()
        .position(|s| s.segment.is_none())
        .ok_or(TrieError::InvalidProof)?;
    if idx + 1 != proof.proof.len() || idx > proof.path_segments.len() {
        return Err(TrieError::InvalidProof);
    }
    let diverge_step = &proof.proof[idx];
    if proof.proof.iter().any(|s| s.children.is_some()) {
        return Err(TrieError::InvalidProof);
    }

    let mut current_hash = if idx == proof.path_segments.len() {
        // The target node exists as a container but carries no object
        if diverge_step.object.is_some() || diverge_step.siblings.is_empty() {
            return Err(TrieError::InvalidProof);
        }
        step_commitment(diverge_step, None)
    } else {
        // The node at this depth lacks the target segment
        if diverge_step.siblings.contains_key(&proof.path_segments[idx]) {
            return Err(TrieError::InvalidProof);
        }
        if diverge_step.siblings.is_empty() && diverge_step.object.is_none() {
            // Nothing here at all: only the empty trie looks like this
            if idx == 0 {
                return Ok(proof.state_root == [0u8; 32]);
            }
            return Err(TrieError::InvalidProof);
        }
        step_commitment(diverge_step, None)
    };

    // Now verify from divergence point up to root
    for i in (0..idx).rev() {
        let step = &proof.proof[i];
        let segment = step.segment.as_ref().ok_or(TrieError::InvalidProof)?;
        if segment != &proof.path_segments[i] || step.siblings.contains_key(segment) {
            return Err(TrieError::InvalidProof);
        }
        current_hash = step_commitment(step, Some((segment, current_hash)));
    }

    Ok(current_hash == proof.state_root)
}

/// Escape special characters for JSON string
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Simple hex encoding (avoids dependency on hex crate in no_std)
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_trie_node_canonical_json() {
        let mut node = TrieNode::new();
        node.children.insert("alice".to_string(), [0x11; 32]);
        node.children.insert("bob".to_string(), [0x22; 32]);

        let json = node.to_canonical_json();
        let json_str = core::str::from_utf8(&json).unwrap();

        // Keys must be sorted lexicographically
        assert!(json_str.contains(r#""alice":"sha256:"#));
        assert!(json_str.find("alice").unwrap() < json_str.find("bob").unwrap());
        // No whitespace
        assert!(!json_str.contains(' '));
        // Proper format
        assert!(json_str.starts_with(r#"{"children":{"#));
        assert!(json_str.ends_with("}}"));

        node.object = Some([0x33; 32]);
        let json = node.to_canonical_json();
        let json_str = core::str::from_utf8(&json).unwrap();
        assert!(json_str.ends_with(&format!(r#"}},"object":"sha256:{}"}}"#, "33".repeat(32))));
    }

    #[test]
    fn test_domain_separation() {
        let h = [5u8; 32];
        // leaf = sha256(0x00 || h)
        let mut pre = alloc::vec![0u8];
        pre.extend_from_slice(&h);
        assert_eq!(leaf_hash(&h), sha256(&pre));
        // node = sha256(0x01 || json)
        let mut node = TrieNode::new();
        node.children.insert("a".into(), h);
        let mut pre = alloc::vec![1u8];
        pre.extend_from_slice(&node.to_canonical_json());
        assert_eq!(node.hash(), sha256(&pre));
        assert_eq!(node.commitment(), node.hash());
        // object-only node collapses to a leaf
        let only = TrieNode { children: BTreeMap::new(), object: Some(h) };
        assert_eq!(only.commitment(), leaf_hash(&h));
    }

    #[test]
    fn test_trie_node_hash_deterministic() {
        let mut node1 = TrieNode::new();
        node1.children.insert("a".to_string(), [1; 32]);
        node1.children.insert("b".to_string(), [2; 32]);

        let mut node2 = TrieNode::new();
        // Insert in different order
        node2.children.insert("b".to_string(), [2; 32]);
        node2.children.insert("a".to_string(), [1; 32]);

        assert_eq!(node1.hash(), node2.hash());
    }

    #[test]
    fn test_sparse_trie_insert_and_root() {
        let mut trie = SparseTrie::new();

        // Empty trie
        assert_eq!(trie.root_hash(), [0u8; 32]);

        // Insert one object
        trie.insert(seg(&["sys", "names", "user1", "alice"]), [1; 32]);
        let root1 = trie.root_hash();
        assert_ne!(root1, [0u8; 32]);

        // Insert another object
        trie.insert(seg(&["sys", "names", "user2", "bob"]), [2; 32]);
        let root2 = trie.root_hash();
        assert_ne!(root2, root1);
    }

    #[test]
    fn test_inclusion_proof_roundtrip() {
        let mut trie = SparseTrie::new();
        trie.insert(seg(&["sys", "names", "user1", "alice"]), [1; 32]);
        trie.insert(seg(&["sys", "names", "user2", "bob"]), [2; 32]);

        // Generate proof for alice
        let proof = trie.generate_proof(&seg(&["sys", "names", "user1", "alice"])).unwrap();

        assert_eq!(proof.object_hash, Some([1; 32]));
        assert!(verify_trie_proof(&proof).unwrap());
    }

    #[test]
    fn test_compute_trie_root() {
        let objects = alloc::vec![
            (seg(&["a", "b"]), [1; 32]),
            (seg(&["a", "c"]), [2; 32]),
        ];

        let root = compute_trie_root(&objects);
        assert_ne!(root, [0u8; 32]);

        // Same objects in different order should produce same root
        let objects2 = alloc::vec![
            (seg(&["a", "c"]), [2; 32]),
            (seg(&["a", "b"]), [1; 32]),
        ];
        let root2 = compute_trie_root(&objects2);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_delete() {
        let mut trie = SparseTrie::new();
        trie.insert(seg(&["a", "b"]), [1; 32]);
        trie.insert(seg(&["a", "c"]), [2; 32]);

        assert!(trie.contains(&seg(&["a", "b"])));

        trie.delete(&seg(&["a", "b"]));

        assert!(!trie.contains(&seg(&["a", "b"])));
        assert!(trie.contains(&seg(&["a", "c"])));
        trie.delete(&seg(&["a", "c"]));
        assert_eq!(trie.root_hash(), [0u8; 32]);
    }

    /// Object-versus-container: `a` at /x/ and `b` at /x/a/ coexist, the root
    /// is order-independent, both have proofs, and deleting `b` collapses the
    /// node for `a` back to a leaf.
    #[test]
    fn test_object_and_container_coexist() {
        let a = seg(&["x", "a"]);
        let ab = seg(&["x", "a", "b"]);
        let mut t = SparseTrie::new();
        t.insert(ab.clone(), [2; 32]);
        t.insert(a.clone(), [1; 32]);
        let mut u = SparseTrie::new();
        u.insert(a.clone(), [1; 32]);
        u.insert(ab.clone(), [2; 32]);
        assert!(t.contains(&a) && t.contains(&ab));
        assert_eq!(t.root_hash(), u.root_hash());

        // Node for a = node_hash({"children":{"b":leaf(2)},"object":1})
        let mut node_a = TrieNode::new();
        node_a.children.insert("b".into(), leaf_hash(&[2; 32]));
        node_a.object = Some([1; 32]);
        let mut root = TrieNode::new();
        let mut x = TrieNode::new();
        x.children.insert("a".into(), node_a.hash());
        root.children.insert("x".into(), x.hash());
        assert_eq!(t.root_hash(), root.hash());

        let pa = t.generate_proof(&a).unwrap();
        assert!(pa.proof.last().unwrap().children.is_some());
        assert_eq!(verify_trie_proof(&pa), Ok(true));
        let pab = t.generate_proof(&ab).unwrap();
        assert_eq!(pab.proof.last().unwrap().object, Some([1; 32]));
        assert_eq!(verify_trie_proof(&pab), Ok(true));

        // Non-existence under a leaf, and of a container without an object.
        let np = t.generate_nonexistence_proof(&seg(&["x", "a", "b", "c"])).unwrap();
        assert_eq!(verify_trie_proof(&np), Ok(true));
        let np = t.generate_nonexistence_proof(&seg(&["x"])).unwrap();
        assert_eq!(verify_trie_proof(&np), Ok(true));
        assert!(t.generate_nonexistence_proof(&a).is_err());

        // Delete b: a collapses to a leaf.
        assert!(t.delete(&ab));
        let mut only_a = SparseTrie::new();
        only_a.insert(a.clone(), [1; 32]);
        assert_eq!(t.root_hash(), only_a.root_hash());
        // Delete a: node vanishes.
        let mut v = u.clone();
        assert!(v.delete(&a));
        let mut only_ab = SparseTrie::new();
        only_ab.insert(ab.clone(), [2; 32]);
        assert_eq!(v.root_hash(), only_ab.root_hash());
    }

    /// Witnesses over object-and-container shapes reproduce the rebuilt root.
    #[test]
    fn test_witness_with_container_objects() {
        let a = seg(&["x", "a"]);
        let ab = seg(&["x", "a", "b"]);
        let ac = seg(&["x", "a", "c"]);
        let mut t = SparseTrie::new();
        t.insert(a.clone(), [1; 32]);
        t.insert(ab.clone(), [2; 32]);
        let prev = t.root_hash();

        let witness = StateTransitionWitness {
            prev_state_root: prev,
            witnesses: alloc::vec![
                ObjectWitness::Update {
                    path_segments: a.clone(),
                    old_object_hash: [1; 32],
                    new_object_hash: [11; 32],
                    inclusion_proof: t.generate_proof(&a).unwrap(),
                },
                ObjectWitness::Delete {
                    path_segments: ab.clone(),
                    old_object_hash: [2; 32],
                    inclusion_proof: t.generate_proof(&ab).unwrap(),
                },
                ObjectWitness::Create {
                    path_segments: ac.clone(),
                    new_object_hash: [3; 32],
                    nonexistence_proof: t.generate_nonexistence_proof(&ac).unwrap(),
                },
            ],
            sibling_hints: alloc::vec![],
        };
        let got = verify_state_transition(&witness).unwrap();
        let mut after = SparseTrie::new();
        after.insert(a.clone(), [11; 32]);
        after.insert(ac.clone(), [3; 32]);
        assert_eq!(got, after.root_hash());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[0x12, 0x34]), "1234");
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_witness_creates_with_shared_prefix() {
        // Test that witness verification correctly handles multiple creates
        // with shared path prefixes (like /sys/names and /sys/policies)

        // Start with empty state
        let empty_root = [0u8; 32];

        // Create paths that share the "sys" prefix
        let path1 = seg(&["sys", "names", "sys"]);
        let path2 = seg(&["sys", "policies", "root"]);
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        // Build expected state using full trie
        let mut expected_trie = SparseTrie::new();
        expected_trie.insert(path1.clone(), hash1);
        expected_trie.insert(path2.clone(), hash2);
        let expected_root = expected_trie.root_hash();

        // Generate non-existence proofs from empty state (since we're creating)
        // For creates from empty state, proofs are trivial
        let proof1 = TrieProof {
            state_root: empty_root,
            path_segments: path1.clone(),
            object_hash: None,
            proof: alloc::vec![],
        };
        let proof2 = TrieProof {
            state_root: empty_root,
            path_segments: path2.clone(),
            object_hash: None,
            proof: alloc::vec![],
        };

        // Build witness with two creates that share "sys" prefix
        let witness = StateTransitionWitness {
            prev_state_root: empty_root,
            witnesses: alloc::vec![
                ObjectWitness::Create {
                    path_segments: path1,
                    new_object_hash: hash1,
                    nonexistence_proof: proof1,
                },
                ObjectWitness::Create {
                    path_segments: path2,
                    new_object_hash: hash2,
                    nonexistence_proof: proof2,
                },
            ],
            sibling_hints: alloc::vec![],
        };

        // Verify that witness produces the same root as full trie
        let computed_root = verify_state_transition(&witness).unwrap();
        assert_eq!(computed_root, expected_root,
            "Witness verification produced different root than full trie. \
             Expected: {:?}, Got: {:?}",
            hex_encode(&expected_root), hex_encode(&computed_root));
    }

    #[test]
    fn test_witness_updates_with_shared_prefix() {
        // Test that witness verification correctly handles multiple updates
        // with shared path prefixes

        // Build initial state with objects sharing "sys" prefix
        let path1 = seg(&["sys", "names", "sys"]);
        let path2 = seg(&["sys", "policies", "root"]);
        let old_hash1 = [1u8; 32];
        let old_hash2 = [2u8; 32];
        let new_hash1 = [11u8; 32];
        let new_hash2 = [22u8; 32];

        let mut initial_trie = SparseTrie::new();
        initial_trie.insert(path1.clone(), old_hash1);
        initial_trie.insert(path2.clone(), old_hash2);
        let prev_root = initial_trie.root_hash();

        // Generate inclusion proofs from initial state
        let proof1 = initial_trie.generate_proof(&path1).unwrap();
        let proof2 = initial_trie.generate_proof(&path2).unwrap();

        // Build expected final state
        let mut expected_trie = SparseTrie::new();
        expected_trie.insert(path1.clone(), new_hash1);
        expected_trie.insert(path2.clone(), new_hash2);
        let expected_root = expected_trie.root_hash();

        // Build witness with two updates
        let witness = StateTransitionWitness {
            prev_state_root: prev_root,
            witnesses: alloc::vec![
                ObjectWitness::Update {
                    path_segments: path1,
                    old_object_hash: old_hash1,
                    new_object_hash: new_hash1,
                    inclusion_proof: proof1,
                },
                ObjectWitness::Update {
                    path_segments: path2,
                    old_object_hash: old_hash2,
                    new_object_hash: new_hash2,
                    inclusion_proof: proof2,
                },
            ],
            sibling_hints: alloc::vec![],
        };

        // Verify that witness produces the same root as full trie
        let computed_root = verify_state_transition(&witness).unwrap();
        assert_eq!(computed_root, expected_root,
            "Witness verification produced different root than full trie. \
             Expected: {:?}, Got: {:?}",
            hex_encode(&expected_root), hex_encode(&computed_root));
    }
}
