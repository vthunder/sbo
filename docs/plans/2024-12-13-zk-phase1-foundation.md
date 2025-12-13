# ZK Validity Proofs Phase 1: Foundation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create `no_std` compatible crates for SBO types and crypto to enable zkVM compilation.

**Architecture:** Extract core types (Path, Id, Action, Message) into `sbo-types` crate with `no_std` support. Add BLS12-381 signatures to `sbo-crypto` crate. Keep RocksDB-dependent code in `sbo-core` which re-exports the new crates.

**Tech Stack:** Rust, `no_std`, `alloc`, `blst` (BLS12-381), `ed25519-dalek`, `sha2`

---

## Task 1: Create sbo-types Crate Skeleton

**Files:**
- Create: `reference_impl/sbo-types/Cargo.toml`
- Create: `reference_impl/sbo-types/src/lib.rs`
- Modify: `reference_impl/Cargo.toml` (workspace members)

**Step 1: Create the sbo-types directory**

```bash
mkdir -p reference_impl/sbo-types/src
```

**Step 2: Create Cargo.toml for sbo-types**

Create file `reference_impl/sbo-types/Cargo.toml`:

```toml
[package]
name = "sbo-types"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "SBO core types (no_std compatible)"

[features]
default = ["std"]
std = ["alloc"]
alloc = []

[dependencies]
# No dependencies yet - we'll add as needed
```

**Step 3: Create lib.rs with no_std setup**

Create file `reference_impl/sbo-types/src/lib.rs`:

```rust
//! SBO Core Types
//!
//! This crate provides the fundamental types for SBO (Simple Blockchain Objects).
//! It is `no_std` compatible for use in zkVM environments.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-export alloc types for convenience
#[cfg(feature = "alloc")]
pub use alloc::{string::String, vec::Vec, vec};

pub mod error;
pub mod id;
pub mod path;
pub mod action;
```

**Step 4: Add sbo-types to workspace**

Edit `reference_impl/Cargo.toml`, add to members:

```toml
[workspace]
resolver = "2"
members = ["sbo-core", "sbo-avail", "sbo-daemon", "sbo-cli", "sbo-types"]
```

**Step 5: Verify it compiles**

Run: `cd reference_impl && cargo check -p sbo-types`

Expected: Compilation errors (missing modules) - that's ok, we'll add them next.

---

## Task 2: Implement Error Types (no_std)

**Files:**
- Create: `reference_impl/sbo-types/src/error.rs`

**Step 1: Create error.rs with no_std compatible errors**

Create file `reference_impl/sbo-types/src/error.rs`:

```rust
//! Error types for sbo-types (no_std compatible)

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Parse error for SBO types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Invalid identifier format
    InvalidIdentifier(InvalidIdentifierReason),
    /// Invalid path format
    InvalidPath(InvalidPathReason),
    /// Invalid action
    InvalidAction,
}

/// Reason for invalid identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidIdentifierReason {
    Empty,
    TooLong,
    InvalidChar,
}

/// Reason for invalid path
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPathReason {
    MustStartWithSlash,
    MustEndWithSlash,
    InvalidSegment,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::InvalidIdentifier(reason) => {
                write!(f, "Invalid identifier: {:?}", reason)
            }
            ParseError::InvalidPath(reason) => {
                write!(f, "Invalid path: {:?}", reason)
            }
            ParseError::InvalidAction => {
                write!(f, "Invalid action")
            }
        }
    }
}
```

**Step 2: Verify it compiles**

Run: `cd reference_impl && cargo check -p sbo-types`

Expected: Still errors for missing id, path, action modules.

---

## Task 3: Implement Id Type (no_std)

**Files:**
- Create: `reference_impl/sbo-types/src/id.rs`

**Step 1: Create id.rs**

Create file `reference_impl/sbo-types/src/id.rs`:

```rust
//! Validated identifier type (no_std compatible)

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::error::{ParseError, InvalidIdentifierReason};

/// Validated identifier (1-256 chars, RFC 3986 unreserved)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    /// Maximum identifier length
    pub const MAX_LEN: usize = 256;

    /// Create a new validated identifier
    pub fn new(s: &str) -> Result<Self, ParseError> {
        // Length check
        if s.is_empty() {
            return Err(ParseError::InvalidIdentifier(InvalidIdentifierReason::Empty));
        }
        if s.len() > Self::MAX_LEN {
            return Err(ParseError::InvalidIdentifier(InvalidIdentifierReason::TooLong));
        }

        // Character check: RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        for c in s.chars() {
            if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~') {
                return Err(ParseError::InvalidIdentifier(InvalidIdentifierReason::InvalidChar));
            }
        }

        Ok(Self(String::from(s)))
    }

    /// Get the identifier as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_id() {
        assert!(Id::new("alice").is_ok());
        assert!(Id::new("Bob-123").is_ok());
        assert!(Id::new("test_id.v1").is_ok());
    }

    #[test]
    fn test_invalid_id() {
        assert!(Id::new("").is_err());
        assert!(Id::new("has space").is_err());
        assert!(Id::new("has/slash").is_err());
    }
}
```

**Step 2: Run tests**

Run: `cd reference_impl && cargo test -p sbo-types`

Expected: PASS (2 tests)

---

## Task 4: Implement Path Type (no_std)

**Files:**
- Create: `reference_impl/sbo-types/src/path.rs`

**Step 1: Create path.rs**

Create file `reference_impl/sbo-types/src/path.rs`:

```rust
//! Path type for SBO objects (no_std compatible)

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec, format};

use crate::error::{ParseError, InvalidPathReason};
use crate::id::Id;

/// Path (e.g., "/alice/nfts/")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path(Vec<Id>);

impl Path {
    /// Parse a path string like "/alice/nfts/"
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        if !s.starts_with('/') {
            return Err(ParseError::InvalidPath(InvalidPathReason::MustStartWithSlash));
        }

        if !s.ends_with('/') {
            return Err(ParseError::InvalidPath(InvalidPathReason::MustEndWithSlash));
        }

        // Root path
        if s == "/" {
            return Ok(Self(Vec::new()));
        }

        let segments: Result<Vec<Id>, _> = s
            .trim_matches('/')
            .split('/')
            .map(Id::new)
            .collect();

        segments
            .map(Self)
            .map_err(|_| ParseError::InvalidPath(InvalidPathReason::InvalidSegment))
    }

    /// Get the root path
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Check if this is the root path
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the path segments
    pub fn segments(&self) -> &[Id] {
        &self.0
    }

    /// Get parent path (or None if root)
    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            None
        } else {
            Some(Self(self.0[..self.0.len() - 1].to_vec()))
        }
    }

    /// Format as string
    pub fn to_string(&self) -> String {
        if self.0.is_empty() {
            String::from("/")
        } else {
            let segments: Vec<&str> = self.0.iter().map(|id| id.as_str()).collect();
            format!("/{}/", segments.join("/"))
        }
    }
}

impl core::fmt::Display for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_path() {
        let path = Path::parse("/").unwrap();
        assert!(path.is_root());
        assert_eq!(path.to_string(), "/");
    }

    #[test]
    fn test_simple_path() {
        let path = Path::parse("/alice/nfts/").unwrap();
        assert!(!path.is_root());
        assert_eq!(path.segments().len(), 2);
        assert_eq!(path.to_string(), "/alice/nfts/");
    }

    #[test]
    fn test_parent() {
        let path = Path::parse("/alice/nfts/").unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent.to_string(), "/alice/");
    }

    #[test]
    fn test_invalid_paths() {
        assert!(Path::parse("no-leading-slash/").is_err());
        assert!(Path::parse("/no-trailing-slash").is_err());
    }
}
```

**Step 2: Run tests**

Run: `cd reference_impl && cargo test -p sbo-types`

Expected: PASS (6 tests total)

---

## Task 5: Implement Action Type (no_std)

**Files:**
- Create: `reference_impl/sbo-types/src/action.rs`

**Step 1: Create action.rs**

Create file `reference_impl/sbo-types/src/action.rs`:

```rust
//! SBO action types (no_std compatible)

use crate::error::ParseError;

/// SBO message action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Create a new object at a specific path (deterministic naming)
    Create,
    /// Post a new object (system assigns ID)
    Post,
    /// Update an existing object
    Update,
    /// Delete an object
    Delete,
    /// Transfer ownership or move an object
    Transfer,
    /// Import an object from another chain
    Import,
}

impl Action {
    /// Parse action from string
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        match s.to_lowercase().as_str() {
            "create" => Ok(Action::Create),
            "post" => Ok(Action::Post),
            "update" => Ok(Action::Update),
            "delete" => Ok(Action::Delete),
            "transfer" => Ok(Action::Transfer),
            "import" => Ok(Action::Import),
            _ => Err(ParseError::InvalidAction),
        }
    }

    /// Get action name as string
    pub fn name(&self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Post => "post",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Transfer => "transfer",
            Action::Import => "import",
        }
    }
}

impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_actions() {
        assert_eq!(Action::parse("create").unwrap(), Action::Create);
        assert_eq!(Action::parse("POST").unwrap(), Action::Post);
        assert_eq!(Action::parse("Update").unwrap(), Action::Update);
    }

    #[test]
    fn test_invalid_action() {
        assert!(Action::parse("invalid").is_err());
    }
}
```

**Step 2: Run all tests**

Run: `cd reference_impl && cargo test -p sbo-types`

Expected: PASS (8 tests total)

**Step 3: Verify no_std compilation**

Run: `cd reference_impl && cargo check -p sbo-types --no-default-features --features alloc`

Expected: Success (compiles without std)

**Step 4: Commit**

```bash
cd reference_impl
git add sbo-types/
git add Cargo.toml
git commit -m "feat: add sbo-types crate with no_std support

- Id type with RFC 3986 validation
- Path type with segment parsing
- Action enum for SBO operations
- All types are no_std compatible with alloc feature"
```

---

## Task 6: Add serde Support to sbo-types

**Files:**
- Modify: `reference_impl/sbo-types/Cargo.toml`
- Modify: `reference_impl/sbo-types/src/id.rs`
- Modify: `reference_impl/sbo-types/src/path.rs`
- Modify: `reference_impl/sbo-types/src/action.rs`

**Step 1: Add serde dependency**

Edit `reference_impl/sbo-types/Cargo.toml`:

```toml
[package]
name = "sbo-types"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "SBO core types (no_std compatible)"

[features]
default = ["std"]
std = ["alloc", "serde?/std"]
alloc = []
serde = ["dep:serde"]

[dependencies]
serde = { version = "1", default-features = false, features = ["derive", "alloc"], optional = true }
```

**Step 2: Add serde derives to Id**

Edit `reference_impl/sbo-types/src/id.rs`, add at top after imports:

```rust
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, Serializer, Deserializer};
```

Add after the `Id` struct definition:

```rust
#[cfg(feature = "serde")]
impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Id::new(&s).map_err(serde::de::Error::custom)
    }
}
```

**Step 3: Add serde derives to Path**

Edit `reference_impl/sbo-types/src/path.rs`, add at top after imports:

```rust
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, Serializer, Deserializer};
```

Add after the `Path` struct definition:

```rust
#[cfg(feature = "serde")]
impl Serialize for Path {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Path {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Path::parse(&s).map_err(serde::de::Error::custom)
    }
}
```

**Step 4: Add serde derives to Action**

Edit `reference_impl/sbo-types/src/action.rs`, add at top:

```rust
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
```

Change the Action enum to:

```rust
/// SBO message action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Action {
    // ... existing variants
}
```

**Step 5: Verify serde compilation**

Run: `cd reference_impl && cargo check -p sbo-types --features serde`

Expected: Success

**Step 6: Commit**

```bash
cd reference_impl
git add sbo-types/
git commit -m "feat(sbo-types): add optional serde support"
```

---

## Task 7: Create sbo-crypto Crate with BLS12-381

**Files:**
- Create: `reference_impl/sbo-crypto/Cargo.toml`
- Create: `reference_impl/sbo-crypto/src/lib.rs`
- Create: `reference_impl/sbo-crypto/src/error.rs`
- Create: `reference_impl/sbo-crypto/src/hash.rs`
- Modify: `reference_impl/Cargo.toml` (workspace)

**Step 1: Create directory and Cargo.toml**

```bash
mkdir -p reference_impl/sbo-crypto/src
```

Create `reference_impl/sbo-crypto/Cargo.toml`:

```toml
[package]
name = "sbo-crypto"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "SBO cryptographic operations (no_std compatible)"

[features]
default = ["std", "ed25519", "bls"]
std = ["alloc", "sha2/std", "ed25519-dalek?/std", "blst?/std"]
alloc = []
ed25519 = ["dep:ed25519-dalek"]
bls = ["dep:blst"]

[dependencies]
sha2 = { version = "0.10", default-features = false }
hex = { version = "0.4", default-features = false, features = ["alloc"] }
ed25519-dalek = { version = "2", default-features = false, features = ["alloc"], optional = true }
blst = { version = "0.3", default-features = false, optional = true }
rand = { version = "0.8", default-features = false, optional = true }

[dev-dependencies]
rand = "0.8"
```

**Step 2: Create lib.rs**

Create `reference_impl/sbo-crypto/src/lib.rs`:

```rust
//! SBO Cryptographic Operations
//!
//! Provides signature verification and hashing for SBO.
//! Supports both Ed25519 and BLS12-381 signatures.
//!
//! This crate is `no_std` compatible for zkVM use.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;

pub mod error;
pub mod hash;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "bls")]
pub mod bls;

pub use error::CryptoError;
pub use hash::{sha256, ContentHash, HashAlgo};
```

**Step 3: Create error.rs**

Create `reference_impl/sbo-crypto/src/error.rs`:

```rust
//! Crypto error types (no_std compatible)

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Cryptographic operation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid signature
    InvalidSignature,
    /// Invalid public key
    InvalidPublicKey,
    /// Unknown algorithm
    UnknownAlgorithm,
    /// Invalid key length
    InvalidKeyLength,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
            CryptoError::UnknownAlgorithm => write!(f, "Unknown algorithm"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
```

**Step 4: Create hash.rs**

Create `reference_impl/sbo-crypto/src/hash.rs`:

```rust
//! Hashing utilities (no_std compatible)

use sha2::{Sha256, Digest};
use crate::error::CryptoError;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
}

/// Content hash with algorithm identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHash {
    pub algo: HashAlgo,
    pub bytes: [u8; 32],
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

impl ContentHash {
    /// Create a new SHA-256 content hash
    pub fn sha256(data: &[u8]) -> Self {
        Self {
            algo: HashAlgo::Sha256,
            bytes: sha256(data),
        }
    }

    /// Parse from "algo:hex" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let (algo_str, hex_str) = s
            .split_once(':')
            .ok_or(CryptoError::UnknownAlgorithm)?;

        let algo = match algo_str {
            "sha256" => HashAlgo::Sha256,
            _ => return Err(CryptoError::UnknownAlgorithm),
        };

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { algo, bytes: arr })
    }

    /// Format as "algo:hex"
    pub fn to_string(&self) -> String {
        let algo_str = match self.algo {
            HashAlgo::Sha256 => "sha256",
        };
        alloc::format!("{}:{}", algo_str, hex::encode(self.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_content_hash_roundtrip() {
        let hash = ContentHash::sha256(b"hello");
        let s = hash.to_string();
        let parsed = ContentHash::parse(&s).unwrap();
        assert_eq!(hash, parsed);
    }
}
```

**Step 5: Add to workspace**

Edit `reference_impl/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["sbo-core", "sbo-avail", "sbo-daemon", "sbo-cli", "sbo-types", "sbo-crypto"]
```

**Step 6: Verify compilation**

Run: `cd reference_impl && cargo check -p sbo-crypto`

Expected: Success (warnings about unused bls/ed25519 features ok for now)

**Step 7: Commit**

```bash
cd reference_impl
git add sbo-crypto/
git add Cargo.toml
git commit -m "feat: add sbo-crypto crate with hash support

- SHA-256 hashing (no_std compatible)
- ContentHash type with algo:hex format
- Feature flags for ed25519 and bls (modules coming next)"
```

---

## Task 8: Implement Ed25519 in sbo-crypto

**Files:**
- Create: `reference_impl/sbo-crypto/src/ed25519.rs`

**Step 1: Create ed25519.rs**

Create `reference_impl/sbo-crypto/src/ed25519.rs`:

```rust
//! Ed25519 signature operations (no_std compatible)

use crate::error::CryptoError;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Ed25519 public key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub bytes: [u8; 32],
}

/// Ed25519 signature (64 bytes)
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 64]);

impl PublicKey {
    /// Parse from "ed25519:<hex>" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let hex_str = s
            .strip_prefix("ed25519:")
            .ok_or(CryptoError::UnknownAlgorithm)?;

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Format as "ed25519:<hex>"
    pub fn to_string(&self) -> String {
        alloc::format!("ed25519:{}", hex::encode(self.bytes))
    }

    /// Get algorithm prefix
    pub fn algorithm() -> &'static str {
        "ed25519"
    }
}

impl Signature {
    /// Parse from hex string
    pub fn parse(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Format as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Verify an Ed25519 signature
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_parse_roundtrip() {
        let key_hex = "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pubkey = PublicKey::parse(key_hex).unwrap();
        assert_eq!(pubkey.to_string(), key_hex);
    }

    #[test]
    fn test_signature_parse_roundtrip() {
        let sig_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sig = Signature::parse(sig_hex).unwrap();
        assert_eq!(sig.to_hex(), sig_hex);
    }
}
```

**Step 2: Run tests**

Run: `cd reference_impl && cargo test -p sbo-crypto`

Expected: PASS (4 tests)

**Step 3: Commit**

```bash
cd reference_impl
git add sbo-crypto/
git commit -m "feat(sbo-crypto): add ed25519 signature verification"
```

---

## Task 9: Implement BLS12-381 in sbo-crypto

**Files:**
- Create: `reference_impl/sbo-crypto/src/bls.rs`

**Step 1: Create bls.rs**

Create `reference_impl/sbo-crypto/src/bls.rs`:

```rust
//! BLS12-381 signature operations (no_std compatible)
//!
//! Uses the `blst` crate which has RISC Zero zkVM acceleration.

use crate::error::CryptoError;

#[cfg(feature = "alloc")]
use alloc::string::String;

use blst::min_pk::{PublicKey as BlstPublicKey, Signature as BlstSignature};

/// BLS12-381 public key (48 bytes compressed G1 point)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub bytes: [u8; 48],
}

/// BLS12-381 signature (96 bytes compressed G2 point)
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 96]);

/// Domain separation tag for SBO signatures
const DST: &[u8] = b"SBO_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

impl PublicKey {
    /// Parse from "bls12-381:<hex>" format
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let hex_str = s
            .strip_prefix("bls12-381:")
            .ok_or(CryptoError::UnknownAlgorithm)?;

        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        if bytes.len() != 48 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Format as "bls12-381:<hex>"
    pub fn to_string(&self) -> String {
        alloc::format!("bls12-381:{}", hex::encode(self.bytes))
    }

    /// Get algorithm prefix
    pub fn algorithm() -> &'static str {
        "bls12-381"
    }
}

impl Signature {
    /// Parse from hex string
    pub fn parse(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if bytes.len() != 96 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Format as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Verify a BLS12-381 signature
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    let pk = BlstPublicKey::from_bytes(&public_key.bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = BlstSignature::from_bytes(&signature.0)
        .map_err(|_| CryptoError::InvalidSignature)?;

    let result = sig.verify(true, message, DST, &[], &pk, true);

    if result == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_parse_format() {
        // 48 bytes = 96 hex chars
        let hex_key = "bls12-381:".to_string() + &"ab".repeat(48);
        let pk = PublicKey::parse(&hex_key).unwrap();
        assert_eq!(pk.to_string(), hex_key);
    }

    #[test]
    fn test_signature_parse_format() {
        // 96 bytes = 192 hex chars
        let hex_sig = "cd".repeat(96);
        let sig = Signature::parse(&hex_sig).unwrap();
        assert_eq!(sig.to_hex(), hex_sig);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = "bls12-381:abcd";
        assert!(PublicKey::parse(short_key).is_err());
    }
}
```

**Step 2: Run tests**

Run: `cd reference_impl && cargo test -p sbo-crypto`

Expected: PASS (7 tests)

**Step 3: Verify no_std compilation (without blst for now)**

Run: `cd reference_impl && cargo check -p sbo-crypto --no-default-features --features "alloc,ed25519"`

Expected: Success

**Step 4: Commit**

```bash
cd reference_impl
git add sbo-crypto/
git commit -m "feat(sbo-crypto): add BLS12-381 signature support

- Uses blst crate (has RISC Zero zkVM acceleration)
- 48-byte compressed G1 public keys
- 96-byte compressed G2 signatures
- SBO-specific domain separation tag"
```

---

## Task 10: Update sbo-core to Use New Crates

**Files:**
- Modify: `reference_impl/sbo-core/Cargo.toml`
- Modify: `reference_impl/sbo-core/src/lib.rs`
- Modify: `reference_impl/sbo-core/src/crypto/mod.rs`

**Step 1: Add dependencies to sbo-core**

Edit `reference_impl/sbo-core/Cargo.toml`, add:

```toml
[dependencies]
# ... existing deps ...
sbo-types = { path = "../sbo-types", features = ["serde"] }
sbo-crypto = { path = "../sbo-crypto" }
```

**Step 2: Re-export from lib.rs**

Edit `reference_impl/sbo-core/src/lib.rs`, add at bottom:

```rust
// Re-export types from sbo-types
pub use sbo_types::{Id, Path, Action};
pub use sbo_types::error::ParseError as TypesParseError;

// Re-export crypto from sbo-crypto
pub use sbo_crypto::{sha256, ContentHash, HashAlgo, CryptoError};
pub use sbo_crypto::ed25519 as ed25519_new;
#[cfg(feature = "bls")]
pub use sbo_crypto::bls;
```

**Step 3: Add bls feature to sbo-core**

Edit `reference_impl/sbo-core/Cargo.toml`, add features section:

```toml
[features]
default = []
bls = ["sbo-crypto/bls"]
```

**Step 4: Verify compilation**

Run: `cd reference_impl && cargo build`

Expected: Success (may have warnings about unused imports)

**Step 5: Run all tests**

Run: `cd reference_impl && cargo test`

Expected: All existing tests pass

**Step 6: Commit**

```bash
cd reference_impl
git add sbo-core/
git commit -m "feat(sbo-core): integrate sbo-types and sbo-crypto

- Re-export types from sbo-types
- Re-export crypto from sbo-crypto
- Add bls feature flag for BLS12-381 support"
```

---

## Summary

This plan creates the foundation for zkVM compatibility:

1. **sbo-types** - `no_std` compatible core types (Id, Path, Action)
2. **sbo-crypto** - `no_std` compatible crypto (SHA-256, Ed25519, BLS12-381)
3. **sbo-core** - Re-exports new crates, maintains backward compatibility

Next phases will:
- Migrate sbo-core to use sbo-types/sbo-crypto internally (remove duplication)
- Add Merkle state tree
- Create zkVM guest program
