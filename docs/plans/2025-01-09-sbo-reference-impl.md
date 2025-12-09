# SBO Reference Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a working SBO client that can parse messages, verify signatures, evaluate policies, manage state, and interact with the Avail DA layer.

**Architecture:** Hybrid crate structure with sbo-core (wire format, crypto, policy, state), sbo-avail (DA integration), and sbo-cli (user interface). TDD approach with frequent commits.

**Tech Stack:** Rust, ed25519-dalek, sha2, RocksDB, tokio, clap

---

## Phase 1: Wire Format Parser

### Task 1.1: Parse Header Lines

**Files:**
- Modify: `reference_impl/sbo-core/src/wire/parser.rs`
- Modify: `reference_impl/sbo-core/src/wire/headers.rs`
- Create: `reference_impl/sbo-core/tests/wire_parser_test.rs`

**Step 1: Write the failing test**

Create `reference_impl/sbo-core/tests/wire_parser_test.rs`:
```rust
use sbo_core::wire::HeaderMap;

#[test]
fn test_parse_single_header() {
    let line = b"Content-Type: application/json";
    let (name, value) = sbo_core::wire::parse_header_line(line).unwrap();
    assert_eq!(name, "Content-Type");
    assert_eq!(value, "application/json");
}

#[test]
fn test_parse_header_rejects_crlf() {
    let line = b"Content-Type: application/json\r";
    let result = sbo_core::wire::parse_header_line(line);
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test`
Expected: FAIL with "cannot find function `parse_header_line`"

**Step 3: Write minimal implementation**

In `reference_impl/sbo-core/src/wire/parser.rs`:
```rust
use crate::error::ParseError;

/// Parse a single header line "Name: value"
pub fn parse_header_line(line: &[u8]) -> Result<(&str, &str), ParseError> {
    // Reject CRLF
    if line.contains(&b'\r') {
        return Err(ParseError::CrlfNotAllowed);
    }

    let line_str = std::str::from_utf8(line)
        .map_err(|_| ParseError::InvalidHeader("Invalid UTF-8".to_string()))?;

    let colon_pos = line_str.find(": ")
        .ok_or_else(|| ParseError::InvalidHeader("Missing ': ' separator".to_string()))?;

    let name = &line_str[..colon_pos];
    let value = &line_str[colon_pos + 2..];

    Ok((name, value))
}
```

In `reference_impl/sbo-core/src/wire/mod.rs`, add:
```rust
pub use parser::parse_header_line;
```

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat(wire): add header line parsing with CRLF rejection"
```

---

### Task 1.2: Split Message into Headers and Payload

**Files:**
- Modify: `reference_impl/sbo-core/src/wire/parser.rs`
- Modify: `reference_impl/sbo-core/tests/wire_parser_test.rs`

**Step 1: Write the failing test**

Add to `wire_parser_test.rs`:
```rust
#[test]
fn test_split_message() {
    let msg = b"SBO-Version: 0.5\nAction: post\n\n{\"hello\":\"world\"}";
    let (headers, payload) = sbo_core::wire::split_message(msg).unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(payload, b"{\"hello\":\"world\"}");
}

#[test]
fn test_split_message_no_blank_line() {
    let msg = b"SBO-Version: 0.5\nAction: post";
    let result = sbo_core::wire::split_message(msg);
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test`
Expected: FAIL with "cannot find function `split_message`"

**Step 3: Write minimal implementation**

In `parser.rs`:
```rust
/// Split message into header lines and payload at blank line
pub fn split_message(bytes: &[u8]) -> Result<(Vec<(&str, &str)>, &[u8]), ParseError> {
    // Find blank line (double LF)
    let mut pos = 0;
    let mut headers = Vec::new();

    while pos < bytes.len() {
        // Find next LF
        let line_end = bytes[pos..].iter().position(|&b| b == b'\n')
            .map(|p| pos + p)
            .unwrap_or(bytes.len());

        let line = &bytes[pos..line_end];

        // Empty line = end of headers
        if line.is_empty() {
            let payload = &bytes[line_end + 1..];
            return Ok((headers, payload));
        }

        let (name, value) = parse_header_line(line)?;
        headers.push((name, value));

        pos = line_end + 1;
    }

    Err(ParseError::MissingBlankLine)
}
```

In `mod.rs`, add:
```rust
pub use parser::split_message;
```

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat(wire): split message into headers and payload"
```

---

### Task 1.3: Parse Complete Message

**Files:**
- Modify: `reference_impl/sbo-core/src/wire/parser.rs`
- Modify: `reference_impl/sbo-core/tests/wire_parser_test.rs`

**Step 1: Write the failing test**

Add to `wire_parser_test.rs`:
```rust
#[test]
fn test_parse_minimal_message() {
    let msg = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: hello\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 17\n\
Content-Hash: sha256:4b7a3c8f2e1d5a9b0c6e3f7a2d4b8c1e5f9a3d7b0c4e8f2a6d9b3c7e1f5a9d3b\n\
Signing-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"hello\":\"world\"}";

    let result = sbo_core::wire::parse(msg);
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let message = result.unwrap();
    assert_eq!(message.path.to_string(), "/test/");
    assert_eq!(message.id.as_str(), "hello");
}
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test test_parse_minimal`
Expected: FAIL (parse returns todo!())

**Step 3: Write minimal implementation**

Replace `parser.rs` `parse` function:
```rust
use crate::message::{Message, Action, ObjectType, Id, Path, Related};
use crate::crypto::{PublicKey, Signature, ContentHash};
use crate::error::ParseError;

/// Parse raw bytes into a validated Message
pub fn parse(bytes: &[u8]) -> Result<Message, ParseError> {
    let (headers, payload) = split_message(bytes)?;
    let headers: std::collections::HashMap<&str, &str> = headers.into_iter().collect();

    // Required headers
    let version = headers.get("SBO-Version")
        .ok_or_else(|| ParseError::MissingHeader("SBO-Version".to_string()))?;
    if *version != "0.5" {
        return Err(ParseError::UnsupportedVersion(version.to_string()));
    }

    let action_str = headers.get("Action")
        .ok_or_else(|| ParseError::MissingHeader("Action".to_string()))?;
    let action = Action::parse(action_str)
        .map_err(|e| ParseError::InvalidHeader(format!("Action: {}", e)))?;

    let path = Path::parse(headers.get("Path")
        .ok_or_else(|| ParseError::MissingHeader("Path".to_string()))?)?;

    let id = Id::new(headers.get("ID")
        .ok_or_else(|| ParseError::MissingHeader("ID".to_string()))?)?;

    let object_type = match *headers.get("Type")
        .ok_or_else(|| ParseError::MissingHeader("Type".to_string()))? {
        "object" => ObjectType::Object,
        "collection" => ObjectType::Collection,
        other => return Err(ParseError::InvalidHeader(format!("Type: {}", other))),
    };

    // Content headers
    let content_type = headers.get("Content-Type").map(|s| s.to_string());
    let content_hash = headers.get("Content-Hash")
        .map(|s| ContentHash::parse(s))
        .transpose()
        .map_err(|e| ParseError::InvalidHeader(format!("Content-Hash: {:?}", e)))?;

    // Validate payload
    if let Some(len_str) = headers.get("Content-Length") {
        let expected_len: usize = len_str.parse()
            .map_err(|_| ParseError::InvalidHeader("Content-Length not a number".to_string()))?;
        if payload.len() != expected_len {
            return Err(ParseError::ContentLengthMismatch {
                expected: expected_len,
                actual: payload.len(),
            });
        }
    }

    if let Some(ref hash) = content_hash {
        let actual = crate::crypto::sha256(payload);
        if actual != hash.bytes {
            return Err(ParseError::ContentHashMismatch);
        }
    }

    // Crypto headers
    let signing_key = PublicKey::parse(headers.get("Signing-Key")
        .ok_or_else(|| ParseError::MissingHeader("Signing-Key".to_string()))?)
        .map_err(|e| ParseError::InvalidHeader(format!("Signing-Key: {:?}", e)))?;

    let signature = Signature::parse(headers.get("Signature")
        .ok_or_else(|| ParseError::MissingHeader("Signature".to_string()))?)
        .map_err(|e| ParseError::InvalidHeader(format!("Signature: {:?}", e)))?;

    // Optional headers
    let owner = headers.get("Owner").map(|s| Id::new(*s)).transpose()?;
    let creator = headers.get("Creator").map(|s| Id::new(*s)).transpose()?;
    let content_encoding = headers.get("Content-Encoding").map(|s| s.to_string());
    let content_schema = headers.get("Content-Schema").map(|s| s.to_string());
    let policy_ref = headers.get("Policy-Ref").map(|s| s.to_string());

    Ok(Message {
        action,
        path,
        id,
        object_type,
        signing_key,
        signature,
        content_type,
        content_hash,
        payload: Some(payload.to_vec()),
        owner,
        creator,
        content_encoding,
        content_schema,
        policy_ref,
        related: None,
    })
}
```

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test test_parse_minimal`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat(wire): implement full message parsing"
```

---

## Phase 2: Wire Format Serializer

### Task 2.1: Serialize Headers in Canonical Order

**Files:**
- Modify: `reference_impl/sbo-core/src/wire/serializer.rs`
- Modify: `reference_impl/sbo-core/tests/wire_parser_test.rs`

**Step 1: Write the failing test**

Add to `wire_parser_test.rs`:
```rust
#[test]
fn test_roundtrip_message() {
    let original = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: hello\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 17\n\
Content-Hash: sha256:4d7953c30e8f2c3a7b6d0f1e5a9c8b2d4f6e3a1b0c9d8e7f6a5b4c3d2e1f0a9b\n\
Signing-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"hello\":\"world\"}";

    let msg = sbo_core::wire::parse(original).unwrap();
    let serialized = sbo_core::wire::serialize(&msg);
    let reparsed = sbo_core::wire::parse(&serialized).unwrap();

    assert_eq!(msg.path.to_string(), reparsed.path.to_string());
    assert_eq!(msg.id.as_str(), reparsed.id.as_str());
}
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test test_roundtrip`
Expected: FAIL (serialize returns todo!())

**Step 3: Write minimal implementation**

Replace `serializer.rs`:
```rust
use crate::message::{Message, Action, ObjectType};

/// Canonical header order per Wire Format spec
const HEADER_ORDER: &[&str] = &[
    "SBO-Version",
    "Action",
    "Path",
    "ID",
    "Type",
    "Content-Type",
    "Content-Encoding",
    "Content-Length",
    "Content-Hash",
    "Attestation",
    "Content-Schema",
    "Creator",
    "New-ID",
    "New-Owner",
    "New-Path",
    "Object-Path",
    "Origin",
    "Owner",
    "Policy-Ref",
    "Proof",
    "Proof-Type",
    "Registry-Path",
    "Related",
    "Signing-Key",
    "Signature",
];

/// Serialize a Message to wire format bytes
pub fn serialize(msg: &Message) -> Vec<u8> {
    let mut headers: Vec<(String, String)> = Vec::new();

    headers.push(("SBO-Version".to_string(), "0.5".to_string()));
    headers.push(("Action".to_string(), msg.action.name().to_string()));
    headers.push(("Path".to_string(), msg.path.to_string()));
    headers.push(("ID".to_string(), msg.id.as_str().to_string()));
    headers.push(("Type".to_string(), match msg.object_type {
        ObjectType::Object => "object",
        ObjectType::Collection => "collection",
    }.to_string()));

    if let Some(ref ct) = msg.content_type {
        headers.push(("Content-Type".to_string(), ct.clone()));
    }
    if let Some(ref ce) = msg.content_encoding {
        headers.push(("Content-Encoding".to_string(), ce.clone()));
    }
    if let Some(ref payload) = msg.payload {
        headers.push(("Content-Length".to_string(), payload.len().to_string()));
    }
    if let Some(ref ch) = msg.content_hash {
        headers.push(("Content-Hash".to_string(), ch.to_string()));
    }
    if let Some(ref cs) = msg.content_schema {
        headers.push(("Content-Schema".to_string(), cs.clone()));
    }
    if let Some(ref creator) = msg.creator {
        headers.push(("Creator".to_string(), creator.as_str().to_string()));
    }
    if let Some(ref owner) = msg.owner {
        headers.push(("Owner".to_string(), owner.as_str().to_string()));
    }
    if let Some(ref pr) = msg.policy_ref {
        headers.push(("Policy-Ref".to_string(), pr.clone()));
    }

    headers.push(("Signing-Key".to_string(), msg.signing_key.to_string()));
    headers.push(("Signature".to_string(), msg.signature.to_hex()));

    // Sort by canonical order
    headers.sort_by_key(|(name, _)| {
        HEADER_ORDER.iter().position(|&h| h == name).unwrap_or(999)
    });

    // Build output
    let mut output = Vec::new();
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.push(b'\n');
    }
    output.push(b'\n');

    if let Some(ref payload) = msg.payload {
        output.extend_from_slice(payload);
    }

    output
}
```

In `mod.rs`, add:
```rust
pub use serializer::serialize;
```

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test wire_parser_test test_roundtrip`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat(wire): implement canonical serialization"
```

---

## Phase 3: Message Signing and Verification

### Task 3.1: Build Canonical Signing Content

**Files:**
- Modify: `reference_impl/sbo-core/src/message/validate.rs`
- Create: `reference_impl/sbo-core/tests/signature_test.rs`

**Step 1: Write the failing test**

Create `reference_impl/sbo-core/tests/signature_test.rs`:
```rust
use sbo_core::crypto::SigningKey;
use sbo_core::message::{Message, Action, ObjectType, Id, Path};

#[test]
fn test_sign_and_verify_message() {
    let signing_key = SigningKey::generate();
    let public_key = signing_key.public_key();

    let payload = b"{\"test\":true}";
    let content_hash = sbo_core::crypto::ContentHash::sha256(payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: sbo_core::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
    };

    // Sign the message
    msg.sign(&signing_key);

    // Verify should pass
    assert!(sbo_core::message::verify_message(&msg).is_ok());
}

#[test]
fn test_verify_fails_with_wrong_key() {
    let signing_key = SigningKey::generate();
    let wrong_key = SigningKey::generate();

    let payload = b"{\"test\":true}";
    let content_hash = sbo_core::crypto::ContentHash::sha256(payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        object_type: ObjectType::Object,
        signing_key: wrong_key.public_key(), // Wrong key!
        signature: sbo_core::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
    };

    msg.sign(&signing_key);

    // Verify should fail
    assert!(sbo_core::message::verify_message(&msg).is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test signature_test`
Expected: FAIL (methods not found)

**Step 3: Write minimal implementation**

Add to `reference_impl/sbo-core/src/message/envelope.rs`:
```rust
impl Message {
    /// Build canonical signing content (headers without Signature + blank line)
    pub fn canonical_signing_content(&self) -> Vec<u8> {
        use crate::wire::serializer::HEADER_ORDER;

        let mut headers: Vec<(String, String)> = Vec::new();

        headers.push(("SBO-Version".to_string(), "0.5".to_string()));
        headers.push(("Action".to_string(), self.action.name().to_string()));
        headers.push(("Path".to_string(), self.path.to_string()));
        headers.push(("ID".to_string(), self.id.as_str().to_string()));
        headers.push(("Type".to_string(), match self.object_type {
            ObjectType::Object => "object",
            ObjectType::Collection => "collection",
        }.to_string()));

        if let Some(ref ct) = self.content_type {
            headers.push(("Content-Type".to_string(), ct.clone()));
        }
        if let Some(ref ce) = self.content_encoding {
            headers.push(("Content-Encoding".to_string(), ce.clone()));
        }
        if let Some(ref payload) = self.payload {
            headers.push(("Content-Length".to_string(), payload.len().to_string()));
        }
        if let Some(ref ch) = self.content_hash {
            headers.push(("Content-Hash".to_string(), ch.to_string()));
        }
        if let Some(ref cs) = self.content_schema {
            headers.push(("Content-Schema".to_string(), cs.clone()));
        }
        if let Some(ref creator) = self.creator {
            headers.push(("Creator".to_string(), creator.as_str().to_string()));
        }
        if let Some(ref owner) = self.owner {
            headers.push(("Owner".to_string(), owner.as_str().to_string()));
        }
        if let Some(ref pr) = self.policy_ref {
            headers.push(("Policy-Ref".to_string(), pr.clone()));
        }
        headers.push(("Signing-Key".to_string(), self.signing_key.to_string()));
        // NOTE: Signature is NOT included in signing content

        // Sort by canonical order (same as serializer)
        let order: &[&str] = &[
            "SBO-Version", "Action", "Path", "ID", "Type",
            "Content-Type", "Content-Encoding", "Content-Length", "Content-Hash",
            "Attestation", "Content-Schema", "Creator", "New-ID", "New-Owner",
            "New-Path", "Object-Path", "Origin", "Owner", "Policy-Ref",
            "Proof", "Proof-Type", "Registry-Path", "Related", "Signing-Key",
        ];
        headers.sort_by_key(|(name, _)| {
            order.iter().position(|&h| h == name).unwrap_or(999)
        });

        let mut output = Vec::new();
        for (name, value) in headers {
            output.extend_from_slice(name.as_bytes());
            output.extend_from_slice(b": ");
            output.extend_from_slice(value.as_bytes());
            output.push(b'\n');
        }
        output.push(b'\n');

        output
    }

    /// Sign this message
    pub fn sign(&mut self, signing_key: &crate::crypto::SigningKey) {
        let content = self.canonical_signing_content();
        self.signature = signing_key.sign(&content);
    }
}
```

Replace `validate.rs`:
```rust
use crate::error::ValidationError;
use crate::crypto;
use super::Message;

/// Verify message signature
pub fn verify_message(msg: &Message) -> Result<(), ValidationError> {
    let content = msg.canonical_signing_content();

    crypto::verify(&msg.signing_key, &content, &msg.signature)
        .map_err(|_| ValidationError::InvalidAction("Signature verification failed".to_string()))
}
```

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test signature_test`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat(message): implement signing and verification"
```

---

## Phase 4: DA Integration Stubs

### Task 4.1: Implement Test Preset Generation

**Files:**
- Modify: `reference_impl/sbo-cli/src/commands/da.rs`
- Create: `reference_impl/sbo-core/src/presets.rs`

**Step 1: Write the failing test**

Create `reference_impl/sbo-core/tests/preset_test.rs`:
```rust
use sbo_core::crypto::SigningKey;
use sbo_core::presets;

#[test]
fn test_generate_genesis_messages() {
    let signing_key = SigningKey::generate();
    let messages = presets::genesis(&signing_key);

    assert_eq!(messages.len(), 2);

    // First should be sys identity
    let sys = sbo_core::wire::parse(&messages[0]).unwrap();
    assert_eq!(sys.path.to_string(), "/sys/names/");
    assert_eq!(sys.id.as_str(), "sys");
    assert!(sbo_core::message::verify_message(&sys).is_ok());

    // Second should be root policy
    let policy = sbo_core::wire::parse(&messages[1]).unwrap();
    assert_eq!(policy.path.to_string(), "/sys/policies/");
    assert_eq!(policy.id.as_str(), "root");
    assert!(sbo_core::message::verify_message(&policy).is_ok());
}
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test preset_test`
Expected: FAIL (module not found)

**Step 3: Write minimal implementation**

Create `reference_impl/sbo-core/src/presets.rs`:
```rust
//! Test preset message generation

use crate::crypto::{SigningKey, ContentHash};
use crate::message::{Message, Action, ObjectType, Id, Path};
use crate::wire;

/// Generate genesis messages (sys identity + root policy)
pub fn genesis(signing_key: &SigningKey) -> Vec<Vec<u8>> {
    let public_key = signing_key.public_key();

    // 1. System identity claim
    let sys_payload = serde_json::json!({
        "public_key": public_key.to_string(),
        "display_name": "System"
    });
    let sys_bytes = serde_json::to_vec(&sys_payload).unwrap();
    let sys_hash = ContentHash::sha256(&sys_bytes);

    let mut sys_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("sys").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(sys_hash),
        payload: Some(sys_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.claim".to_string()),
        policy_ref: None,
        related: None,
    };
    sys_msg.sign(signing_key);

    // 2. Root policy
    let policy_payload = serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["update", "delete"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["*"], "on": "/$owner/**"}
        ]
    });
    let policy_bytes = serde_json::to_vec(&policy_payload).unwrap();
    let policy_hash = ContentHash::sha256(&policy_bytes);

    let mut policy_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(policy_hash),
        payload: Some(policy_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("policy.v2".to_string()),
        policy_ref: None,
        related: None,
    };
    policy_msg.sign(signing_key);

    vec![
        wire::serialize(&sys_msg),
        wire::serialize(&policy_msg),
    ]
}

/// Generate a simple post message
pub fn post(signing_key: &SigningKey, path: &str, id: &str, payload: &[u8]) -> Vec<u8> {
    let public_key = signing_key.public_key();
    let content_hash = ContentHash::sha256(payload);

    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(path).unwrap(),
        id: Id::new(id).unwrap(),
        object_type: ObjectType::Object,
        signing_key: public_key,
        signature: crate::crypto::Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(content_hash),
        payload: Some(payload.to_vec()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: None,
        policy_ref: None,
        related: None,
    };
    msg.sign(signing_key);

    wire::serialize(&msg)
}
```

Add to `lib.rs`:
```rust
pub mod presets;
```

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test preset_test`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat(presets): add genesis and post message generation"
```

---

## Phase 5: State Management

### Task 5.1: Store and Retrieve Objects

**Files:**
- Modify: `reference_impl/sbo-core/src/state/db.rs`
- Create: `reference_impl/sbo-core/tests/state_test.rs`

**Step 1: Write the failing test**

Create `reference_impl/sbo-core/tests/state_test.rs`:
```rust
use sbo_core::state::{StateDb, StoredObject};
use sbo_core::message::{Id, Path};
use sbo_core::crypto::ContentHash;
use tempfile::tempdir;

#[test]
fn test_store_and_retrieve_object() {
    let dir = tempdir().unwrap();
    let db = StateDb::open(dir.path()).unwrap();

    let obj = StoredObject {
        path: Path::parse("/test/").unwrap(),
        id: Id::new("hello").unwrap(),
        creator: Id::new("alice").unwrap(),
        owner: Id::new("alice").unwrap(),
        content_type: "application/json".to_string(),
        content_hash: ContentHash::sha256(b"{}"),
        payload: b"{}".to_vec(),
        policy_ref: None,
        block_number: 1,
    };

    db.put_object(&obj).unwrap();

    let retrieved = db.get_object(
        &Path::parse("/test/").unwrap(),
        &Id::new("alice").unwrap(),
        &Id::new("hello").unwrap(),
    ).unwrap();

    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id.as_str(), "hello");
    assert_eq!(retrieved.block_number, 1);
}
```

Add to `sbo-core/Cargo.toml`:
```toml
[dev-dependencies]
tokio = { workspace = true, features = ["rt", "macros"] }
tempfile = "3"
```

**Step 2: Run test to verify it fails**

Run: `cd reference_impl && cargo test --package sbo-core --test state_test`
Expected: May pass if implementation is complete, or fail on specific issues

**Step 3: Verify implementation works**

The existing `db.rs` should work. Run tests and fix any issues.

**Step 4: Run test to verify it passes**

Run: `cd reference_impl && cargo test --package sbo-core --test state_test`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "test(state): add storage tests"
```

---

## Phase 6: CLI Integration

### Task 6.1: Wire Up DA Submit Command

**Files:**
- Modify: `reference_impl/sbo-cli/src/commands/da.rs`

**Step 1: Update da.rs to use presets module**

Replace the generate_preset function to use sbo_core::presets.

**Step 2: Build and test CLI**

Run: `cd reference_impl && cargo build --release`

**Step 3: Test help output**

Run: `./target/release/sbo --help`
Run: `./target/release/sbo da submit --help`

**Step 4: Commit**

```bash
git add -A && git commit -m "feat(cli): wire up DA submit with presets"
```

---

## Summary

This plan covers:
1. Wire format parsing (Tasks 1.1-1.3)
2. Wire format serialization (Task 2.1)
3. Message signing and verification (Task 3.1)
4. Preset message generation (Task 4.1)
5. State storage (Task 5.1)
6. CLI integration (Task 6.1)

Each task follows TDD: write failing test → implement → verify → commit.

After completing these tasks, the client will be able to:
- Parse and serialize SBO messages
- Sign and verify signatures
- Generate valid genesis messages
- Store and retrieve objects from RocksDB
- Submit test payloads via CLI

Future phases (not in this plan):
- Avail light client integration
- Policy evaluation
- Full indexer implementation
- Block syncing
