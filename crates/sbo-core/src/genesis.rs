//! Genesis block handling

use crate::error::ValidationError;
use crate::message::Message;
use crate::wire;
use crate::crypto::ContentHash;

/// Genesis block validator
pub struct Genesis;

impl Genesis {
    /// Validate genesis block (must contain sys identity + root policy)
    pub fn validate(_messages: &[Message]) -> Result<(), ValidationError> {
        todo!("Implement genesis validation")
    }
}

/// Compute the canonical genesis hash — the content-derived **verifying** half of a
/// database's identity (`{chain}:{appId}:{firstBlock}:{genesisHash}`).
///
/// `genesisHash = sha256(all_genesis_objects_bytes)`, where `all_genesis_objects_bytes`
/// is the canonical wire serialization of the ordered genesis messages concatenated with
/// no separators (each message is self-delimiting via its `Content-Length`). This is
/// exactly the byte sequence a genesis builder emits, and is reproducible offline from a
/// chain-read reconstruction because the wire serializer is deterministic. Returns a
/// [`ContentHash`] whose `to_string()` is `sha256:<hex>` — the form used in `?genesis=`
/// and the `_sbo` record's `genesis=` field.
pub fn genesis_hash(messages: &[Message]) -> ContentHash {
    let mut bytes = Vec::new();
    for m in messages {
        bytes.extend_from_slice(&wire::serialize(m));
    }
    ContentHash::sha256(&bytes)
}

/// Compute the genesis hash from raw genesis-batch wire bytes by parsing the batch and
/// re-serializing each message canonically (so the result is independent of any
/// incidental framing in the input). Equivalent to [`genesis_hash`] applied to the parsed
/// messages.
pub fn genesis_hash_from_wire(wire_bytes: &[u8]) -> Result<ContentHash, crate::error::ParseError> {
    let messages = wire::parse_batch(wire_bytes)?;
    Ok(genesis_hash(&messages))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_matches_wire_roundtrip() {
        // A hash computed over messages equals the hash computed from their wire batch.
        use crate::message::{Action, Id, ObjectType, Path};
        use crate::crypto::{Signature, SigningKey};

        let key = SigningKey::generate();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/test/").unwrap(),
            id: Id::new("a").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("text/plain".to_string()),
            content_hash: Some(ContentHash::sha256(b"hi")),
            payload: Some(b"hi".to_vec()),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: None,
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
        };
        msg.sign(&key);

        let batch = wire::serialize(&msg);
        let from_msgs = genesis_hash(std::slice::from_ref(&msg));
        let from_wire = genesis_hash_from_wire(&batch).unwrap();
        assert_eq!(from_msgs.to_string(), from_wire.to_string());
        assert!(from_msgs.to_string().starts_with("sha256:"));
    }
}
