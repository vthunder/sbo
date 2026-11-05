//! Message validation

use crate::error::ValidationError;
use crate::crypto;
use super::Message;

/// Verify the signature of an in-memory message over its canonical signing
/// content. For a message that came off the wire prefer [`verify_received`],
/// which verifies the bytes that were received.
pub fn verify_message(msg: &Message) -> Result<(), ValidationError> {
    let content = msg.canonical_signing_content();

    crypto::verify(&msg.signing_key, &content, &msg.signature)
        .map_err(|_| ValidationError::InvalidAction("Signature verification failed".to_string()))
}

/// Verify a parsed message against the bytes it was parsed from: the signing
/// content is the received header block minus the `Signature` line; nothing
/// is reserialized (decision Q32 (c), "bytes in, bytes out").
pub fn verify_received(msg: &Message, received: &[u8]) -> Result<(), ValidationError> {
    let content = crate::wire::signing_content(received)
        .map_err(|e| ValidationError::InvalidAction(format!("Signing content: {e}")))?;

    crypto::verify(&msg.signing_key, &content, &msg.signature)
        .map_err(|_| ValidationError::InvalidAction("Signature verification failed".to_string()))
}
