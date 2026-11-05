//! Validated identifier type (no_std compatible).
//!
//! This is THE identifier grammar (Core spec §Identifier Syntax, as amended
//! by audit 2026-11 decisions Q5, Q24, Q36 and Q37). `sbo-core::message::Id`
//! and `sbo-wasm` re-export it; the zkVM guest uses it directly.

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::error::{InvalidIdentifierReason, ParseError};
use crate::identity::{self, IdentityError};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Validated identifier (1-256 chars, RFC 3986 unreserved plus `@`, `+`
/// and `:`; never `.` or `..`; at most one `@`, and then a well-formed
/// identity reference with a lowercase domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    /// Maximum identifier length
    pub const MAX_LEN: usize = 256;

    /// Create a new validated identifier
    pub fn new(s: impl AsRef<str>) -> Result<Self, ParseError> {
        let s = s.as_ref();
        Self::check(s).map_err(ParseError::InvalidIdentifier)?;
        Ok(Self(String::from(s)))
    }

    /// The grammar check alone (no allocation).
    pub fn check(s: &str) -> Result<(), InvalidIdentifierReason> {
        // Length check
        if s.is_empty() {
            return Err(InvalidIdentifierReason::Empty);
        }
        if s.len() > Self::MAX_LEN {
            return Err(InvalidIdentifierReason::TooLong);
        }

        // Character check: RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // plus "@" for email-rooted identity references (e.g. alice@gmail.com),
        // "+" for their RFC-subaddressed forms (agent identities like
        // alice+bot@gmail.com — first-class owners under the browserid holder
        // model), and ":" for namespaced identifiers — attestation type IDs
        // (`role:moderator`) and algorithm-prefixed key references
        // (`ed25519:…`). All are safe since the state-key delimiter is the
        // Unit Separator (0x1F). ASCII only (Q37): no percent-encoding.
        for c in s.chars() {
            if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' | '@' | ':' | '+') {
                return Err(InvalidIdentifierReason::InvalidChar);
            }
        }

        // `.` and `..` carry path semantics (and would escape a filesystem
        // mirror); they are not ids (Q24 / D21).
        if s == "." || s == ".." {
            return Err(InvalidIdentifierReason::DotSegment);
        }

        // An id carrying `@` is an identity reference and follows the one
        // identity rule (Q5): exactly one `@`, both parts non-empty, and the
        // canonical on-chain form has a lowercase domain (D13 / D54).
        if s.contains('@') {
            match identity::split(s) {
                Ok((_, domain)) => {
                    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
                        return Err(InvalidIdentifierReason::IdentityDomainNotLowercase);
                    }
                }
                Err(IdentityError::MultipleAt) => return Err(InvalidIdentifierReason::IdentityMultipleAt),
                Err(IdentityError::EmptyLocal) => return Err(InvalidIdentifierReason::IdentityEmptyLocal),
                Err(IdentityError::EmptyDomain) => return Err(InvalidIdentifierReason::IdentityEmptyDomain),
                Err(IdentityError::NotAnIdentity) => unreachable!("contains '@'"),
            }
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_id() {
        assert!(Id::new("alice").is_ok());
        assert!(Id::new("Bob-123").is_ok());
        assert!(Id::new("test_id.v1").is_ok());
        assert!(Id::new("...x").is_ok());
    }

    #[test]
    fn test_invalid_id() {
        assert!(Id::new("").is_err());
        assert!(Id::new("has space").is_err());
        assert!(Id::new("has/slash").is_err());
        assert!(Id::new("caf%C3%A9").is_err());
        assert!(Id::new("café").is_err());
    }

    #[test]
    fn id_allows_email_and_namespaced_ids() {
        assert!(Id::new("alice@gmail.com").is_ok());
        assert!(Id::new("alice+bot@gmail.com").is_ok());
        assert!(Id::new("role:moderator").is_ok());
        assert!(Id::new("ed25519:abc").is_ok());
        assert!(Id::new("null:").is_ok());
    }

    #[test]
    fn dot_segments_are_not_ids() {
        assert_eq!(Id::check("."), Err(InvalidIdentifierReason::DotSegment));
        assert_eq!(Id::check(".."), Err(InvalidIdentifierReason::DotSegment));
    }

    #[test]
    fn identity_rule() {
        assert_eq!(Id::check("a@b@c"), Err(InvalidIdentifierReason::IdentityMultipleAt));
        assert_eq!(Id::check("@example.com"), Err(InvalidIdentifierReason::IdentityEmptyLocal));
        assert_eq!(Id::check("alice@"), Err(InvalidIdentifierReason::IdentityEmptyDomain));
        assert_eq!(Id::check("alice@Example.COM"), Err(InvalidIdentifierReason::IdentityDomainNotLowercase));
        // The local part is byte-exact: uppercase there is fine.
        assert!(Id::new("Alice@example.com").is_ok());
    }
}
