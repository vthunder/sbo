//! SBO action types (no_std compatible).
//!
//! This is the wire grammar for the `Action` header (Wire Format spec): the
//! four lowercase names, no case folding. `create` and `update` are not wire
//! actions (`post` creates and updates). `sbo-core::message::Action` re-exports
//! this type.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::error::ParseError;
use crate::id::Id;
use crate::path::Path;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// SBO action types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create or update an object
    Post,

    /// Transfer ownership, path, and/or ID
    Transfer {
        new_owner: Option<Id>,
        new_path: Option<Path>,
        new_id: Option<Id>,
    },

    /// Delete an object (transfer to null owner)
    Delete,

    /// Import from external chain
    Import {
        origin: String,
        registry_path: Path,
        object_path: Path,
        attestation: Vec<u8>,
    },
}

impl Action {
    /// Parse action from header value (exact lowercase match)
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        match s {
            "post" => Ok(Action::Post),
            "delete" => Ok(Action::Delete),
            "transfer" => Ok(Action::Transfer {
                new_owner: None,
                new_path: None,
                new_id: None,
            }),
            "import" => Ok(Action::Import {
                origin: String::new(),
                registry_path: Path::root(),
                object_path: Path::root(),
                attestation: Vec::new(),
            }),
            _ => Err(ParseError::InvalidAction),
        }
    }

    /// Get the action name for wire format
    pub fn name(&self) -> &'static str {
        match self {
            Action::Post => "post",
            Action::Transfer { .. } => "transfer",
            Action::Delete => "delete",
            Action::Import { .. } => "import",
        }
    }
}

impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Serialized as the wire name (`"post"`, ...); transfer / import payloads
/// live in their own headers and are not carried here.
#[cfg(feature = "serde")]
impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Action::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_actions() {
        assert_eq!(Action::parse("post").unwrap(), Action::Post);
        assert_eq!(Action::parse("delete").unwrap(), Action::Delete);
        assert!(matches!(Action::parse("transfer").unwrap(), Action::Transfer { .. }));
        assert!(matches!(Action::parse("import").unwrap(), Action::Import { .. }));
    }

    #[test]
    fn test_invalid_action() {
        assert!(Action::parse("invalid").is_err());
        // No case folding; `create` / `update` are not wire actions.
        assert!(Action::parse("POST").is_err());
        assert!(Action::parse("Post").is_err());
        assert!(Action::parse("create").is_err());
        assert!(Action::parse("update").is_err());
        assert!(Action::parse("post ").is_err());
        assert!(Action::parse("").is_err());
    }
}
