//! Error types for sbo-types (no_std compatible)

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
    /// `.` and `..` are reserved path semantics, not ids (Core spec
    /// §Identifier Syntax; audit 2026-11 D21 / Q24).
    DotSegment,
    /// An identity reference carries exactly one `@` (Q5 / D54).
    IdentityMultipleAt,
    /// The local part before `@` is empty (Q5).
    IdentityEmptyLocal,
    /// The domain after `@` is empty (Q5).
    IdentityEmptyDomain,
    /// The on-chain form of an identity reference has a lowercase domain;
    /// an uppercase domain in a header is invalid (Q5 / D13).
    IdentityDomainNotLowercase,
}

/// Reason for invalid path
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPathReason {
    MustStartWithSlash,
    MustEndWithSlash,
    InvalidSegment(InvalidIdentifierReason),
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl core::fmt::Display for InvalidIdentifierReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Empty => "empty",
            Self::TooLong => "longer than 256 characters",
            Self::InvalidChar => "invalid character",
            Self::DotSegment => "`.` and `..` are not identifiers",
            Self::IdentityMultipleAt => "identity reference must contain exactly one `@`",
            Self::IdentityEmptyLocal => "identity reference has an empty local part",
            Self::IdentityEmptyDomain => "identity reference has an empty domain",
            Self::IdentityDomainNotLowercase => "identity domain must be lowercase",
        };
        f.write_str(s)
    }
}

impl core::fmt::Display for InvalidPathReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MustStartWithSlash => f.write_str("path must start with /"),
            Self::MustEndWithSlash => f.write_str("path must end with /"),
            Self::InvalidSegment(r) => write!(f, "invalid segment: {}", r),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::InvalidIdentifier(reason) => {
                write!(f, "Invalid identifier: {}", reason)
            }
            ParseError::InvalidPath(reason) => {
                write!(f, "Invalid path: {}", reason)
            }
            ParseError::InvalidAction => {
                write!(f, "Invalid action")
            }
        }
    }
}
