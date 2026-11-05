//! Action types.
//!
//! The wire `Action` grammar lives in `sbo-types` (audit 2026-11 Q36) and is
//! re-exported here; `Action::parse` is an exact lowercase match on the four
//! wire actions and yields `sbo_types::ParseError::InvalidAction`.
pub use sbo_types::Action;
