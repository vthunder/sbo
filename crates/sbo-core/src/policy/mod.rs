//! Policy evaluation

mod types;
mod evaluate;
mod path;
mod delegation;
pub mod glob;
pub mod validate;

pub use types::{Policy, Grant, Restriction, Identity, AttestedSource, ActionType, Requirements, FieldCondition, SchemaRequirement, PolicyPin, DescendantConstraint};
pub use evaluate::{evaluate, evaluate_with, extract_namespace_owner, action_covered_by, PolicyResult, AttestedCheck, SignerKeyLookup};
pub use path::{IdPattern, PathPattern, PolicyVars};
pub use delegation::{check_descendant_constraint, grant_covered_by_template};
pub use validate::{validate as validate_policy, PolicyError, MAX_ROLE_DEPTH};
