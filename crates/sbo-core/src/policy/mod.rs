//! Policy evaluation

mod types;
mod evaluate;
mod path;
mod delegation;

pub use types::{Policy, Grant, Restriction, Identity, AttestedSource, ActionType, Requirements, FieldCondition, SchemaRequirement, PolicyPin, DescendantConstraint};
pub use evaluate::{evaluate, extract_namespace_owner, action_covered_by, PolicyResult};
pub use path::{IdPattern, PathPattern, PolicyVars};
pub use delegation::{check_descendant_constraint, grant_covered_by_template};
