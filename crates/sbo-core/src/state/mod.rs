//! State management

#[cfg(feature = "storage")]
mod db;
mod objects;
mod names;

#[cfg(feature = "storage")]
pub use db::{StateDb, StoredProof};
pub use objects::StoredObject;
pub use names::IdentityClaim;
