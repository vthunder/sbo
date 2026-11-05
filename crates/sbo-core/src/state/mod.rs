//! State management

#[cfg(feature = "storage")]
mod db;
mod objects;

#[cfg(feature = "storage")]
pub use db::{StateDb, StoredProof, PolicyEntry};
pub use objects::StoredObject;
