//! Path pattern matching

use serde::{Deserialize, Serialize};
use crate::message::Path;

/// The dynamic identity values a policy pattern may interpolate. All are
/// **literal references** (the strings as written in headers / claimed by the
/// signer) — never resolved controllers, keeping the path layer separate from
/// authorization. A `None` field means the variable is **undefined** for this
/// message: any pattern referencing it is left with the literal `$var` token,
/// which matches no real path segment, so the pattern **fails closed**.
///
/// - `$owner` — the object's owner reference (declared `Owner` on create, stored
///   `owner_ref` on update). Not path-derived.
/// - `$user`  — the acting signer's canonical identity.
/// - `$email` — the signer's email form, if any.
/// - `$name`  — the signer's local name form, if any.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyVars<'a> {
    pub owner: Option<&'a str>,
    pub user: Option<&'a str>,
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
}

/// Path pattern for matching (e.g., "/users/**", "/$owner/*")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PathPattern(String);

impl PathPattern {
    /// Create a new path pattern
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Check if this pattern matches a path, with policy variables resolved.
    pub fn matches(&self, path: &Path, vars: &PolicyVars) -> bool {
        let pattern = self.resolve_variables(vars);
        Self::match_pattern(&pattern, &path.to_string())
    }

    /// Substitute `$owner`/`$user`/`$email`/`$name`. An undefined (`None`)
    /// variable is left as its literal token so the pattern fails closed.
    fn resolve_variables(&self, vars: &PolicyVars) -> String {
        let mut result = self.0.clone();
        if let Some(v) = vars.owner { result = result.replace("$owner", v); }
        if let Some(v) = vars.user { result = result.replace("$user", v); }
        if let Some(v) = vars.email { result = result.replace("$email", v); }
        if let Some(v) = vars.name { result = result.replace("$name", v); }
        result
    }

    /// Match a resolved pattern against a path string
    fn match_pattern(pattern: &str, path: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        Self::match_parts(&pattern_parts, &path_parts)
    }

    fn match_parts(pattern: &[&str], path: &[&str]) -> bool {
        match (pattern.first(), path.first()) {
            // Both empty = match
            (None, None) => true,

            // Pattern empty but path not = no match
            (None, Some(_)) => false,

            // ** matches zero or more segments
            (Some(&"**"), _) => {
                // Try matching ** with 0, 1, 2, ... segments
                for i in 0..=path.len() {
                    if Self::match_parts(&pattern[1..], &path[i..]) {
                        return true;
                    }
                }
                false
            }

            // Path empty but pattern not (unless **)
            (Some(_), None) => false,

            // * matches exactly one segment
            (Some(&"*"), Some(_)) => Self::match_parts(&pattern[1..], &path[1..]),

            // Exact match required
            (Some(p), Some(s)) => {
                if *p == *s {
                    Self::match_parts(&pattern[1..], &path[1..])
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = PathPattern::new("/users/alice");
        assert!(pattern.matches(&Path::parse("/users/alice/").unwrap(), &PolicyVars::default()));
    }

    #[test]
    fn test_wildcard() {
        let pattern = PathPattern::new("/users/*");
        assert!(pattern.matches(&Path::parse("/users/alice/").unwrap(), &PolicyVars::default()));
        assert!(pattern.matches(&Path::parse("/users/bob/").unwrap(), &PolicyVars::default()));
    }

    #[test]
    fn test_double_wildcard() {
        let pattern = PathPattern::new("/users/**");
        assert!(pattern.matches(&Path::parse("/users/alice/").unwrap(), &PolicyVars::default()));
        assert!(pattern.matches(&Path::parse("/users/alice/nfts/").unwrap(), &PolicyVars::default()));
    }
}
