//! Path pattern matching

use serde::{Deserialize, Serialize};
use crate::message::Path;
use super::glob;

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

    /// The pattern text as written (variables unsubstituted).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Match a resolved pattern against a path string (memoised segment glob,
    /// see [`super::glob`]).
    fn match_pattern(pattern: &str, path: &str) -> bool {
        glob::segments_match(&glob::segments(pattern), &glob::segments(path))
    }
}

/// Pattern for matching an object's **id** (the leaf name within a container),
/// as opposed to its container path. Ids are single tokens, so the grammar is
/// deliberately small: a literal, `*` for "any id", or a glob with `*` standing
/// for any run of characters (`ev_*`). Policy variables are substituted exactly
/// as in [`PathPattern`], and an undefined variable fails closed for the same
/// reason.
///
/// Why a separate field rather than a longer path pattern: `/agreements/*/proposal`
/// is ambiguous between the container `/agreements/x/proposal/` and the object
/// with id `proposal` at `/agreements/x/`. Keeping the id out of the path
/// pattern removes the ambiguity, and lets an existing policy keep its exact
/// meaning — an absent `id` matches ANY id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdPattern(String);

impl IdPattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Match against an object id, with policy variables resolved.
    pub fn matches(&self, id: &str, vars: &PolicyVars) -> bool {
        let mut pattern = self.0.clone();
        if let Some(v) = vars.owner { pattern = pattern.replace("$owner", v); }
        if let Some(v) = vars.user { pattern = pattern.replace("$user", v); }
        if let Some(v) = vars.email { pattern = pattern.replace("$email", v); }
        if let Some(v) = vars.name { pattern = pattern.replace("$name", v); }
        glob::chars_match(&pattern, id)
    }

    /// The pattern text as written (variables unsubstituted).
    pub fn as_str(&self) -> &str {
        &self.0
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

    #[test]
    fn id_pattern_literal_and_wildcard() {
        let vars = PolicyVars::default();
        assert!(IdPattern::new("proposal").matches("proposal", &vars));
        assert!(!IdPattern::new("proposal").matches("acceptance", &vars));
        assert!(IdPattern::new("*").matches("anything", &vars));
        assert!(IdPattern::new("ev_*").matches("ev_abc", &vars));
        assert!(!IdPattern::new("ev_*").matches("lock", &vars));
        // `*` may stand for nothing at all.
        assert!(IdPattern::new("ev_*").matches("ev_", &vars));
    }

    #[test]
    fn id_pattern_substitutes_variables_and_fails_closed() {
        let user = "alice@x.test";
        let vars = PolicyVars { user: Some(user), ..Default::default() };
        assert!(IdPattern::new("$user").matches(user, &vars));
        assert!(!IdPattern::new("$user").matches("bob@x.test", &vars));
        // Undefined variable keeps the literal token, which matches no real id.
        assert!(!IdPattern::new("$user").matches(user, &PolicyVars::default()));
    }
}
