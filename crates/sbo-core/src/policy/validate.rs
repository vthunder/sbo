//! Policy validation on write (security audit 2026-11, D10 / Q17 (a), Q38).
//!
//! A `policy.v2` document is checked when it is parsed — which is how every
//! write of one enters a node — so a document that would send the evaluator
//! into unbounded recursion, that references a role nobody defined, or that
//! carries a pattern outside the grammar's size bound never reaches the chain
//! state. The evaluator keeps its own guards ([`super::evaluate`] bounds role
//! resolution by depth and a visited set) for documents that reach it by any
//! other route; this pass is what makes those guards unreachable in practice.

use std::collections::{HashMap, HashSet};

use super::glob::{char_wildcards, segment_wildcards, MAX_WILDCARDS};
use super::types::{Grant, Identity, Policy, Restriction};
use super::path::{IdPattern, PathPattern};

/// The deepest chain of role references (`role → role → …`, counting `any`
/// nesting) a policy may define, and the depth at which the evaluator stops
/// resolving. I11: "role resolution at evaluation time is bounded".
pub const MAX_ROLE_DEPTH: usize = 32;

/// Why a policy document was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// `{"role": name}` names a role the document does not define.
    UnknownRole(String),
    /// The role graph contains a cycle through this role.
    RoleCycle(String),
    /// A role chain is deeper than [`MAX_ROLE_DEPTH`].
    RoleDepth(String),
    /// A path or id pattern is outside the grammar (where, why).
    BadPattern(String, String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRole(r) => write!(f, "policy references undefined role '{r}'"),
            Self::RoleCycle(r) => write!(f, "policy role '{r}' is part of a reference cycle"),
            Self::RoleDepth(r) => {
                write!(f, "policy role '{r}' nests deeper than {MAX_ROLE_DEPTH} references")
            }
            Self::BadPattern(at, why) => write!(f, "policy pattern at {at}: {why}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Validate a policy document. Called from the `Deserialize` impl, so every
/// parsed `Policy` has passed; also usable on a policy built in code.
pub fn validate(policy: &Policy) -> Result<(), PolicyError> {
    // Every role reference names a defined role.
    for members in policy.roles.values() {
        for m in members {
            check_role_refs(m, &policy.roles)?;
        }
    }
    for g in &policy.grants {
        check_role_refs(&g.to, &policy.roles)?;
    }
    if let Some(dc) = &policy.descendant_constraint {
        for g in &dc.allowed_grants {
            check_role_refs(&g.to, &policy.roles)?;
        }
    }

    // The role graph is acyclic and no chain is deeper than the bound.
    // State per role: None = unvisited, Some(None) = on the current path,
    // Some(Some(d)) = finished, with d the depth of the deepest chain under it.
    let mut state: HashMap<&str, Option<usize>> = HashMap::new();
    let mut roles: Vec<&String> = policy.roles.keys().collect();
    roles.sort(); // deterministic error for a given document
    for r in roles {
        role_depth(r, &policy.roles, &mut state)?;
    }

    // Every pattern is within the grammar's size bound.
    for (i, d) in policy.deny.iter().enumerate() {
        check_path_pattern(d, &format!("deny[{i}]"))?;
    }
    for (i, g) in policy.grants.iter().enumerate() {
        check_grant(g, &format!("grants[{i}]"))?;
    }
    for (i, r) in policy.restrictions.iter().enumerate() {
        check_restriction(r, &format!("restrictions[{i}]"))?;
    }
    if let Some(dc) = &policy.descendant_constraint {
        for (i, g) in dc.allowed_grants.iter().enumerate() {
            check_grant(g, &format!("descendant_constraint.allowed_grants[{i}]"))?;
        }
        for (i, r) in dc.mandated_restrictions.iter().enumerate() {
            check_restriction(r, &format!("descendant_constraint.mandated_restrictions[{i}]"))?;
        }
    }
    Ok(())
}

fn check_role_refs(id: &Identity, roles: &HashMap<String, Vec<Identity>>) -> Result<(), PolicyError> {
    match id {
        Identity::Role { role } if !roles.contains_key(role) => {
            Err(PolicyError::UnknownRole(role.clone()))
        }
        Identity::Any { any } => any.iter().try_for_each(|m| check_role_refs(m, roles)),
        _ => Ok(()),
    }
}

/// Depth of the deepest reference chain rooted at `role` (1 for a role whose
/// members reference no role). Iterative DFS with an explicit stack so the
/// validator itself never recurses on a hostile document.
fn role_depth<'a>(
    role: &'a str,
    roles: &'a HashMap<String, Vec<Identity>>,
    state: &mut HashMap<&'a str, Option<usize>>,
) -> Result<usize, PolicyError> {
    if let Some(Some(d)) = state.get(role) {
        return Ok(*d);
    }
    // (role, its child roles, next child index, deepest child so far)
    let mut stack: Vec<(&'a str, Vec<&'a str>, usize, usize)> = Vec::new();
    let mut on_path: HashSet<&'a str> = HashSet::new();
    let push = |r: &'a str, stack: &mut Vec<_>, on_path: &mut HashSet<&'a str>| {
        let kids = child_roles(&roles[r]);
        on_path.insert(r);
        stack.push((r, kids, 0, 0));
    };
    push(role, &mut stack, &mut on_path);
    loop {
        let (r, kids, next, deepest) = stack.last_mut().expect("non-empty");
        if *next < kids.len() {
            let child = kids[*next];
            *next += 1;
            if on_path.contains(child) {
                return Err(PolicyError::RoleCycle(child.to_string()));
            }
            match state.get(child) {
                Some(Some(d)) => *deepest = (*deepest).max(*d),
                _ => push(child, &mut stack, &mut on_path),
            }
            continue;
        }
        let depth = *deepest + 1;
        if depth > MAX_ROLE_DEPTH {
            return Err(PolicyError::RoleDepth(r.to_string()));
        }
        let r = *r;
        on_path.remove(r);
        state.insert(r, Some(depth));
        stack.pop();
        match stack.last_mut() {
            Some((_, _, _, parent_deepest)) => *parent_deepest = (*parent_deepest).max(depth),
            None => return Ok(depth),
        }
    }
}

/// The roles referenced by a member list, through any `any` nesting (an `any`
/// level counts toward depth like a role level).
fn child_roles(members: &[Identity]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut todo: Vec<&Identity> = members.iter().collect();
    while let Some(m) = todo.pop() {
        match m {
            Identity::Role { role } => out.push(role.as_str()),
            Identity::Any { any } => todo.extend(any.iter()),
            _ => {}
        }
    }
    out
}

fn check_grant(g: &Grant, at: &str) -> Result<(), PolicyError> {
    check_path_pattern(&g.on, &format!("{at}.on"))?;
    if let Some(id) = &g.id {
        check_id_pattern(id, &format!("{at}.id"))?;
    }
    Ok(())
}

fn check_restriction(r: &Restriction, at: &str) -> Result<(), PolicyError> {
    check_path_pattern(&r.on, &format!("{at}.on"))?;
    if let Some(id) = &r.id {
        check_id_pattern(id, &format!("{at}.id"))?;
    }
    if let Some(sb) = &r.require.require_payload_signed_by {
        check_path_pattern_str(&sb.path, &format!("{at}.require.require_payload_signed_by.path"))?;
    }
    Ok(())
}

fn check_path_pattern(p: &PathPattern, at: &str) -> Result<(), PolicyError> {
    check_path_pattern_str(p.as_str(), at)
}

/// A path pattern is absolute and carries at most [`MAX_WILDCARDS`] wildcard
/// segments.
pub fn check_path_pattern_str(p: &str, at: &str) -> Result<(), PolicyError> {
    if !p.starts_with('/') {
        return Err(PolicyError::BadPattern(at.into(), format!("'{p}' is not an absolute path")));
    }
    let n = segment_wildcards(p);
    if n > MAX_WILDCARDS {
        return Err(PolicyError::BadPattern(
            at.into(),
            format!("{n} wildcard segments, more than the {MAX_WILDCARDS} allowed"),
        ));
    }
    Ok(())
}

fn check_id_pattern(p: &IdPattern, at: &str) -> Result<(), PolicyError> {
    let n = char_wildcards(p.as_str());
    if n > MAX_WILDCARDS {
        return Err(PolicyError::BadPattern(
            at.into(),
            format!("{n} wildcards, more than the {MAX_WILDCARDS} allowed"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: serde_json::Value) -> Result<Policy, String> {
        serde_json::from_value::<Policy>(v).map_err(|e| e.to_string())
    }

    #[test]
    fn cycles_and_self_reference_reject() {
        let e = parse(serde_json::json!({
            "roles": {"a": [{"role": "b"}], "b": [{"any": [{"role": "a"}]}]}
        })).unwrap_err();
        assert!(e.contains("cycle"), "{e}");
        let e = parse(serde_json::json!({"roles": {"r": [{"role": "r"}]}})).unwrap_err();
        assert!(e.contains("cycle"), "{e}");
    }

    #[test]
    fn unknown_role_rejects() {
        let e = parse(serde_json::json!({
            "grants": [{"to": {"role": "ghost"}, "can": ["post"], "on": "/**"}]
        })).unwrap_err();
        assert!(e.contains("undefined role 'ghost'"), "{e}");
        let e = parse(serde_json::json!({
            "roles": {"a": [{"any": ["x", {"role": "ghost"}]}]}
        })).unwrap_err();
        assert!(e.contains("undefined role"), "{e}");
    }

    #[test]
    fn depth_is_bounded() {
        let chain = |n: usize| {
            let mut roles = serde_json::Map::new();
            for i in 0..n {
                roles.insert(format!("r{i}"), serde_json::json!([{"role": format!("r{}", i + 1)}]));
            }
            roles.insert(format!("r{n}"), serde_json::json!(["someone"]));
            serde_json::json!({"roles": roles})
        };
        assert!(parse(chain(MAX_ROLE_DEPTH - 1)).is_ok());
        let e = parse(chain(MAX_ROLE_DEPTH)).unwrap_err();
        assert!(e.contains("deeper than"), "{e}");
        // A diamond is not a cycle.
        assert!(parse(serde_json::json!({
            "roles": {"top": [{"role": "l"}, {"role": "r"}], "l": [{"role": "leaf"}], "r": [{"role": "leaf"}], "leaf": ["x"]}
        })).is_ok());
    }

    #[test]
    fn pattern_bounds() {
        let wide = format!("/{}/", vec!["**"; MAX_WILDCARDS + 1].join("/"));
        let e = parse(serde_json::json!({"deny": [wide]})).unwrap_err();
        assert!(e.contains("wildcard"), "{e}");
        let ok = format!("/{}/", vec!["*"; MAX_WILDCARDS].join("/"));
        assert!(parse(serde_json::json!({"deny": [ok]})).is_ok());
        let e = parse(serde_json::json!({"grants": [{"to": "*", "can": ["post"], "on": "/x/", "id": "*".repeat(MAX_WILDCARDS + 1)}]})).unwrap_err();
        assert!(e.contains("wildcard"), "{e}");
        let e = parse(serde_json::json!({"grants": [{"to": "*", "can": ["post"], "on": "x/"}]})).unwrap_err();
        assert!(e.contains("absolute"), "{e}");
        let e = parse(serde_json::json!({"restrictions": [{"on": "/**", "require": {"require_payload_signed_by": {"path": "sys/domains/*"}}}]})).unwrap_err();
        assert!(e.contains("absolute"), "{e}");
    }
}
