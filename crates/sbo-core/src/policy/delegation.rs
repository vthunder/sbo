//! Policy delegation constraints (P3/P4).
//!
//! The pure, state-free half of the descendant-policy constraint clause: given a
//! child `policy.v2` document and the parent's [`DescendantConstraint`], decide
//! whether the child is admissible. Version pinning (P2) and its historical-store
//! bookkeeping live in the daemon (they need chain state); this module only
//! covers the declarative ceiling/template check the parent imposes on its DIRECT
//! children.

use super::evaluate::action_covered_by;
use super::types::{DescendantConstraint, Grant, Policy, Restriction};

/// Whether `child` grant is covered by some grant in the parent's template.
///
/// Coverage is intentionally CONSERVATIVE (sound, never over-permissive): a
/// template grant covers a child grant when the recipient (`to`) and path (`on`)
/// are byte-exact equal and every child action is covered by a template action
/// (so `post` in the template covers a child `create`/`update`, and `*` covers
/// all — reusing the evaluator's [`action_covered_by`]). This matches the
/// "byte-exact freezing of reserved/mandated entries" the design calls for: a
/// child cannot broaden the recipient or the path, only narrow the action set.
pub fn grant_covered_by_template(child: &Grant, template: &[Grant]) -> bool {
    let child_to = serde_json::to_value(&child.to).ok();
    let child_on = serde_json::to_value(&child.on).ok();
    template.iter().any(|t| {
        serde_json::to_value(&t.to).ok() == child_to
            && serde_json::to_value(&t.on).ok() == child_on
            && child
                .can
                .iter()
                .all(|c| t.can.iter().any(|g| action_covered_by(*g, *c)))
    })
}

/// Whether `needle` restriction is present (byte-exact) in `haystack`.
fn restriction_present(needle: &Restriction, haystack: &[Restriction]) -> bool {
    let n = serde_json::to_value(needle).ok();
    haystack.iter().any(|r| serde_json::to_value(r).ok() == n)
}

/// Validate a direct child `policy.v2` against its parent's constraint clause
/// (P3): every child grant must be covered by the template's `allowed_grants`,
/// and every mandated restriction must be present verbatim in the child.
/// Returns `Err(reason)` on the first violation.
///
/// Direct-children-only: the caller resolves `constraint` from the child's DIRECT
/// parent policy (the nearest policy strictly above it), so deeper descendants
/// are governed by their own parent's clause, not this one.
pub fn check_descendant_constraint(
    child: &Policy,
    constraint: &DescendantConstraint,
) -> Result<(), String> {
    for grant in &child.grants {
        if !grant_covered_by_template(grant, &constraint.allowed_grants) {
            return Err(format!(
                "child grant {:?} exceeds the parent's descendant-constraint template",
                grant
            ));
        }
    }
    for mandated in &constraint.mandated_restrictions {
        if !restriction_present(mandated, &child.restrictions) {
            return Err(format!(
                "child policy is missing a mandated restriction on {:?}",
                mandated.on
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(v: serde_json::Value) -> Policy {
        serde_json::from_value(v).unwrap()
    }
    fn constraint(v: serde_json::Value) -> DescendantConstraint {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn over_broad_child_grant_rejected() {
        // Template allows create+update on /c/x/spaces/**; child grants `*` — over-broad.
        let c = constraint(serde_json::json!({
            "allowed_grants": [{"to": "*", "can": ["create", "update"], "on": "/c/x/spaces/**"}]
        }));
        let child = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["*"], "on": "/c/x/spaces/**"}]
        }));
        assert!(check_descendant_constraint(&child, &c).is_err());
    }

    #[test]
    fn broader_path_child_grant_rejected() {
        let c = constraint(serde_json::json!({
            "allowed_grants": [{"to": "*", "can": ["create"], "on": "/c/x/spaces/**"}]
        }));
        let child = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/c/x/**"}]
        }));
        assert!(check_descendant_constraint(&child, &c).is_err());
    }

    #[test]
    fn narrower_action_child_grant_accepted() {
        // Template allows `post`; child narrows to `create` — covered.
        let c = constraint(serde_json::json!({
            "allowed_grants": [{"to": "*", "can": ["post"], "on": "/c/x/spaces/**"}]
        }));
        let child = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/c/x/spaces/**"}]
        }));
        assert!(check_descendant_constraint(&child, &c).is_ok());
    }

    #[test]
    fn missing_mandated_restriction_rejected() {
        let c = constraint(serde_json::json!({
            "allowed_grants": [{"to": "*", "can": ["create"], "on": "/c/x/**"}],
            "mandated_restrictions": [{"on": "/c/x/**", "require": {"max_size": 1000}}]
        }));
        let child = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/c/x/**"}]
        }));
        assert!(check_descendant_constraint(&child, &c).is_err());

        // Present verbatim ⇒ accepted.
        let child_ok = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/c/x/**"}],
            "restrictions": [{"on": "/c/x/**", "require": {"max_size": 1000}}]
        }));
        assert!(check_descendant_constraint(&child_ok, &c).is_ok());
    }

    #[test]
    fn empty_template_forbids_all_grants() {
        let c = constraint(serde_json::json!({}));
        let child = policy(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/c/x/**"}]
        }));
        assert!(check_descendant_constraint(&child, &c).is_err());
        // A child with no grants passes a no-op constraint.
        let empty_child = policy(serde_json::json!({}));
        assert!(check_descendant_constraint(&empty_child, &c).is_ok());
    }
}
