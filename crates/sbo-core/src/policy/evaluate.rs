//! Policy evaluation

use crate::message::{Message, Id};
use super::types::{Policy, ActionType, AttestedSource, Identity};
use super::path::PolicyVars;

/// Resolves an [`AttestedSource`] against on-chain attestations for the acting
/// user: returns `true` when an in-force `attestation.v1` of `type` (by `by`,
/// when given) exists whose subject resolves to the requester's controller.
/// Supplied by the caller (the daemon, with state + inclusion time); pure
/// tests pass a stub.
pub type AttestedCheck<'a> = dyn Fn(&AttestedSource) -> bool + 'a;

/// Result of policy evaluation
#[derive(Debug)]
pub enum PolicyResult {
    Allowed,
    Denied(String),
}

/// Evaluate a policy for an action.
///
/// `vars` carries the literal-reference policy variables (`$owner`/`$user`/
/// `$email`/`$name`) the caller resolved from the message + identity graph.
/// Undefined variables fail closed (see [`PolicyVars`]). `signer_is_owner` is the
/// caller's L2 determination that the signer controls `vars.owner` (what a
/// `to: owner` grant requires).
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    policy: &Policy,
    actor: &Id,
    action: ActionType,
    target_path: &str,
    vars: &PolicyVars,
    signer_is_owner: bool,
    is_attested: &AttestedCheck,
    message: &Message,
    primary_domain: Option<&str>,
) -> PolicyResult {
    tracing::debug!(
        "Policy eval: actor={}, action={:?}, path={}, vars={:?}",
        actor, action, target_path, vars
    );

    // 1. Check deny list first
    for pattern in &policy.deny {
        if pattern.matches(&crate::message::Path::parse(target_path).unwrap(), vars) {
            return PolicyResult::Denied(format!("Path denied by pattern: {:?}", pattern));
        }
    }

    // Get actor's signing key for key-based identity matching
    let actor_key = message.signing_key.to_string();

    // 2. Find matching grant
    let mut grant_debug = Vec::new();
    let granted = policy.grants.iter().any(|grant| {
        let path_parsed = crate::message::Path::parse(target_path).unwrap();
        let path_matches = grant.on.matches(&path_parsed, vars);
        let action_matches = grant.can.iter().any(|granted| action_covered_by(*granted, action));
        let identity_match = identity_matches(&grant.to, actor, &actor_key, vars.owner, signer_is_owner, is_attested, &policy.roles, primary_domain);

        grant_debug.push(format!(
            "  grant to={:?} can={:?} on={:?} -> path:{} action:{} identity:{}",
            grant.to, grant.can, grant.on,
            path_matches, action_matches, identity_match
        ));

        path_matches && action_matches && identity_match
    });

    if !granted {
        tracing::debug!("Grant evaluation:\n{}", grant_debug.join("\n"));
        return PolicyResult::Denied("No matching grant".to_string());
    }

    // 3. Check restrictions
    for restriction in &policy.restrictions {
        if restriction.on.matches(&crate::message::Path::parse(target_path).unwrap(), vars) {
            if let Some(reason) = check_requirements(&restriction.require, message, is_attested) {
                return PolicyResult::Denied(reason);
            }
        }
    }

    PolicyResult::Allowed
}

/// Whether a granted action covers a requested action. `post` is shorthand for
/// `create` + `update` (Policy Spec §Actions), so a `post` grant authorizes both
/// `create` and `update` requests; `*` covers everything. The daemon only ever
/// requests `Create`/`Update`/`Delete`/`Transfer` (it maps a `post` envelope to
/// `create` or `update` by object existence), so the `post`⇒{create,update}
/// expansion is what makes community `can: ["post"]` grants work.
fn action_covered_by(granted: ActionType, requested: ActionType) -> bool {
    // `govern` is meta-authority: only an explicit `govern` grant covers it.
    // Crucially `*` does NOT — otherwise `to: admin can:[*]` (and any broad
    // wildcard grant) would silently confer the power to install policies, which
    // is exactly the capture vector we are closing. Governance must always be
    // granted by name.
    if requested == ActionType::Govern {
        return granted == ActionType::Govern;
    }
    granted == ActionType::All
        || granted == requested
        || (granted == ActionType::Post
            && matches!(requested, ActionType::Create | ActionType::Update))
}

/// Extract namespace owner from path (first component)
/// e.g., "/alice/nfts/" -> Some("alice"), "/sys/names/" -> Some("sys")
pub fn extract_namespace_owner(path: &str) -> Option<String> {
    path.trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Check if message satisfies requirements, returns Some(reason) if not satisfied
fn check_requirements(
    require: &super::types::Requirements,
    message: &Message,
    is_attested: &AttestedCheck,
) -> Option<String> {
    // Attestation conditions: the acting user must (not) be the in-force
    // subject of the named attestation.
    if let Some(source) = &require.attested {
        if !is_attested(source) {
            return Some(format!(
                "Acting user is not the in-force subject of attestation '{}'{}",
                source.type_,
                source.by.as_deref().map(|b| format!(" by {b}")).unwrap_or_default()
            ));
        }
    }
    if let Some(source) = &require.not_attested {
        if is_attested(source) {
            return Some(format!(
                "Acting user is the in-force subject of disallowed attestation '{}'{}",
                source.type_,
                source.by.as_deref().map(|b| format!(" by {b}")).unwrap_or_default()
            ));
        }
    }

    // Check max_size
    if let Some(max_size) = require.max_size {
        if let Some(ref payload) = message.payload {
            if payload.len() > max_size {
                return Some(format!(
                    "Payload size {} exceeds max_size {}",
                    payload.len(),
                    max_size
                ));
            }
        }
    }

    // Check content_type
    if let Some(ref required_type) = require.content_type {
        match &message.content_type {
            Some(actual_type) if actual_type == required_type => {}
            Some(actual_type) => {
                return Some(format!(
                    "Content type '{}' does not match required '{}'",
                    actual_type, required_type
                ));
            }
            None => {
                return Some(format!("Missing content type, required '{}'", required_type));
            }
        }
    }

    // Check schema
    if let Some(ref required_schema) = require.schema {
        let actual_schema = message.content_schema.as_deref();

        let matches = match required_schema {
            super::types::SchemaRequirement::Single(s) => {
                actual_schema == Some(s.as_str())
            }
            super::types::SchemaRequirement::Any { any } => {
                actual_schema.map_or(false, |a| any.iter().any(|s| s == a))
            }
        };

        if !matches {
            return Some(format!(
                "Schema {:?} does not match required {:?}",
                actual_schema, required_schema
            ));
        }
    }

    // Check require_payload_signed_by
    // This verifies the JWT issuer maps to an object at the required path pattern.
    // Note: Cryptographic signature verification happens in the daemon's validation layer.
    if let Some(ref signed_by) = require.require_payload_signed_by {
        if let Some(reason) = check_payload_signed_by(signed_by, message) {
            return Some(reason);
        }
    }

    // Check dnssec_proof: the payload must be a valid RFC 9102 DNSSEC proof for
    // the domain this object is named after. For a `/sys/dnssec/<domain>` write
    // the object id IS `<domain>` (the write path is the container `/sys/dnssec/`
    // plus the id leaf). This is what makes the object self-authorizing — the
    // payload proves its own authority, so an unprivileged grant is safe.
    // Domain-binding is intrinsic: the proof must carry `_browserid.<domain>` for
    // this exact id, so a valid proof for a *different* domain is rejected.
    if require.dnssec_proof {
        if let Some(reason) = check_dnssec_proof(message) {
            return Some(reason);
        }
    }

    None
}

/// Verify the payload is a valid RFC 9102 DNSSEC proof bound to the object's id
/// (the `<domain>` of a `/sys/dnssec/<domain>` object).
fn check_dnssec_proof(message: &Message) -> Option<String> {
    let domain = message.id.as_str();
    if domain.is_empty() {
        return Some("dnssec_proof: object id (domain) is empty".to_string());
    }

    let payload = match message.payload.as_ref() {
        Some(p) => p,
        None => return Some("dnssec_proof: missing payload (expected RFC 9102 proof)".to_string()),
    };

    match crate::attribution::verify_dnssec_proof_for_domain(payload, domain) {
        Ok(_window) => None,
        Err(e) => Some(format!("dnssec_proof: invalid proof for '{}': {}", domain, e)),
    }
}

/// Check if the payload's JWT issuer maps to an object at the required path pattern
fn check_payload_signed_by(
    signed_by: &super::types::RequirePayloadSignedBy,
    message: &Message,
) -> Option<String> {
    // Get payload
    let payload = message.payload.as_ref()?;

    // Try to parse as JWT (UTF-8 string)
    let token = match std::str::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => return Some("Payload is not valid UTF-8 (expected JWT)".to_string()),
    };

    // Decode JWT claims to get issuer
    let claims = match crate::jwt::decode_identity_claims(token) {
        Ok(c) => c,
        Err(e) => return Some(format!("Failed to decode JWT: {}", e)),
    };

    // Map issuer to object path
    let issuer_path = match issuer_to_path(&claims.iss) {
        Some(p) => p,
        None => {
            return Some(format!(
                "Issuer '{}' does not reference an external signing object",
                claims.iss
            ));
        }
    };

    // Check if issuer path matches the required pattern
    let pattern = super::path::PathPattern::new(&signed_by.path);
    let issuer_path_parsed = match crate::message::Path::parse(&issuer_path) {
        Ok(p) => p,
        Err(_) => return Some(format!("Invalid issuer path: {}", issuer_path)),
    };

    if !pattern.matches(&issuer_path_parsed, &PolicyVars::default()) {
        return Some(format!(
            "Issuer path '{}' does not match required pattern '{}'",
            issuer_path, signed_by.path
        ));
    }

    None
}

/// Map a JWT issuer to an object path
///
/// - "domain:example.com" -> "/sys/domains/example.com"
/// - "self" -> None (no external object)
fn issuer_to_path(issuer: &str) -> Option<String> {
    if let Some(domain) = issuer.strip_prefix("domain:") {
        Some(format!("/sys/domains/{}", domain))
    } else if issuer == "self" {
        None // Self-signed, no external signing object
    } else {
        // Unknown issuer format - could extend in future
        None
    }
}

#[allow(clippy::too_many_arguments)]
/// Canonicalize a grant's identity *name reference* to the form the actor is
/// canonicalized to, so resolution-based matching (Policy Spec §Identity
/// references) can be a single string compare.
///
/// `resolve_creator` canonicalizes a signer with a `/sys/names/<local>` claim on
/// a primary-domain repo to the email `<local>@<primary_domain>`. So a bare
/// grant name `"sys"` must canonicalize the *same way* to match that actor:
/// - With a primary domain and a bare name (no `@`) → `<name>@<primary_domain>`.
///   This makes `to: "sys"` ≡ `to: "sys@mingo.place"` for the party who claims
///   `/sys/names/sys` (Policy Spec: a name and the email that controls it
///   resolve to the same controller).
/// - An already email-qualified reference (`"sys@mingo.place"`, or a user's
///   `"dan@gmail.com"`) is left verbatim — we never re-domain it. This keeps a
///   foreign `@domain` distinct: `to: "sys"` (→ `sys@mingo.place`) does NOT
///   match a `dan@gmail.com` signer, and bare `to: "dan"` does NOT match a
///   browserid-attributed `dan@gmail.com`.
/// - With no primary domain (chain-only / multi-domain repos) a bare name stays
///   bare — we don't invent a domain — so literal name matching is preserved.
fn canonical_name_ref(name: &str, primary_domain: Option<&str>) -> String {
    match primary_domain {
        Some(domain) if !name.contains('@') => format!("{}@{}", name, domain),
        _ => name.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn identity_matches(
    identity: &Identity,
    actor: &Id,
    actor_key: &str,
    owner: Option<&str>,
    signer_is_owner: bool,
    is_attested: &AttestedCheck,
    roles: &std::collections::HashMap<String, Vec<Identity>>,
    primary_domain: Option<&str>,
) -> bool {
    match identity {
        Identity::Name(name) => {
            match name.as_str() {
                "*" => true,
                // The `owner` identity is satisfied when the signer speaks for
                // the object's resolved controller (key match for key-rooted
                // owners, browserid attribution for email-rooted owners),
                // computed by the caller via L2 — not a creator-name string
                // compare, which would never match an email-rooted owner.
                "owner" => signer_is_owner,
                // Resolution-based matching: canonicalize the grant name to the
                // primary-domain email form (the same form `resolve_creator`
                // canonicalizes the actor to) before comparing, so a bare name,
                // its controlling email, and the actor all identify one party.
                _ => canonical_name_ref(name, primary_domain) == actor.as_str(),
            }
        }
        Identity::Key { key } => {
            // Compare public keys, stripping algorithm prefix if present
            let key_clean = key.strip_prefix("ed25519:").unwrap_or(key);
            let actor_clean = actor_key.strip_prefix("ed25519:").unwrap_or(actor_key);
            key_clean == actor_clean
        }
        Identity::Role { role } => {
            if let Some(members) = roles.get(role) {
                members.iter().any(|m| identity_matches(m, actor, actor_key, owner, signer_is_owner, is_attested, roles, primary_domain))
            } else {
                false
            }
        }
        Identity::Attested { attested } => is_attested(attested),
        Identity::Any { any } => {
            any.iter().any(|id| identity_matches(id, actor, actor_key, owner, signer_is_owner, is_attested, roles, primary_domain))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ContentHash, Signature, SigningKey};
    use crate::message::{Action, ObjectType, Path};

    fn signed_msg() -> Message {
        let key = SigningKey::generate();
        let payload = b"{}".to_vec();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/alice/posts/").unwrap(),
            id: Id::new("p1").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature::parse(&"0".repeat(128)).unwrap(),
            content_type: Some("application/json".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: None,
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(&key);
        msg
    }

    fn owner_grant_policy() -> Policy {
        serde_json::from_value(serde_json::json!({
            "grants": [{"to": "owner", "can": ["*"], "on": "/$owner/**"}]
        }))
        .unwrap()
    }

    #[test]
    fn owner_grant_honors_signer_is_owner_not_actor_string() {
        let policy = owner_grant_policy();
        let msg = signed_msg();
        // The actor (a key-hex creator id) never string-equals the owner
        // "alice"; authorization must come from signer_is_owner.
        let actor = Id::new("e_deadbeef").unwrap();
        let no_attest = |_: &AttestedSource| false;

        // signer_is_owner = true → the `owner` grant applies → allowed.
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", &PolicyVars { owner: Some("alice"), ..Default::default() }, true, &no_attest, &msg, None),
            PolicyResult::Allowed
        ));
        // signer_is_owner = false → no matching grant → denied.
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", &PolicyVars { owner: Some("alice"), ..Default::default() }, false, &no_attest, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn owner_grant_works_for_email_owner_via_signer_is_owner() {
        // An email-rooted owner: `$owner` substitutes the email into the path
        // pattern, and signer_is_owner carries the attribution result. The old
        // `owner == actor` compare could never match an email owner.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "owner", "can": ["*"], "on": "/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_ephemeral").unwrap();
        let no_attest = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", &PolicyVars { owner: Some("alice@example.com"), ..Default::default() }, true, &no_attest, &msg, None),
            PolicyResult::Allowed
        ));
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/alice/posts/", &PolicyVars { owner: Some("alice@example.com"), ..Default::default() }, false, &no_attest, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn post_grant_covers_create_and_update_not_delete() {
        // `post` is shorthand for create + update; a `post` grant must authorize
        // both (the daemon maps a `post` envelope to Create/Update by existence),
        // but must NOT authorize delete.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["post"], "on": "/public/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no_attest = |_: &AttestedSource| false;

        for action in [ActionType::Create, ActionType::Update, ActionType::Post] {
            assert!(
                matches!(
                    evaluate(&policy, &actor, action, "/public/p1/", &PolicyVars::default(), false, &no_attest, &msg, None),
                    PolicyResult::Allowed
                ),
                "post grant should cover {action:?}"
            );
        }
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Delete, "/public/p1/", &PolicyVars::default(), false, &no_attest, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn wildcard_and_post_do_not_confer_govern() {
        // Governance is meta-authority: neither `*` nor `post` nor `create`
        // covers a `govern` request — only an explicit `govern` grant does.
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no = |_: &AttestedSource| false;

        for cans in [vec!["*"], vec!["post"], vec!["create", "update", "delete", "transfer"]] {
            let policy: Policy = serde_json::from_value(serde_json::json!({
                "grants": [{"to": "*", "can": cans, "on": "/**"}]
            })).unwrap();
            assert!(
                matches!(
                    evaluate(&policy, &actor, ActionType::Govern, "/communities/x/", &PolicyVars::default(), false, &no, &msg, None),
                    PolicyResult::Denied(_)
                ),
                "grant {cans:?} must NOT confer govern"
            );
        }

        // An explicit govern grant authorizes it.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["govern"], "on": "/communities/**"}]
        })).unwrap();
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Govern, "/communities/x/", &PolicyVars::default(), false, &no, &msg, None),
            PolicyResult::Allowed
        ));
        // ...and a govern grant does not leak into ordinary content actions.
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/communities/x/", &PolicyVars::default(), false, &no, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn create_grant_does_not_imply_update() {
        // The create/update split must stay asymmetric: a bare `create` grant
        // (first-come-first-served) must not confer update rights.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/sys/names/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no_attest = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/sys/names/alice/", &PolicyVars::default(), false, &no_attest, &msg, None),
            PolicyResult::Allowed
        ));
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Update, "/sys/names/alice/", &PolicyVars::default(), false, &no_attest, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn attested_role_and_conditions_use_the_closure() {
        // A grant to an attestation-defined role.
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "roles": { "mod": [{"attested": {"type": "role:moderator", "by": "c@x.org"}}] },
            "grants": [{"to": {"role": "mod"}, "can": ["post"], "on": "/**"}],
            "restrictions": [{"on": "/**", "require": {"not_attested": {"type": "ban"}}}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();

        // Attested as a moderator and not banned → allowed.
        let mod_not_banned = |s: &AttestedSource| s.type_ == "role:moderator";
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Post, "/space/", &PolicyVars::default(), false, &mod_not_banned, &msg, None),
            PolicyResult::Allowed
        ));

        // Not attested as a moderator → no grant matches → denied.
        let none = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Post, "/space/", &PolicyVars::default(), false, &none, &msg, None),
            PolicyResult::Denied(_)
        ));

        // Moderator but banned → grant matches but the not_attested restriction blocks.
        let mod_and_banned = |_: &AttestedSource| true;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Post, "/space/", &PolicyVars::default(), false, &mod_and_banned, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    // --- Phase 1: four-variable literal-reference model ---------------------

    #[test]
    fn u_container_owner_grant_uses_declared_owner_not_path() {
        // The /u/<id>/ layout: `/u/$owner/**` must match when $owner is the
        // declared owner (de-circularized — segment 0 is the container "u").
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "owner", "can": ["*"], "on": "/u/$owner/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no = |_: &AttestedSource| false;

        // declared owner + signer controls it → allowed under /u/<owner>/.
        let vars = PolicyVars { owner: Some("alice@mingo.place"), ..Default::default() };
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/posts/", &vars, true, &no, &msg, None),
            PolicyResult::Allowed
        ));
        // no declared owner → $owner undefined → fails closed (NOT derived as "u").
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/posts/", &PolicyVars::default(), true, &no, &msg, None),
            PolicyResult::Denied(_)
        ));
        // owner declared but path is someone else's namespace → no path match.
        let vars_bob = PolicyVars { owner: Some("bob@mingo.place"), ..Default::default() };
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/posts/", &vars_bob, true, &no, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    #[test]
    fn email_variable_fails_closed_when_absent() {
        // `/u/$email/**` restricts the namespace to email-rooted identities; a
        // key-only signer (no email) must be denied (the literal `$email` token
        // matches no real segment).
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/u/$email/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no = |_: &AttestedSource| false;

        let with_email = PolicyVars { email: Some("alice@mingo.place"), ..Default::default() };
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/x/", &with_email, false, &no, &msg, None),
            PolicyResult::Allowed
        ));
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/x/", &PolicyVars::default(), false, &no, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    fn dnssec_msg(domain: &str, payload: Vec<u8>) -> Message {
        let key = SigningKey::generate();
        let mut msg = Message {
            action: Action::Post,
            path: Path::parse("/sys/dnssec/").unwrap(),
            id: Id::new(domain).unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature::parse(&"0".repeat(128)).unwrap(),
            content_type: Some("application/octet-stream".to_string()),
            content_hash: Some(ContentHash::sha256(&payload)),
            payload: Some(payload),
            owner: None,
            creator: None,
            content_encoding: None,
            content_schema: Some("dnssec.v1".to_string()),
            policy_ref: None,
            related: None,
            hlc: None,
            prev: None,
            auth_cert: None,
            auth_evidence: None,
            auth_warrant: None,
        };
        msg.sign(&key);
        msg
    }

    fn self_authorizing_dnssec_policy() -> Policy {
        // The default /sys/dnssec/* policy: anyone may write, but the payload
        // must be a valid DNSSEC proof for the object's domain id.
        serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["create", "update"], "on": "/sys/dnssec/**"}],
            "restrictions": [{
                "on": "/sys/dnssec/**",
                "require": {
                    "schema": "dnssec.v1",
                    "content_type": "application/octet-stream",
                    "dnssec_proof": true
                }
            }]
        }))
        .unwrap()
    }

    #[test]
    fn dnssec_proof_grant_matches_container_path() {
        // The write target is the container `/sys/dnssec/` (id is the leaf), so
        // the `/sys/dnssec/**` grant+restriction must fire on it. With an invalid
        // proof payload the restriction denies — proving both that the grant let
        // an unprivileged signer through AND that the dnssec_proof guard ran.
        let policy = self_authorizing_dnssec_policy();
        let msg = dnssec_msg("mingo.place", b"not-a-valid-rfc9102-proof".to_vec());
        let actor = Id::new("e_anon").unwrap();
        let no = |_: &AttestedSource| false;
        match evaluate(&policy, &actor, ActionType::Create, "/sys/dnssec/", &PolicyVars::default(), false, &no, &msg, None) {
            PolicyResult::Denied(r) => assert!(r.contains("dnssec_proof"), "expected dnssec_proof denial, got: {r}"),
            PolicyResult::Allowed => panic!("invalid proof must be denied"),
        }
    }

    #[test]
    fn dnssec_proof_requires_payload() {
        // A dnssec_proof restriction with no payload is denied (can't prove authority).
        let require: super::super::types::Requirements = serde_json::from_value(serde_json::json!({
            "dnssec_proof": true
        }))
        .unwrap();
        let mut msg = dnssec_msg("mingo.place", vec![]);
        msg.payload = None;
        let no = |_: &AttestedSource| false;
        assert!(check_requirements(&require, &msg, &no).is_some());
    }

    #[test]
    fn dnssec_proof_absent_by_default_is_noop() {
        // Requirements without dnssec_proof set must not invoke the proof check
        // (the field defaults to false and round-trips out of serialization).
        let require: super::super::types::Requirements = serde_json::from_value(serde_json::json!({
            "schema": "post.v1"
        }))
        .unwrap();
        assert!(!require.dnssec_proof);
    }

    #[test]
    fn user_variable_substitutes_signer_canonical_id() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "*", "can": ["create"], "on": "/u/$user/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("e_x").unwrap();
        let no = |_: &AttestedSource| false;
        let vars = PolicyVars { user: Some("alice@mingo.place"), ..Default::default() };
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/x/", &vars, false, &no, &msg, None),
            PolicyResult::Allowed
        ));
        // Different user than the path namespace → denied.
        let vars_other = PolicyVars { user: Some("bob@mingo.place"), ..Default::default() };
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/u/alice@mingo.place/x/", &vars_other, false, &no, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    // --- Resolution-based identity matching (Policy Spec §Identity references) --

    /// A grant to a bare name matches an actor canonicalized to the
    /// primary-domain email — the name and the email resolve to one controller.
    #[test]
    fn bare_name_matches_primary_domain_email_actor() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "sys", "can": ["*"], "on": "/sys/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("sys@mingo.place").unwrap();
        let no = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/sys/x/", &PolicyVars::default(), false, &no, &msg, Some("mingo.place")),
            PolicyResult::Allowed
        ));
    }

    /// The email form of the same reference keeps matching the email actor.
    #[test]
    fn email_name_matches_email_actor() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "sys@mingo.place", "can": ["*"], "on": "/sys/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("sys@mingo.place").unwrap();
        let no = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/sys/x/", &PolicyVars::default(), false, &no, &msg, Some("mingo.place")),
            PolicyResult::Allowed
        ));
    }

    /// Security: a bare name resolves ONLY to the primary domain. It must NOT
    /// match a signer attributed to a foreign email-provider domain.
    #[test]
    fn bare_name_does_not_match_foreign_domain_actor() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "dan", "can": ["*"], "on": "/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("dan@gmail.com").unwrap();
        let no = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/dan/x/", &PolicyVars::default(), false, &no, &msg, Some("mingo.place")),
            PolicyResult::Denied(_)
        ));
    }

    /// The key form still matches by public key (the live checkpointer grant).
    #[test]
    fn key_form_still_matches_by_pubkey() {
        let key = SigningKey::generate();
        let mut msg = signed_msg();
        msg.signing_key = key.public_key();
        msg.sign(&key);
        let key_str = key.public_key().to_string();
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": {"key": key_str}, "can": ["*"], "on": "/**"}]
        }))
        .unwrap();
        let actor = Id::new("checkpointer@mingo.place").unwrap();
        let no = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/x/", &PolicyVars::default(), false, &no, &msg, Some("mingo.place")),
            PolicyResult::Allowed
        ));
    }

    /// A role whose member is a bare name matches an email-form actor — the
    /// `roles.admin: ["sys"]` case that regressed.
    #[test]
    fn role_bare_name_member_matches_email_actor() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "roles": { "admin": ["sys"] },
            "grants": [{"to": {"role": "admin"}, "can": ["*"], "on": "/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("sys@mingo.place").unwrap();
        let no = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/x/", &PolicyVars::default(), false, &no, &msg, Some("mingo.place")),
            PolicyResult::Allowed
        ));
    }

    /// No primary domain (chain-only repo): a bare name stays literal — it
    /// matches a bare-name actor and does not spuriously gain a domain.
    #[test]
    fn no_primary_domain_keeps_bare_name_literal() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": "sys", "can": ["*"], "on": "/sys/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let no = |_: &AttestedSource| false;

        let actor_bare = Id::new("sys").unwrap();
        assert!(matches!(
            evaluate(&policy, &actor_bare, ActionType::Create, "/sys/x/", &PolicyVars::default(), false, &no, &msg, None),
            PolicyResult::Allowed
        ));
        // Without a primary domain, an email-form actor is a different party.
        let actor_email = Id::new("sys@mingo.place").unwrap();
        assert!(matches!(
            evaluate(&policy, &actor_email, ActionType::Create, "/sys/x/", &PolicyVars::default(), false, &no, &msg, None),
            PolicyResult::Denied(_)
        ));
    }

    /// `*` and `any` are unaffected by the primary-domain threading.
    #[test]
    fn wildcard_and_any_unaffected() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "grants": [{"to": {"any": ["*"]}, "can": ["*"], "on": "/**"}]
        }))
        .unwrap();
        let msg = signed_msg();
        let actor = Id::new("anybody@elsewhere.com").unwrap();
        let no = |_: &AttestedSource| false;
        assert!(matches!(
            evaluate(&policy, &actor, ActionType::Create, "/x/", &PolicyVars::default(), false, &no, &msg, Some("mingo.place")),
            PolicyResult::Allowed
        ));
    }
}
