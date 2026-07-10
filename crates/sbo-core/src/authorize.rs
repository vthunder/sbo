//! L2 owner authorization — the bridge between attribution and ownership.
//!
//! This module composes the two halves of SBO's L2 (attribution) validity
//! layer into a single decision:
//!
//! 1. [`resolve::resolve_controller`] resolves an object's `Owner` reference to
//!    a [`Controller`] (a key, an email, or unresolvable).
//! 2. [`attribution::verify_attribution`] decides which email (if any) the
//!    signing key speaks for at the write's DA inclusion time.
//! 3. [`resolve::is_authorized`] combines the two: a key-rooted owner needs a
//!    direct signature match; an email-rooted owner needs the signer to be
//!    attributed to that email.
//!
//! The result is [`AuthzOutcome::Authorized`] or [`AuthzOutcome::Unauthorized`].
//! Per the Validity-Layers spec, an L1-valid but L2-unauthorized write is
//! *carried* by the DA layer but *disregarded* on replay — it must not mutate
//! owned state. Callers therefore treat [`AuthzOutcome::Unauthorized`] as a
//! skip, not a hard parse error.
//!
//! ## Testability
//!
//! The pure decision — [`authorize_owner`] — takes an already-computed
//! `attributed_email` and a name-lookup closure, so it is fully unit-testable
//! offline. The attribution glue — [`message_attribution`] — wraps
//! [`attribution::verify_attribution`], whose DNSSEC half cannot be exercised
//! with a synthetic offline proof (the IANA root is hardcoded); that path is
//! covered by attribution.rs's `#[ignore]`d live test.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::attribution::{self, Attribution, TrustAnchors, WarrantAttribution};
use crate::uri::SboRawUri;
use crate::resolve::{is_authorized, resolve_controller, Controller, NameRecord};

/// The outcome of an L2 owner-authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzOutcome {
    /// The signer is authorized to act for the object's owner.
    Authorized,
    /// The signer is not authorized. The message is well-formed (L1-valid) but
    /// must be disregarded on replay; the string explains why (for logging).
    Unauthorized(String),
}

impl AuthzOutcome {
    /// Whether the outcome is [`AuthzOutcome::Authorized`].
    pub fn is_authorized(&self) -> bool {
        matches!(self, AuthzOutcome::Authorized)
    }
}

/// Parse an `Auth-Evidence` header value into raw RFC 9102 proof bytes.
///
/// Supported forms:
/// - `inline:<base64url>` — the proof bytes, base64url (no padding), inline.
/// - `ref:<sbo-ref>` — a reference to a self-authenticating `dnssec.v1`
///   object. Resolving it requires state access this pure function does not
///   have, so it returns `Err` here; the caller may resolve the ref and call
///   [`attribution::verify_attribution`] directly with the fetched bytes.
///
/// A bare value with no recognized prefix is rejected.
pub fn parse_auth_evidence(value: &str) -> Result<Vec<u8>, String> {
    if let Some(b64) = value.strip_prefix("inline:") {
        URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("Auth-Evidence inline base64url decode failed: {e}"))
    } else if let Some(reference) = value.strip_prefix("ref:") {
        Err(format!(
            "Auth-Evidence ref '{reference}' cannot be resolved without state access"
        ))
    } else {
        Err("Auth-Evidence must be 'inline:<base64url>' or 'ref:<sbo-ref>'".to_string())
    }
}

/// Encode raw RFC 9102 proof bytes as an inline `Auth-Evidence` header value
/// (`inline:<base64url>`), the form [`parse_auth_evidence`] round-trips.
pub fn encode_auth_evidence_inline(proof: &[u8]) -> String {
    format!("inline:{}", URL_SAFE_NO_PAD.encode(proof))
}

/// Parse the issuer domain (`iss`) from a browserid `Auth-Cert`, without
/// verifying its signature. Used to locate conventional `/sys/dnssec/<issuer>`
/// evidence when `Auth-Evidence` is absent (Authorization Spec line 140).
/// Returns `None` if the cert is unparseable.
pub fn cert_issuer(auth_cert: &str) -> Option<String> {
    browserid_core::Certificate::parse(auth_cert)
        .ok()
        .map(|c| c.issuer().to_string())
}

/// Whether an `Auth-Cert` is a typed browserid **agent** certificate (and thus
/// requires an accompanying warrant). Unparseable ⇒ `false`.
pub fn auth_cert_is_agent(auth_cert: &str) -> bool {
    browserid_core::Certificate::parse(auth_cert)
        .map(|c| c.is_agent())
        .unwrap_or(false)
}

/// Compute the [`Attribution`] for a message's signing key, if it carries a
/// valid `Auth-Cert` + `Auth-Evidence` pair verifying at `inclusion_time`.
///
/// Returns `None` when attribution is absent, malformed, or fails verification
/// — i.e. the signer is simply unattributed. (The reason is not surfaced; a
/// caller wanting the error should call [`attribution::verify_attribution`].)
pub fn message_attribution(
    signer_key: &str,
    auth_cert: Option<&str>,
    auth_evidence: Option<&str>,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Option<Attribution> {
    let cert = auth_cert?;
    let evidence_str = auth_evidence?;
    let evidence = parse_auth_evidence(evidence_str).ok()?;
    attribution::verify_attribution(signer_key, cert, &evidence, inclusion_time, anchors).ok()
}

/// Decide whether a write signed by `signer_key`, with optional
/// `attributed_email` (the email the signer was proven to speak for at
/// inclusion time, or `None`), is authorized for an object whose `Owner`
/// reference is `owner_ref`.
///
/// `lookup` resolves `/sys/names/<name>` records; `hop_limit` bounds name
/// indirection (use [`resolve::DEFAULT_HOP_LIMIT`]). Pure and deterministic.
pub fn authorize_owner<F>(
    owner_ref: &str,
    signer_key: &str,
    attributed_email: Option<&str>,
    lookup: &F,
    hop_limit: u32,
    primary_domain: Option<&str>,
) -> AuthzOutcome
where
    F: Fn(&str) -> Option<NameRecord>,
{
    let controller = resolve_controller(owner_ref, lookup, hop_limit, primary_domain);
    if is_authorized(&controller, signer_key, attributed_email) {
        return AuthzOutcome::Authorized;
    }
    let reason = match controller {
        Controller::Key(k) => format!(
            "owner '{owner_ref}' is key-rooted ({k}) but signer is {signer_key}"
        ),
        Controller::Email(e) => match attributed_email {
            Some(att) => format!(
                "owner '{owner_ref}' is email-rooted ({e}) but signer is attributed to {att}"
            ),
            None => format!(
                "owner '{owner_ref}' is email-rooted ({e}) but signer carries no valid attribution"
            ),
        },
        Controller::None => format!("owner '{owner_ref}' resolves to no controller"),
        Controller::Unresolved => format!("owner '{owner_ref}' could not be resolved"),
    };
    AuthzOutcome::Unauthorized(reason)
}

/// Convenience: compute the message's attribution and authorize it against
/// `owner_ref` in one call. The daemon uses this on replay.
#[allow(clippy::too_many_arguments)]
pub fn authorize_message<F>(
    owner_ref: &str,
    signer_key: &str,
    auth_cert: Option<&str>,
    auth_evidence: Option<&str>,
    inclusion_time: i64,
    anchors: &TrustAnchors,
    lookup: &F,
    hop_limit: u32,
    primary_domain: Option<&str>,
) -> AuthzOutcome
where
    F: Fn(&str) -> Option<NameRecord>,
{
    let attribution =
        message_attribution(signer_key, auth_cert, auth_evidence, inclusion_time, anchors);
    let email = attribution.as_ref().map(|a| a.email.as_str());
    authorize_owner(owner_ref, signer_key, email, lookup, hop_limit, primary_domain)
}

/// Whether a warrant audience string identifies the database `db` (with genesis
/// hash `db_genesis`, if known) — the SBO Authorization Spec audience rule. The
/// audience MUST be an `sbo+raw://` **bare** reference whose authority equals
/// `chain:appId`; an `@firstBlock` anchor and/or `?genesis` in the audience must
/// match if present. A bare-authority audience matches across a regenesis; a
/// pinned one confines to a genesis instance. `sbo://` audiences never identify
/// a database on chain (DNS is not a trust root) and are rejected.
pub fn audience_identifies_db(aud: &str, db: &SboRawUri, db_genesis: Option<&str>) -> bool {
    let a = match SboRawUri::parse(aud) {
        Ok(a) => a,
        Err(_) => return false, // not sbo+raw:// (e.g. sbo:// or garbage)
    };
    // Bare reference: no path/creator/id (path is None or just "/").
    if let Some(path) = &a.path {
        if path != "/" {
            return false;
        }
    }
    // Authority: chain:appId always required.
    if a.chain != db.chain || a.app_id != db.app_id {
        return false;
    }
    // If the audience pins the anchor, it must match the database's.
    if let Some(fb) = a.first_block {
        if Some(fb) != db.first_block {
            return false;
        }
    }
    // If the audience pins the genesis hash, it must match.
    if let Some(g) = &a.query.genesis {
        match db_genesis {
            Some(dg) if dg == g => {}
            _ => return false,
        }
    }
    true
}

/// Split a scope string `"<dimension>:<value>"`. Returns `None` for a
/// malformed (colon-less) scope.
fn scope_parts(scope: &str) -> Option<(&str, &str)> {
    scope.split_once(':')
}

/// Segment glob match: `*` matches within one path segment, `**` matches any
/// number of segments. Paths compare by `/`-split segments.
fn path_glob_matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let seg: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    fn m(pat: &[&str], seg: &[&str]) -> bool {
        match pat.first() {
            None => seg.is_empty(),
            Some(&"**") => {
                // `**` consumes zero-or-more segments.
                (0..=seg.len()).any(|k| m(&pat[1..], &seg[k..]))
            }
            Some(&p) => {
                if seg.is_empty() { return false; }
                let head_ok = p == "*" || p == seg[0];
                head_ok && m(&pat[1..], &seg[1..])
            }
        }
    }
    m(&pat, &seg)
}

/// Whether the warrant `scopes` authorize a write with the given `action`,
/// `path`, and optional `content_schema` (SBO Authorization Spec scope grammar).
/// OR within a dimension, AND across dimensions; a dimension with no scope is
/// unconstrained. `as:` is recognized (identity selector, see
/// [`warrant_effective_email`]) and does not constrain the write. An
/// **unrecognized** dimension fails closed.
pub fn scopes_authorize(
    scopes: &[String],
    action: &str,
    path: &str,
    content_schema: Option<&str>,
) -> bool {
    let (mut acts, mut paths, mut schemas) = (Vec::new(), Vec::new(), Vec::new());
    for sc in scopes {
        match scope_parts(sc) {
            Some(("action", v)) => acts.push(v),
            Some(("path", v)) => paths.push(v),
            Some(("schema", v)) => schemas.push(v),
            Some(("as", _)) => {} // identity selector — not a write constraint here
            _ => return false, // unrecognized dimension ⇒ fail closed
        }
    }
    if !acts.is_empty() && !acts.iter().any(|a| *a == action) {
        return false;
    }
    if !paths.is_empty() && !paths.iter().any(|p| path_glob_matches(p, path)) {
        return false;
    }
    if !schemas.is_empty() {
        match content_schema {
            Some(cs) if schemas.iter().any(|s| *s == cs) => {}
            _ => return false,
        }
    }
    true
}

/// Resolve the **effective author** of an agent write from its warrant scopes.
/// Default (no `as:`) is the agent itself. An `as:<delegator>` scope makes the
/// effective author the delegator — but only if it names exactly the delegator
/// and the warrant also carries at least one `path:` scope (guardrail: no
/// unrestricted act-as-you). Returns `Err(reason)` if the `as:` scope is
/// malformed, names a non-delegator, is duplicated, or lacks a path scope.
pub fn warrant_effective_email(
    scopes: &[String],
    agent_email: &str,
    delegator: &str,
) -> Result<String, String> {
    let as_targets: Vec<&str> = scopes
        .iter()
        .filter_map(|s| scope_parts(s))
        .filter(|(d, _)| *d == "as")
        .map(|(_, v)| v)
        .collect();
    match as_targets.as_slice() {
        [] => Ok(agent_email.to_string()),
        [target] => {
            if *target != delegator {
                return Err(format!(
                    "on-behalf scope 'as:{target}' does not name the delegator '{delegator}'"
                ));
            }
            let has_path = scopes.iter().any(|s| matches!(scope_parts(s), Some(("path", _))));
            if !has_path {
                return Err("on-behalf ('as:') warrant must also carry a 'path:' scope".into());
            }
            Ok(delegator.to_string())
        }
        _ => Err("warrant carries more than one 'as:' scope".into()),
    }
}

/// The effective attributed email for an agent write, or `Err(reason)`: verifies
/// the warrant binds to `wa` (already crypto-verified by attribution), that its
/// audience identifies this database, that its scopes permit this write, and
/// resolves agent-vs-delegator authorship. `on_behalf_allowed` is the
/// repository's policy toggle (guardrail 2); pass `true` unless the repo opts
/// out of on-behalf writes.
#[allow(clippy::too_many_arguments)]
pub fn agent_effective_email(
    wa: &WarrantAttribution,
    db: &SboRawUri,
    db_genesis: Option<&str>,
    action: &str,
    path: &str,
    content_schema: Option<&str>,
    on_behalf_allowed: bool,
) -> Result<String, String> {
    if !audience_identifies_db(&wa.audience, db, db_genesis) {
        return Err(format!("warrant audience '{}' does not identify this database", wa.audience));
    }
    if !scopes_authorize(&wa.scopes, action, path, content_schema) {
        return Err("warrant scopes do not authorize this write".into());
    }
    let email = warrant_effective_email(&wa.scopes, &wa.agent_email, &wa.delegator)?;
    if email == wa.delegator && email != wa.agent_email && !on_behalf_allowed {
        return Err("this repository does not honor on-behalf ('as:') warrants".into());
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::DEFAULT_HOP_LIMIT;
    use std::collections::HashMap;

    fn lookup_from(map: HashMap<String, NameRecord>) -> impl Fn(&str) -> Option<NameRecord> {
        move |name: &str| map.get(name).cloned()
    }

    fn empty_lookup() -> impl Fn(&str) -> Option<NameRecord> {
        lookup_from(HashMap::new())
    }

    #[test]
    fn key_rooted_owner_authorized_by_direct_signature() {
        let mut map = HashMap::new();
        map.insert("alice".to_string(), NameRecord::KeyRooted("pk_alice".to_string()));
        let lookup = lookup_from(map);
        // Owner resolves to a key; signer matches → authorized, no attribution needed.
        assert_eq!(
            authorize_owner("alice", "pk_alice", None, &lookup, DEFAULT_HOP_LIMIT, None),
            AuthzOutcome::Authorized
        );
    }

    #[test]
    fn key_rooted_owner_rejects_wrong_signer() {
        let mut map = HashMap::new();
        map.insert("alice".to_string(), NameRecord::KeyRooted("pk_alice".to_string()));
        let lookup = lookup_from(map);
        assert!(matches!(
            authorize_owner("alice", "pk_mallory", None, &lookup, DEFAULT_HOP_LIMIT, None),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn email_rooted_owner_authorized_by_matching_attribution() {
        let lookup = empty_lookup();
        // Bare-email owner; signer attributed to that email → authorized.
        assert_eq!(
            authorize_owner(
                "alice@example.com",
                "ephemeral_key",
                Some("alice@example.com"),
                &lookup,
                DEFAULT_HOP_LIMIT,
                None
            ),
            AuthzOutcome::Authorized
        );
    }

    #[test]
    fn email_rooted_owner_rejects_missing_attribution() {
        let lookup = empty_lookup();
        assert!(matches!(
            authorize_owner(
                "alice@example.com",
                "ephemeral_key",
                None,
                &lookup,
                DEFAULT_HOP_LIMIT,
                None
            ),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn email_rooted_owner_rejects_wrong_email_attribution() {
        let lookup = empty_lookup();
        assert!(matches!(
            authorize_owner(
                "alice@example.com",
                "ephemeral_key",
                Some("bob@example.com"),
                &lookup,
                DEFAULT_HOP_LIMIT,
                None
            ),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn name_indirection_to_email_authorized() {
        // alice (a name) → identity.email.v1 owned by alice@example.com.
        let mut map = HashMap::new();
        map.insert(
            "alice".to_string(),
            NameRecord::EmailRooted("alice@example.com".to_string()),
        );
        let lookup = lookup_from(map);
        assert_eq!(
            authorize_owner(
                "alice",
                "ephemeral_key",
                Some("alice@example.com"),
                &lookup,
                DEFAULT_HOP_LIMIT,
                None
            ),
            AuthzOutcome::Authorized
        );
    }

    #[test]
    fn unresolved_owner_is_unauthorized() {
        let lookup = empty_lookup();
        assert!(matches!(
            authorize_owner("ghost", "k", Some("a@b"), &lookup, DEFAULT_HOP_LIMIT, None),
            AuthzOutcome::Unauthorized(_)
        ));
    }

    #[test]
    fn parse_inline_evidence_roundtrips() {
        let bytes = b"\x00\x01\x02proof-bytes\xff";
        let encoded = format!("inline:{}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(parse_auth_evidence(&encoded).unwrap(), bytes);
    }

    #[test]
    fn parse_ref_evidence_is_unsupported_here() {
        assert!(parse_auth_evidence("ref:/sys/dnssec/example.com").is_err());
    }

    #[test]
    fn parse_bare_evidence_rejected() {
        assert!(parse_auth_evidence("deadbeef").is_err());
    }

    #[test]
    fn cert_issuer_parses_iss_without_verification() {
        use browserid_core::{Certificate, KeyPair};
        let provider = KeyPair::generate();
        let user = KeyPair::generate();
        let cert = Certificate::create(
            "id.sandmill.org",
            "alice@sandmill.org",
            &user.public_key(),
            chrono::Duration::seconds(3600),
            &provider,
        )
        .unwrap();
        assert_eq!(cert_issuer(cert.encoded()).as_deref(), Some("id.sandmill.org"));
        assert_eq!(cert_issuer("not-a-cert"), None);
    }

    #[test]
    fn message_attribution_none_without_cert() {
        let anchors = TrustAnchors::default();
        assert!(message_attribution("k", None, Some("inline:AAAA"), 0, &anchors).is_none());
        assert!(message_attribution("k", Some("cert"), None, 0, &anchors).is_none());
    }

    // ---- agent warrant helpers ----
    use crate::attribution::WarrantAttribution;
    use crate::uri::SboRawUri;

    fn db() -> SboRawUri { SboRawUri::parse("sbo+raw://avail:turing:506@3567386/").unwrap() }

    #[test]
    fn audience_bare_and_pinned() {
        let db = db();
        // Bare authority matches (survives regenesis).
        assert!(audience_identifies_db("sbo+raw://avail:turing:506/", &db, Some("sha256:abc")));
        // Pinned anchor matches.
        assert!(audience_identifies_db("sbo+raw://avail:turing:506@3567386/", &db, None));
        // Pinned genesis matches / mismatches.
        assert!(audience_identifies_db("sbo+raw://avail:turing:506@3567386/?genesis=sha256:abc", &db, Some("sha256:abc")));
        assert!(!audience_identifies_db("sbo+raw://avail:turing:506@3567386/?genesis=sha256:zzz", &db, Some("sha256:abc")));
        // Wrong appId, wrong anchor, and sbo:// / garbage all fail.
        assert!(!audience_identifies_db("sbo+raw://avail:turing:999/", &db, None));
        assert!(!audience_identifies_db("sbo+raw://avail:turing:506@9999/", &db, None));
        assert!(!audience_identifies_db("sbo://mingo.place/", &db, None));
        assert!(!audience_identifies_db("https://mingo.place", &db, None));
        // Non-bare (has a path) is rejected.
        assert!(!audience_identifies_db("sbo+raw://avail:turing:506/attestor", &db, None));
    }

    #[test]
    fn scopes_grammar() {
        // action OR + path glob AND schema.
        let sc = vec!["action:post".to_string(), "path:/attestor/*".to_string()];
        assert!(scopes_authorize(&sc, "post", "/attestor/note", None));
        assert!(!scopes_authorize(&sc, "delete", "/attestor/note", None)); // wrong action
        assert!(!scopes_authorize(&sc, "post", "/other/note", None));      // wrong path
        assert!(!scopes_authorize(&sc, "post", "/attestor/a/b", None));    // * is one segment
        // ** spans segments.
        assert!(scopes_authorize(&["path:/attestor/**".to_string()], "post", "/attestor/a/b", None));
        // schema dimension.
        let sc = vec!["schema:nft.v1".to_string()];
        assert!(scopes_authorize(&sc, "post", "/x", Some("nft.v1")));
        assert!(!scopes_authorize(&sc, "post", "/x", Some("other.v1")));
        assert!(!scopes_authorize(&sc, "post", "/x", None));
        // unknown dimension fails closed; `as:` recognized (non-constraining).
        assert!(!scopes_authorize(&["frobnicate:yes".to_string()], "post", "/x", None));
        assert!(scopes_authorize(&["as:human@example.com".to_string(), "path:/u/**".to_string()], "post", "/u/a", None));
    }

    #[test]
    fn effective_email_agent_vs_delegator() {
        // Default: the agent.
        assert_eq!(warrant_effective_email(&[], "bot@x", "human@x").unwrap(), "bot@x");
        // On-behalf with a path scope: the delegator.
        let sc = vec!["as:human@x".to_string(), "path:/u/human/**".to_string()];
        assert_eq!(warrant_effective_email(&sc, "bot@x", "human@x").unwrap(), "human@x");
        // `as:` naming a non-delegator, or without a path scope, or duplicated → error.
        assert!(warrant_effective_email(&["as:mallory@x".to_string(), "path:/**".to_string()], "bot@x", "human@x").is_err());
        assert!(warrant_effective_email(&["as:human@x".to_string()], "bot@x", "human@x").is_err());
        assert!(warrant_effective_email(&["as:human@x".to_string(), "as:human@x".to_string(), "path:/**".to_string()], "bot@x", "human@x").is_err());
    }

    #[test]
    fn agent_effective_email_integration() {
        let db = db();
        let wa = WarrantAttribution {
            agent_email: "attestor@browserid.me".into(),
            delegator: "human@example.com".into(),
            audience: "sbo+raw://avail:turing:506/".into(),
            scopes: vec!["action:post".into(), "path:/attestor/*".into()],
        };
        // Authorized as the agent.
        assert_eq!(
            agent_effective_email(&wa, &db, None, "post", "/attestor/note", None, true).unwrap(),
            "attestor@browserid.me"
        );
        // Wrong audience / out-of-scope path → Err.
        let mut wrong = wa.clone();
        wrong.audience = "sbo+raw://avail:turing:999/".into();
        assert!(agent_effective_email(&wrong, &db, None, "post", "/attestor/note", None, true).is_err());
        assert!(agent_effective_email(&wa, &db, None, "post", "/elsewhere", None, true).is_err());

        // On-behalf, honored vs repo opt-out.
        let ob = WarrantAttribution {
            scopes: vec!["as:human@example.com".into(), "path:/u/human/**".into()],
            ..wa.clone()
        };
        assert_eq!(agent_effective_email(&ob, &db, None, "post", "/u/human/draft", None, true).unwrap(), "human@example.com");
        assert!(agent_effective_email(&ob, &db, None, "post", "/u/human/draft", None, false).is_err());
    }

}
