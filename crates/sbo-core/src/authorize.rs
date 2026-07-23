//! L2 owner authorization — the bridge between attribution and ownership.
//!
//! This module composes the two halves of SBO's L2 (attribution) validity
//! layer into a single decision:
//!
//! 1. [`resolve::resolve_controller`] resolves an object's `Owner` reference to
//!    a [`Controller`] (a key, an email, or unresolvable).
//! 2. [`message_attribution`] verifies the write's device-model presentation
//!    (`crate::device_attribution`) and decides which email (if any) the signing
//!    key speaks for at the write's DA inclusion time.
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
//! [`crate::device_attribution::verify_device_attribution`], whose DNSSEC half
//! cannot be exercised with a synthetic offline proof (the IANA root is
//! hardcoded); that path is covered by the device-attribution unit tests
//! (provider key supplied directly) plus an `#[ignore]`d live test.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::attribution::TrustAnchors;
use crate::device_attribution::{verify_device_attribution, DeviceAttribution};
use crate::uri::SboRawUri;
use crate::resolve::{is_authorized, resolve_controller, Controller, NameRecord};
use browserid_core::device::AccessPresentation;

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
///   [`message_attribution`] directly with the fetched bytes.
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

/// Parse the issuer domain (`iss`) from a device-model presentation's access
/// cert, without verifying its signature. Used to locate conventional
/// `/sys/dnssec/<issuer>` evidence when `Auth-Evidence` is absent (Authorization
/// Spec line 140). Returns `None` if the presentation is unparseable.
pub fn presentation_issuer(presentation: &str) -> Option<String> {
    AccessPresentation::parse(presentation)
        .ok()
        .map(|p| p.access_cert.claims().iss.clone())
}

/// The audience the presentation's warrant (and assertion) is bound to — an
/// `sbo+raw://…` reference. Read without verifying signatures; the caller checks
/// it identifies this database (via [`audience_identifies_db`]) and then passes
/// it as the `expected_audience` the presentation verifier enforces. `None` if
/// the presentation is unparseable.
pub fn presentation_audience(presentation: &str) -> Option<String> {
    AccessPresentation::parse(presentation)
        .ok()
        .map(|p| p.warrant.claims().audience.clone())
}

/// Compute the [`DeviceAttribution`] for a message's signing key, if it carries
/// a valid device-model presentation (`Auth-Cert`) + `Auth-Evidence` pair that
/// verifies at `inclusion_time` for `expected_audience`.
///
/// Returns `None` when attribution is absent, malformed, or fails verification
/// — i.e. the signer is simply unattributed.
pub fn message_attribution(
    signer_key: &str,
    presentation: Option<&str>,
    get_evidence: impl Fn(&str) -> Option<Vec<u8>>,
    expected_audience: &str,
    inclusion_time: i64,
    anchors: &TrustAnchors,
) -> Option<DeviceAttribution> {
    let pres = presentation?;
    verify_device_attribution(
        signer_key,
        pres,
        get_evidence,
        expected_audience,
        inclusion_time,
        anchors,
    )
    .ok()
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

/// The attributed author of a device-model write, or `Err(reason)`: the write's
/// presentation is already crypto-verified into `attr` (identity, subject,
/// scopes, all bound to the presentation's audience). This enforces the
/// remaining SBO-layer authorization: that the warrant's scopes permit THIS
/// write's action/path/schema. On success returns the warrant identifier
/// (`attr.email`) — the identity the write speaks for (a user or an agent,
/// per `attr.subject`).
///
/// Audience-identifies-database is checked by the caller *before* verification
/// (it must pass the DB-matching audience as the presentation's
/// `expected_audience`), so it is not re-checked here.
pub fn authorized_write_email(
    attr: &DeviceAttribution,
    action: &str,
    path: &str,
    content_schema: Option<&str>,
) -> Result<String, String> {
    if !scopes_authorize(&attr.scopes, action, path, content_schema) {
        return Err("warrant scopes do not authorize this write".into());
    }
    Ok(attr.email.clone())
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
    fn presentation_issuer_and_audience_none_on_garbage() {
        assert_eq!(presentation_issuer("not-a-presentation"), None);
        assert_eq!(presentation_audience("not-a-presentation"), None);
    }

    #[test]
    fn message_attribution_none_without_presentation() {
        let anchors = TrustAnchors::default();
        let aud = "sbo+raw://avail:turing:506/";
        assert!(message_attribution("k", None, |_: &str| Some(vec![0u8]), aud, 0, &anchors).is_none());
        assert!(message_attribution("k", Some("pres"), |_: &str| None::<Vec<u8>>, aud, 0, &anchors).is_none());
    }

    // ---- device-warrant helpers ----
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

    // `db()` retained above for symmetry with the audience test; the device
    // presentation itself is exercised end-to-end in
    // `device_attribution::tests` and the daemon `l2_authorization` suite. Here
    // we only check the SBO-layer scope enforcement on an already-verified
    // attribution.
    fn attr_with(scopes: Vec<String>, email: &str) -> DeviceAttribution {
        use browserid_core::device::{Holder, VerifiedAccess};
        DeviceAttribution {
            email: email.to_string(),
            grantee: email.to_string(),
            holder: Holder::new("svc.sbo").unwrap(),
            key: "ed25519:00".to_string(),
            scopes: scopes.clone(),
            issuer: "example.com".to_string(),
            grantee_issuer: "example.com".to_string(),
            valid_from: 0,
            valid_until: i64::MAX,
            verified: VerifiedAccess {
                email: email.to_string(),
                grantee: email.to_string(),
                holder: Holder::new("svc.sbo").unwrap(),
                scopes,
                issuer: "example.com".to_string(),
                grantee_issuer: "example.com".to_string(),
                access_status: None,
                config_status: None,
                warrant_status: None,
            },
        }
    }

    #[test]
    fn authorized_write_email_enforces_scopes() {
        let attr = attr_with(
            vec!["action:post".into(), "path:/attestor/*".into()],
            "attestor@example.com",
        );
        // In-scope → returns the warrant identifier.
        assert_eq!(
            authorized_write_email(&attr, "post", "/attestor/note", None).unwrap(),
            "attestor@example.com"
        );
        // Out-of-scope action / path → Err.
        assert!(authorized_write_email(&attr, "delete", "/attestor/note", None).is_err());
        assert!(authorized_write_email(&attr, "post", "/elsewhere", None).is_err());

        // Empty scopes are unconstrained (plain user write).
        let user = attr_with(vec![], "alice@example.com");
        assert_eq!(
            authorized_write_email(&user, "post", "/anything", None).unwrap(),
            "alice@example.com"
        );
    }
}
