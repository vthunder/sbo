//! The one identity-comparison rule (Identity Specification; audit 2026-11
//! decision Q5, findings S6 / D13 / D54).
//!
//! An email-rooted identity reference is `<local>@<domain>` with **exactly one
//! `@`**, a non-empty local part and a non-empty domain. Two references name
//! the same identity iff the local part is byte-equal and the domain is equal
//! as a lowercased A-label. The canonical on-chain form carries the domain in
//! lowercase; [`crate::id::Id::new`] rejects any other spelling, so a header
//! can never alias a path (`/u/alice@Example.com/` vs `/u/alice@example.com/`).
//!
//! Every comparison site (`resolve_controller`, `check_authority`,
//! `dns::parse_email`, policy `canonical_name_ref`) goes through this module;
//! none splits on `@` by hand.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Why a string is not an identity reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// No `@` at all: a bare name or a key, not an email-rooted identity.
    NotAnIdentity,
    /// More than one `@`.
    MultipleAt,
    /// Empty local part.
    EmptyLocal,
    /// Empty domain.
    EmptyDomain,
}

/// Split `<local>@<domain>` under the Q5 rule. The domain is returned as
/// written (not lowercased); use [`domain_of`] for the comparison form.
pub fn split(reference: &str) -> Result<(&str, &str), IdentityError> {
    let mut parts = reference.split('@');
    let local = parts.next().unwrap_or("");
    let domain = match parts.next() {
        None => return Err(IdentityError::NotAnIdentity),
        Some(d) => d,
    };
    if parts.next().is_some() {
        return Err(IdentityError::MultipleAt);
    }
    if local.is_empty() {
        return Err(IdentityError::EmptyLocal);
    }
    if domain.is_empty() {
        return Err(IdentityError::EmptyDomain);
    }
    Ok((local, domain))
}

/// Whether the reference is a well-formed identity reference (exactly one
/// `@`, both parts non-empty), in any domain case.
pub fn is_identity(reference: &str) -> bool {
    split(reference).is_ok()
}

/// Whether the reference is in canonical on-chain form: well-formed and the
/// domain carries no uppercase ASCII.
pub fn is_canonical(reference: &str) -> bool {
    matches!(split(reference), Ok((_, d)) if !d.bytes().any(|b| b.is_ascii_uppercase()))
}

/// The comparison form of the domain (lowercased A-label), or `None` when the
/// string is not an identity reference.
#[cfg(feature = "alloc")]
pub fn domain_of(reference: &str) -> Option<String> {
    split(reference).ok().map(|(_, d)| d.to_ascii_lowercase())
}

/// The canonical on-chain form (`<local>@<lowercase domain>`), or `None` when
/// the string is not an identity reference.
#[cfg(feature = "alloc")]
pub fn canonical(reference: &str) -> Option<String> {
    let (local, domain) = split(reference).ok()?;
    let mut out = String::with_capacity(reference.len());
    out.push_str(local);
    out.push('@');
    for b in domain.bytes() {
        out.push(b.to_ascii_lowercase() as char);
    }
    Some(out)
}

/// Whether two identity references name the same identity: local part
/// byte-exact, domain case-insensitive. Strings without `@` (bare names,
/// keys, `null:`) compare byte-exact. A malformed identity reference (`a@b@c`,
/// `@x`, `a@`) is no identity and never equals anything, itself included.
pub fn identity_eq(a: &str, b: &str) -> bool {
    match (split(a), split(b)) {
        (Ok((la, da)), Ok((lb, db))) => la == lb && da.eq_ignore_ascii_case(db),
        (Err(IdentityError::NotAnIdentity), Err(IdentityError::NotAnIdentity)) => a == b,
        _ => false,
    }
}

/// Whether the reference's domain equals `domain`, case-insensitively.
pub fn in_domain(reference: &str, domain: &str) -> bool {
    matches!(split(reference), Ok((_, d)) if d.eq_ignore_ascii_case(domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_at() {
        assert_eq!(split("a@mingo.place@evil"), Err(IdentityError::MultipleAt));
        assert_eq!(split("alice"), Err(IdentityError::NotAnIdentity));
        assert_eq!(split("@x.com"), Err(IdentityError::EmptyLocal));
        assert_eq!(split("alice@"), Err(IdentityError::EmptyDomain));
        assert_eq!(split("alice+bot@x.com"), Ok(("alice+bot", "x.com")));
    }

    #[test]
    fn comparison_rule() {
        assert!(identity_eq("alice@example.com", "alice@EXAMPLE.COM"));
        assert!(!identity_eq("alice@example.com", "Alice@example.com"));
        assert!(!identity_eq("alice@example.com", "alice+bot@example.com"));
        assert!(!identity_eq("alice@example.com", "alice@example.com."));
        assert!(identity_eq("sys", "sys"));
        assert!(!identity_eq("sys", "sys@example.com"));
        assert!(!identity_eq("a@b@c", "a@b@c"));
        assert!(in_domain("alice@EXAMPLE.com", "example.com"));
        assert!(!in_domain("a@mingo.place@evil", "mingo.place"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonical_form() {
        assert_eq!(canonical("alice@EXAMPLE.com").as_deref(), Some("alice@example.com"));
        assert_eq!(canonical("Alice@Example.com").as_deref(), Some("Alice@example.com"));
        assert_eq!(canonical("a@b@c"), None);
        assert_eq!(domain_of("alice@EXAMPLE.com").as_deref(), Some("example.com"));
        assert!(is_canonical("alice@example.com"));
        assert!(!is_canonical("alice@Example.com"));
    }
}
