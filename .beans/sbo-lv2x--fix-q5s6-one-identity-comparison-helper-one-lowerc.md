---
# sbo-lv2x
title: 'Fix Q5/S6: one identity-comparison helper (one @, lowercase A-label domain, byte-exact local part)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-05T10:20:48Z
parent: sbo-ax7t
blocking:
    - sbo-3ao9
    - sbo-nepw
---

Shared helper. Four byte-exact comparison sites (`resolve.rs:70-90`, `device_attribution.rs::check_authority`, `dns.rs::parse_email`, policy `canonical_name_ref`) and no spec rule; `Id` admits several `@` and the two split rules disagree (D54). Q5 (a): exactly one `@`, domain compared as a lowercased A-label, local part byte-exact, canonical on-chain form lowercase-domain; a header with an uppercase domain is invalid. Also remove the vestigial `names.rs IdentityClaim` (sbo-0web) if confirmed dead.

No open decision. Blocks: D13 bean, Q36 grammar bean.

- [x] `sbo-core::identity` (or `sbo-types`) helper: parse, canonical form, `identity_eq`
- [x] Acceptance: `audit_2026_11_ws3_uri_identity.rs` `d13_uppercase_domain_is_not_a_valid_identity_reference`, `d54_identity_has_exactly_one_at`

## Summary of Changes

- New `sbo_types::identity` (re-exported as `sbo_core::identity`): `split` (exactly one `@`, both parts non-empty), `domain_of` / `canonical` (lowercase A-label domain), `identity_eq` (local byte-exact, domain case-insensitive; malformed references equal nothing), `in_domain`, `is_canonical`.
- `Id::new` enforces the identity rule on any id with `@`: one `@`, non-empty local/domain, lowercase domain (`IdentityMultipleAt` / `IdentityEmptyLocal` / `IdentityEmptyDomain` / `IdentityDomainNotLowercase` reasons).
- Identity spec: new "Comparing identity references" paragraph; Core spec §Identifier Syntax names the rule.
- Removed the vestigial `state/names.rs` `IdentityClaim` (defined and re-exported, never used; sbo-0web item).
- Un-ignored `d13_uppercase_domain_is_not_a_valid_identity_reference`, `d54_identity_has_exactly_one_at` (ws3_uri_identity); the latter now asserts `parse_email("a@b@c") == None`.
