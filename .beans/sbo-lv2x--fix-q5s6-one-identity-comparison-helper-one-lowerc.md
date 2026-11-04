---
# sbo-lv2x
title: 'Fix Q5/S6: one identity-comparison helper (one @, lowercase A-label domain, byte-exact local part)'
status: todo
type: task
priority: normal
created_at: 2026-11-04T21:32:42Z
updated_at: 2026-11-04T21:34:48Z
parent: sbo-ax7t
blocking:
    - sbo-3ao9
    - sbo-nepw
---

Shared helper. Four byte-exact comparison sites (`resolve.rs:70-90`, `device_attribution.rs::check_authority`, `dns.rs::parse_email`, policy `canonical_name_ref`) and no spec rule; `Id` admits several `@` and the two split rules disagree (D54). Q5 (a): exactly one `@`, domain compared as a lowercased A-label, local part byte-exact, canonical on-chain form lowercase-domain; a header with an uppercase domain is invalid. Also remove the vestigial `names.rs IdentityClaim` (sbo-0web) if confirmed dead.

No open decision. Blocks: D13 bean, Q36 grammar bean.

- [ ] `sbo-core::identity` (or `sbo-types`) helper: parse, canonical form, `identity_eq`
- [ ] Acceptance: `audit_2026_11_ws3_uri_identity.rs` `d13_uppercase_domain_is_not_a_valid_identity_reference`, `d54_identity_has_exactly_one_at`
