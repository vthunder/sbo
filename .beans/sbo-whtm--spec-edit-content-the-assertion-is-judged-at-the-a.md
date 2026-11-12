---
# sbo-whtm
title: 'Spec edit (Content): the assertion is judged at the authoring instant bounded by a capped W; _config needs an explicit grant (Q9, S10)'
status: completed
type: task
priority: normal
created_at: 2026-11-04T21:36:02Z
updated_at: 2026-11-05T10:38:34Z
parent: sbo-ax7t
---

`specs/SBO Content Specification.md`: replace 'attribution is unchanged … valid at inclusion time' with the Q9 (a) rule; protocol maximum for `W` (reference 24 h); `_config` writes require the governing policy to grant them explicitly.

- [x] Q9 text

## Summary of Changes

specs/SBO Content Specification.md: changelog; abstract sentence; Validity bound defines W_max (reference 24 h), clamping of max_authoring_lag_s and checked arithmetic (D22); §Attribution and Offline Writes replaces 'attribution is unchanged ... valid at inclusion time' with the Q9 (a) rule (assertion at the HLC authoring instant bounded by W, everything else at inclusion time; offline budget = min(access-cert lifetime, W)); §Declaring a tier adds the explicit-grant requirement for _config (id: _config grant or govern, never an ordinary create grant); worked example and Security Considerations updated.
