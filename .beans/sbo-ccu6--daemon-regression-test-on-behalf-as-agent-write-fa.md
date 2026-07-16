---
# sbo-ccu6
title: 'Daemon regression test: on-behalf (as:) agent write faces delegator''s policy'
status: todo
type: task
priority: high
created_at: 2026-07-14T23:27:01Z
updated_at: 2026-07-14T23:27:01Z
---

The fix in sbo 54f4b11 (validate.rs: resolve_agent_effective wired into attributed_email) makes on-behalf agent writes attribute to the delegator for the policy check, so a member's mingo-posted write is granted. Covered by the spec + all 89 existing tests pass, but there's NO daemon-level test exercising the exact path (agent cert + as: warrant + DNSSEC evidence + member-gated community policy).

Add one modeled on tests/l2_authorization.rs open_community_membership_post_and_ban_end_to_end: build an agent-cert + as:<user> warrant + evidence harness (none exists in daemon tests yet — sbo-core/tests/agent_write.rs has the cert/warrant construction to borrow), attest <user> as a community member, then assert an AGENT post on-behalf(as:<user>) is ALLOWED, and a non-member delegator is DENIED 'No matching grant'. Also assert the object's creator/attribution resolves to <user>, not the agent.
