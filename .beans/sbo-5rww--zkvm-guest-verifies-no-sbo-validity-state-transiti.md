---
# sbo-5rww
title: zkVM guest verifies no SBO validity; state transition unbound from block data
status: todo
type: bug
priority: critical
created_at: 2026-07-08T15:48:22Z
updated_at: 2026-07-08T15:48:22Z
parent: sbo-f5wn
---

methods/guest/src/main.rs:124-158 checks only header-chain + DA + trie witnesses. No signature/policy/attribution checks (design's process_sbo_actions is absent). Worse: actions hash is computed then discarded (let _actions_hash, ~line 257) and state_witness is an independent input never derived from actions_data/KZG cells, so a prover can commit ANY new_state_root with arbitrary Create/Update witnesses. A 'validity proof' proves 'some trie transition happened and data was available', not 'writes were authorized' — the design's central claim.
- [ ] Bind committed state transition to the block's actual actions (derive/verify witnesses against actions_data)
- [ ] Implement process_sbo_actions in guest: signature verify, identity resolve, policy authorization
- [ ] Guard the bootstrap-proof anchor (single proof starts at arbitrary unproven prev_state_root; only verify_proof_chain forces genesis)
- [ ] DA verification is skipped when header_data is None (returns [0;32]) — require anchoring
