# Native KAS payment research: current handoff

Worktree: `continuation`; branch: `research/shielded-kas-feasibility`.
The starting checkpoint is `8cd88a6eb4e01ddfaeeaf3c902457dc70c7032e3`.
Research remains stopped pending an owner instruction to resume.

1. Read the [session handoff](SESSION-HANDOFF-2026-10-27.md) for the exact stop
   state, failure identities, local evidence locations and resume priorities.
2. Read the [bounded financial result](final-result-01/RESULTS.md) and
   [public checkpoint](../../../docs/checkpoints/2026-10-27.md).
3. Inspect the [preserved source drafts](source-checkpoint-2026-10-27/README.md).
   Their byte-for-byte copies and draft repairs are now part of this branch.

The retained handoff reports six testnet payments, nine confirmed payouts,
zero reserve, three original-wallet recovery scans and nineteen accounted
transactions. Grouping privacy remains unresolved, measured lifecycle fees
remain 12.5793% against the fixed 2% target, and final recovery publication is
incomplete. The source import does not add experimental evidence.

The handoff is preserved as written on October 27, including its historical
statement that the handoff and external drafts were outside that commit.
This later branch tidy tracks the handoff and selected public source copies;
the old publication selection and recorded source hashes remain unchanged.

The top-level [RESULTS.md](RESULTS.md) is the older October 25 snapshot.
Use [final-result-01/RESULTS.md](final-result-01/RESULTS.md) for the completed
October 27 rehearsal. Runtime JSON, raw logs, wallet material, recovery archives,
build caches and unreviewed historical files remain locally retained. Their
local Git exclusions are not a declaration that their contents may be published.
