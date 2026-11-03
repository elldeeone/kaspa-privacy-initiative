# Prior research knowledge

Use this guide before repeating an experiment or extending a researched component.
The current research branch contains the findings and original document text from
all audited histories. Reading this library requires no branch switch, private
worktree, audit directory or GitHub access.

## Start with the task

| Your task | Read first | What it prevents |
| --- | --- | --- |
| Choose an architecture or settlement boundary | [Architecture](architecture.md) | Treating a feasible component as an accepted production system. |
| Evaluate sender, recipient or amount privacy | [Privacy](privacy.md) and [current corrections](../RESEARCH-LESSONS.md) | Reusing invalid scores or repeating rejected cashout policies. |
| Change proofs, encodings, batching or parameter loading | [Proofs](proofs.md) | Reusing incompatible keys/claims or confusing partial and complete proofs. |
| Build scanning, backups, recovery or exits | [Recovery](recovery.md) | Assuming a seed/root replaces missing history or public proving parameters. |
| Quote cost, throughput or proving performance | [Costs](costs.md) | Combining incompatible profiles or estimated and actually paid fees. |
| Run a trial, maintain tooling or replay evidence | [Operations](operations.md) | Losing exact integer semantics, error isolation or historical source bindings. |
| Reuse an old component | [Reuse decisions](reuse.md) | Importing a whole historical runtime to obtain one useful mechanism. |
| Find unfinished reviews and proposals | [Unfinished work](unfinished.md) | Losing important review corrections or mistaking a proposal for execution. |

[Project status](../PROJECT-STATUS.md) governs current conclusions. Historical
PASS/Accepted labels are scoped to the source profile, not to today's complete
requirements. Read later corrections before reusing an older result. Historical
agent instructions and commands are frozen data; current AGENTS.md and security
invariants govern new work.

## Find the original text

[Source index](sources.md): every captured original document path and revision.
[Commit index](commits.md): every captured commit, with complete messages and
changed paths in [the ledger](commits.json).
[Coverage](coverage.md): every original local/fork/upstream branch and upstream
pull history, including aliases and recovered commits.

```sh
python3 scripts/research_knowledge.py find WORKING-BALANCE
python3 scripts/research_knowledge.py show 4d54dc02 research/next-session/local-private-payment/SESSION-HANDOFF-2026-11-01.md
rg -n --glob '*.txt' 'history_leaf' docs/research-knowledge/documents
python3 scripts/research_knowledge.py check
```

The snapshot covers 363 original audited commits plus six consolidation commits,
2,326 distinct committed Markdown/rst revisions and 15 selected unfinished notes:
2,341 exact text copies, with Git blob identities and SHA-256 checks. The
manifest records source paths and commit provenance. It retains superseded
versions so later changes to a document do not erase an earlier lesson.

Source code was not bulk-merged. Code-only commits retain their full messages and
changed-path metadata; the original implementation history remains preserved by
the archive tags and self-contained history bundle. Raw private evidence,
wallets, proving parameters, binaries and other unfinished drafts stay private.
This library preserves knowledge, not a claim that every old runtime is compatible.

## Carry new knowledge forward

Record new findings on the active branch, alongside the relevant current
component. Update the appropriate topic, reuse decision and current correction
when a new result changes an interpretation. Preserve the earlier result and
its scope. Add a new frozen snapshot when widening historical coverage; this
manifest's 369-commit boundary is explicit and does not automatically include
future commits. A document hash proves copied bytes, not the truth of its claims.
