# Research preservation checkpoint — 3 November 2026

The repository consolidation preserves the original experiments before retiring
their active branch names. The machine-readable
[receipt](research-history/2026-11-03.json) records all 24 original branch tips
and their annotated `archive/2026-11-03/` tags.

## Verified preservation

- The original self-contained Git bundle preserves 361 reachable audited
  commits, including all 42 upstream pull-request histories. Final coverage
  checking corrected the initial claim of 363: its reference list omitted two
  otherwise unreachable commits retained in the audit mirror. The consolidated
  history archive includes explicit references for both recovered commits,
  all 363 original audited commits and the consolidation commits. Its private
  completion receipt records the independently restored total and bundle hash.
- All 149 unmatched files outside the identified build-output directory were
  copied into a private local archive. Every copied size and SHA-256 was checked.
  Their combined size is 7,741,505,192 bytes.
- Existing tracked changes are retained as three worktree patches covering five
  paths, including the deliberately rejected MPC vendor patch.
- Ignored and external runtime data stays retained. Wallets, private truth,
  proving parameters, raw diagnostics and runtime state are outside this Git
  selection. Original failed experiments and corrected reports remain intact.

The archive is on the same machine. This is local preservation, not an
independent off-host backup or a claim that historical services remain available.
The private manifest and its location are kept outside Git; the public receipt
binds its SHA-256 without disclosing the file inventory.

## Restoring history

Use `git show archive/2026-11-03/BRANCH:path/to/file` for a historical file or
create a new explicitly selected checkout from that tag. Original branch names
and exact commit IDs are listed in the receipt. The history bundle can restore
the audited commits without the original repository object store.

Restoring a source snapshot does not select its domain, keys, proving artifacts
or runtime for a new experiment. Check its dated handoff and qualifications.
The paused feasibility line remains a historical reference, with its rejected
patch separate from the committed source.

This checkpoint starts no proof, trial, broadcast, runtime deployment or MPC run.
