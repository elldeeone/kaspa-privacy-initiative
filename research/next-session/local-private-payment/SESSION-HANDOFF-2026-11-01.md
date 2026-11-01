# Session handoff — 2026-11-01

Status: **OWNER-PAUSED.** Do not resume MPC/private-construction experiments,
W1 integration, capture-framework work, Testnet trials, or architecture
implementation without a new explicit owner instruction. The pointers below
are for a fresh assessment, not authorization to begin it.

## Final checkpoint

- Checkout: `/home/luke/projects/kpi-intensive-2026-10-22/continuation`.
- Branch: `research/shielded-kas-feasibility`.
- Bounded privacy result: commit
  `c41e733e88c0e1b60cf6113b2ac90728fe6c57f6`.
- This handoff and the remaining publishable WIP are in the final checkpoint
  commit on the same branch; use `git log -1` for its immutable ID.
- No new privacy experiment, architecture work, Testnet action, broadcast, or
  private-evidence publication was performed during wrap-up.

## Actually demonstrated

Commit `c41e733e` executed one fresh bounded three-owner ADR-0065 construction
against this named linkage attack:

```text
owner -> input NF/CV -> that owner's two output tuples -> Spend-proof slot
```

| Observer | Complete map candidates |
|---|---:|
| Leaking offline-W1 construction root | 1 |
| ADR-0065 coordinator/public view | 540 |
| Coordinator plus owner 0's legitimate wallet knowledge | 6 |

Owner 0's legitimate view included its input, outputs, proof, one-party MPC
state and decrypted receipts, including one sender-identified inbound payment.
It still did not uniquely recover the complete honest-owner map.

The same run recorded two genuine MASCOT phases, zero host-controller reads of
owner inputs, three verified Spend proofs, six verified Output proofs, an exact
NF/CV authorization bijection, an independent Arkworks pairing check,
public-state/native-effects/global-balance checks, and genuine CPU guest
execution. These are bounded implementation observations, not a cryptographic
audit or production-security proof.

This was not filtered-artifact privacy: the live coordinator processes received
only common mixed projections and never received the owner-labelled map. The
trusted post-run scorer used owner truth only after the observations existed and
emitted counts and hashes rather than the map.

Detailed public observation:
`research/next-session/local-private-payment/private-batch-2026-10-28/THREE-OWNER-CONSTRUCTOR-PRIVACY-OBSERVATION-2026-11-01.md`.

## ADR-0074/W1 remains unfixed

The current W1 constructor still learns the plaintext map before any retained
artifact can be filtered:

1. `poc/local-private-payment/private_batch_trial/offline_w1_components.py:448-461`
   holds an owner, its input and its two plaintext outputs together.
2. Lines 484-504 serialize an already-known map.
3. Lines 726-739 recombine all owner records and ordering.

Withholding `joint-ordering.json`, `w0-selection.json`, or owner records cannot
provide constructor privacy because the constructor already knew the map.

The registered path is still unavailable:

- `KPI_REGISTERED_FINANCIAL_CONFIGURED` remains `0`;
- `selected_registered_financial_main()` is absent;
- the proposed single-use `SelectedRelationAdmissionAuthority` is absent;
- its required live selection, model, source-closure, graph, matrices, mapping,
  trace, layout, owner-column, runtime, context and failure-epoch bindings are
  therefore absent.

ADR-0074 restricted intents bind each NF to two exact outputs. A shuffle-only
adaptation is unsound; that correspondence must be checked inside the
secret-shared aggregate relation. The ADR-0065 result does not repair or
validate the ADR-0074 one-aggregate-proof path.

## Claim limits

The checkpoint does not establish protection from the trusted host/root
administrator; privacy against two colluding wallets or all-server collusion;
resistance to changed-cohort abort/retry intersection; endpoint, timing, amount
or global-network anonymity; proof of the assumed one-corrupt-party MASCOT
privacy; an ADR-0074 aggregate proof; funding, broadcast, Testnet or chain
acceptance; cryptographic audit; production safety; or a preferred architecture.

## Unfinished work preserved in the checkpoint

The pre-handoff dirty snapshot contained 58 source/test/patch paths: 46 modified
and 12 new. The publishable subset is preserved as explicitly unqualified WIP:

1. P1 MAC-check and SoftSpoken random-tape state capture, including a new
   hash-pinned MAC-check patch and offline controls.
2. Registered selected-producer activation, run binding and persistent
   fresh-trial controls.
3. C1 contact-value authority and registered plan-route bridge/minters.
4. Frozen-W1 Bubblewrap build/run wrappers and tests.
5. P1 corrupt-state capsules, fresh-preparation authority, two-round and abort
   manifests, prelaunch compiler/policy controls and owner-score lineage.

These sources do not establish that the registered producer, W1 proof path,
corrupt-view capture, or privacy qualification is complete.

One modified vendor patch remains deliberately uncommitted:
`poc/local-private-payment/mpc-prover/vendor-patches/mp-spdz-p1-ondemand-ot-state-v1.patch`.
Its working-tree SHA-256 changed from the still-pinned value and exact
`patch --fuzz=0` application fails against the pinned upstream source. It is
retained locally as rejected/incomplete WIP; publishing it would break the
existing source and postimage bindings.

## Bounded wrap-up checks

No new research run was opened. Offline source/control checks reported:

- bounded constructor scorer: 5/5;
- C1/contact/W1 inert controls: 139 tests;
- privacy capsule/manifest/prelaunch controls: 40 tests and 35 subtests, plus
  the owner-lineage sanitizer at 7/7;
- financial/P1 controls: 39 tests plus one strict syntax compile;
- the new pinned MAC patch: exact apply/postimage and 5/5 integration tests;
- SoftSpoken hook scaffolding: 20/20 normal and 20/20 sanitized modes.

The excluded on-demand-OT patch retains its negative result: five of nine
targeted controls fail, including exact hash/application checks. The privacy
controls are host-only WIP; one test needs the ignored local MP-SPDZ fixture,
some negative compile probes can false-pass on unrelated compiler failures, and
the owner-lineage change removes the earlier live C++ receiver fault matrix.
These passes do not establish MPC privacy, value conservation, Testnet
acceptance, or a production binding.

`git diff --cached --check` reports six whitespace warnings solely because the
new unified patch represents blank context lines as a single patch-prefix
space. Excluding that exact hash-pinned patch, the staged diff check passes.

## Excluded evidence retained locally

Private, raw and generated evidence remains unpublished under ignored or
external runtime roots, including:

- `.local/private-batch-offline-w1-components-20261029-01/`;
- `.local/checkpoint-2026-11-01/`;
- `.local/wrapup-2026-10-27/`;
- `/var/tmp/kpi-owner-private-lifecycle-01/private/`;
- `/var/tmp/kpi-sender-private-lifecycle-01/`;
- `/var/tmp/kpi-four-wallet-*/`.

These roots retain owner-private streams, wallet/controller state, MPC/runtime
state, raw observations, generated artifacts and checkpoint receipts. Do not
publish wallet material, Originals, private truth, TLS/player/MAC keys, proving
keys, private diagnostics, or raw receipts. Ignored build/cache roots and all
paths in `.git/info/exclude` also remain excluded. No evidence was deleted or
moved during wrap-up.

## Neutral starting point for a fresh architecture assessment

Compare, without assuming the outcome:

1. wallet-local native-KAS construction;
2. MPC-based construction;
3. a hybrid with wallet-local authorization and MPC aggregation/mixing.

Start from:

- `SECURITY-INVARIANTS.md` and `docs/shielded-kas-next.md`;
- wallet-local: ADR-0066, RFC-0029, and `docs/checkpoints/2026-10-27.md`;
- MPC admission: ADR-0065, RFC-0028, and the `c41e733e` observation;
- aggregate MPC: ADR-0074, RFC-0030,
  `poc/local-private-payment/mpc-prover/financial/REGISTERED-RELATION-ADMISSION-BLOCKER.md`,
  and the retained-W1 observation;
- `research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md`;
- `research/next-session/sender-private-lifecycle/review/RETRY-PRIVACY-OPTIONS.md`.

Use the same workload, observer model and named attacks across candidates.
Compare authorization, conservation, spentness, recovery, permissionless exits,
constructor visibility, public grouping, retry intersection, collusion, host
trust, network metadata, liveness, proving cost and operational dependencies.
Keep source review, local execution, privacy measurement and Testnet acceptance
as separate evidence levels.
