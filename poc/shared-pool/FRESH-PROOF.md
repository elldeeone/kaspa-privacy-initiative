# Fresh proof with a private exit fallback

Passed offline, 2026-10-19. A genuinely new proof removed the old anchor's
unique source-transaction link in both small activity fixtures. The old proof
still settled independently before the note was spent; either winner prevented
the other from spending. All claims drained in both alternative histories.
This supports the mechanism, not a usable-privacy or Stage 2 population result.
No transaction was broadcast and no tKAS was spent.

The [specification](FRESH-PROOF-SPEC.md) was hashed before proving. Baseline
`49e526285587c4fb39ccbfa6de97ddb97c0032cc`; branch `shared-pool-four-wallet`.
The circuit, covenant, setup and L1 rules are unchanged.
[Source review](../../research/compact-privacy-source-review-2026-10-19.md),
[decision](../../docs/adr/0021-separate-exit-fallback-and-privacy-policy.md),
[adversarial self-review](FRESH-PROOF-REVIEW.md).

## What was compared

One synthetic 10-tKAS reserve per fixture, three wallet key sets, and one initial
deposit. Alice pays Bob 4 tKAS, and Bob prepares an old exit at commitment count
three. Alice then makes zero, two or four payments from her change to Carol.
Bob creates a fresh exit proof against the latest fixture anchor: count 3, 7
or 11. Both authorizations bind the same note, nullifier, exact recipient script,
3.782704-tKAS payout and 21,729,600-sompi fee. Only anchor count/root may differ;
the singleton has the same authorization and a newly randomized proof.

Both alternative histories use identical preceding transaction bytes, private
payment values, target destination, fee and withdrawal order. After Bob exits,
Carol's notes exit in creation order and Alice drains her change. Both histories
reconcile exactly: payouts plus pool fees equal the initial reserve, and every
created claim is spent. They are exclusive synthetic histories, not two accepted
chains. There are 4/8/12 serialized transactions per history, including funding,
and 24 genuinely generated proofs overall. Common-prefix and cleanup proofs
are reused where their statements are identical.

## Chain-only result

An isolated observer sees one history's serialized transactions and declared
synthetic timestamps. It receives no other history, fallback bundle, keys,
plaintext notes, workload seeds, owner labels or truth file. It decodes the
public anchor, nullifiers, payout/fee, scripts, outputs and reserve ancestry,
then applies anchor/single-spend matching and joint integer value/floor
constraints. A separate scorer checks its predictions against private truth.
The model assumes commitments/proofs/ciphertexts hide their private inputs;
this experiment does not establish that cryptographic assumption.

| Fixture | Bob's old → fresh source candidates | Bob's old → fresh note positions | All-exit unique-source coverage, old → fresh | Recency top-1 correct, old → fresh |
| --- | ---: | ---: | ---: | ---: |
| No intervening payment | 1 → 1 | 2 → 2 | 2/2 → 2/2 | 2/2 → 2/2 |
| Two intervening payments | 1 → 3 | 2 → 6 | 1/4 → 0/4 | 3/4 → 2/4 |
| Four intervening payments | 1 → 5 | 2 → 10 | 1/6 → 0/6 | 3/6 → 2/6 |

These joint-value results are unchanged between each withdrawal's observation
prefix and complete drainage. Unique-source predictions were correct whenever
made; an ambiguous set is an abstention, not demonstrated privacy. Fresh-arm
remaining exits also retain 3/5 sources in the activity fixtures. The observer
output records every exit, both constraint models and both horizons.

The full-coverage recency baseline chooses the latest feasible source transaction;
there are no source-time ties here. The declared clocks therefore give the same
ordering as transaction recency. Under an explicitly uniform candidate prior,
mean expected success is 1 → 1, 0.625 → 1/3 and 0.375 → 1/5. These are reference
priors, not fitted posterior probabilities. No confidence interval or population
improvement is estimated from three designed ledgers. Bob's target was deliberately
the earliest received note, so this is not a representative recency-attack sample.

Every full withdrawal still reveals its consumed value as payout plus fee.
Every fixture still has one visible deposit ancestor. Source transactions and
note positions are not people or independent users. The published experiment
description supplies information beyond the isolated observer's input; the
result does not assert privacy against someone who knows that description,
recipient information, RPC traffic, network metadata or unpublished bundles.

## Exit and hostile controls

Six isolated rebuilds (old/fresh in each fixture) succeeded with only the selected
bundle, current public state/UTXO and verification key. Wallet keys, proving
parameters and network access were absent. Rebuilt proof and authorization bytes
were unchanged, and the resulting transaction exactly matched the corresponding
history. Fresh proving was not required to use the old fallback.

Both winner orders rejected the loser in every fixture. The normal builder
rejected its already-spent nullifier. A hostile transaction then retained the
genuine losing proof, consumed the winner's current successor, and supplied
recomputed duplicate-insertion paths/roots; native validation rejected it.
Exact replay of the old reserve outpoint was separately rejected by the synthetic
UTXO ledger. This separates current spentness from merely trying a missing input.
The singleton duplicate additionally has a premature terminal-output inconsistency;
the two larger fixtures avoid that confound. This is not a live simultaneous race.

All 34 native negative controls rejected: six duplicate attempts, wrong
pool/root/fee/payout/recipient, malformed nullifier paths/proofs, stale paths,
and four swapped old/new proof-authorization pairs. Swapping the singleton's
identical authorization is not an invalid case and was not counted. All 48
serialized transaction instances across the exclusive histories passed separate
native Full validation, relay-policy checks and script metering after JSON
parsing with explicit synthetic UTXO contexts. These do not establish mempool
admission, canonical state, finality or a second independent implementation.

## Cost and delay

| Measurement | Result |
| --- | ---: |
| Additional native transactions / fees for fresh versus old | 0 / 0 sompi |
| Bob's full-exit fee, either authorization | 21,729,600 sompi = 0.217296 tKAS |
| Bob's estimated serialized size / mining mass | 16,566 bytes / 217,296 |
| Modeled total fee per history, zero/two/four intervening payments | 0.653525 / 1.521885 / 2.390245 tKAS |
| Fresh target proof work, zero/two/four payments | 9.589 / 9.514 / 9.574 seconds |
| All 24 proof times, range / median | 9.388–9.897 / 9.6195 seconds |
| Cold parameter deserialization, once | 100.414 seconds |
| Public-only rebuilds, old / fresh range | 8.345–8.614 / 7.567–7.869 ms |
| Complete proof-generation harness wall time | 5 minutes 32.25 seconds |
| Actual on-chain expenditure | 0 tKAS |

Amounts/fees come from native transaction calculations at 100 sompi/mass, not a
current network quote. CPU: AMD Ryzen 7 5800X, four Rayon threads. Proof timing
includes Groth16 generation, local verification and serialization, but excludes
parameter loading, construction of its private inputs, RPC and confirmation.
Public rebuild timing covers local settlement/native validation/policy, excluding
process startup and file input. The outer timer measured bubblewrap rather than
the prover's peak memory; the exported prover-memory value is explicitly null.
The reusable launcher now places the resource timer inside the sandbox for
future runs. No repeat proving was needed to correct this reporting boundary.

Both histories use the same synthetic exit times: 5, 25 and 240 minutes after
Bob receives. Added scheduled waiting is zero; fresh proving adds the local work
above. This does not establish a p95 delay or include the cost of waiting for
real independent activity. The script does not sleep for simulated minutes.

## Evidence and reproduction

[Sanitized evidence](evidence/2026-10-19-fresh-proof/README.md) contains only the
fresh histories, observer results, aggregate comparisons, native receipts,
isolation records and hashes. Both pending bundles, the old histories, rejected
transaction material, raw errors, wallet files and private truth stay outside
Git in owner-readable directories; fallback files have mode 0600. Export scanned
33 known wallet/initial-note secret values, three unused old proofs and two
distinct old authorizations. Six actual-material injection controls and six
export/scoring unit tests passed, along with the 12 existing observer controls.

In the singleton, old/fresh authorization bytes necessarily match. Its unused
old proof is still excluded. In the two activity fixtures neither the unused
old proof nor its distinct authorization is published. Keeping that unused
authorization private is part of the proposed policy: disclosure would link its
shared nullifier to the fresh exit and restore the older restriction. Once either
proof spends, the retained fallback cannot withdraw the spent note again.

Use Rust 1.95.0, the locked dependencies and the existing compact parameters, whose
VK SHA256 is `79ed99da1d7b586887edf13e1d7404f5692479b0cb759ab8701a039eb340d1b4`.
The tested native SDK remains pinned to
`01b532e8b553523216471682649693af92f0fd16`. No new setup was created.

```sh
CARGO_TARGET_DIR=/build cargo +1.95.0 build --release --locked --manifest-path poc/shared-pool/Cargo.toml --bin kpi-fresh-proof --bin kpi-compact
python3 poc/shared-pool/fresh-proof.py run /private/new-run --binary /build/release/kpi-fresh-proof --validator /build/release/kpi-compact --params /private/compact-params --venv /tools/observer-venv
python3 poc/shared-pool/fresh-proof.py export /private/new-run --destination /public/new-export
/tools/observer-venv/bin/python poc/shared-pool/test_compact_observer.py
python3 poc/shared-pool/test_fresh_proof.py
```

`/private/new-run` must be new and outside the repository. The observer environment
needs `z3-solver==4.15.4.0`; bubblewrap and GNU time are also required. A run uses
fresh secret randomness, so its bytes differ while the declared workload is
repeated. Existing private results can be analyzed with the `analyze` command,
without proof generation; an existing analysis directory is never overwritten.
One public fresh history can also be reanalyzed with `fresh_observer.py` without
any wallet material. The old-side comparison deliberately requires its private
artifacts or a new run; public reproducibility does not justify disclosing the
unused fallback.

## Decision

Retain fresh authorization as the candidate normal path when useful later
activity exists, and retain the private old authorization for independent exit.
This implements the bounded mechanism selected in ADR-0021 without a protocol
change. It does not choose an optimal anchor age or withdrawal policy.

Stage 2 remains open. Its 25% inference/25% fee/30-minute screening conditions
require matched independent ledgers and explicit traffic assumptions; none is
passed by these fixtures. Independent later deposits and partial withdrawals
remain missing compact capabilities. Keep full-exit amount leakage, useful
independent activity, cold proving, setup trust, public-data availability, fee
repricing and independent review unresolved. No TN10 run follows automatically.
