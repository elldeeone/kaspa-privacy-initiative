# Bounded 32-role comparison: no measured privacy advantage over rerandomization

One frozen synthetic batch completed all **72 cases**: eight independent demand
ledgers, three policies and three repriced fee rates. Every case independently
passed ownership, conservation, fee, urgent-exit and complete-drainage checks.
This is an arithmetic model with genuine note/receipt crypto, **no Groth16 proofs
or accepted native transactions**. It does not qualify financial privacy.

The same original 64 payments, 32 exact net cash requests, two urgent full exits
and final drainage order were used in each paired ledger. Unsupported exact
payouts remain failures. Public funding-owner associations, timing, amounts,
fees, ciphertexts, nullifiers, note openings and re-entry ancestry remained
observer inputs. Private economic labels were withheld until all predictions
were sealed. All three policies used corrected sealed padding; the historical
raw-padding failure remains [separate evidence](PADDING-RESULTS.md).

At rate100, across the eight ledgers:

| Measured diagnostic | Direct REVEAL | P0 then REVEAL | Private EXIT |
| --- | ---: | ---: | ---: |
| C: primary payment amounts directly opened by final drainage | 203 / 290 | 0 / 290 | 0 / 290 |
| Exact requested net cash payouts completed | 0 / 256 | 256 / 256 | 256 / 256 |
| Urgent whole-owner exits completed | 16 / 16 | 16 / 16 | 16 / 16 |
| Final positive liabilities remaining | 0 | 0 | 0 |
| Total modeled fees, KAS | 149.317714 | 341.732570 | 298.562946 |

The direct policy safely drains but cannot provide these exact partial net
requests from existing whole notes. Its lower fees are therefore not a cost
comparison for equivalent cash-request functionality. Both other policies meet
the same requests; private EXIT costs about12.63% less in this workload. Every
per-user fee, preparation, urgent exit, re-entry and tail is retained. These
totals are diagnostics, not lifecycle cost qualification or real native fees.

The important negative finding is that **the tested attacks do not establish a
privacy improvement over old P0 rerandomization**. Both policies avoid directly
opening those290 primary payment values to C through drainage. This is not a
proof of ambiguity, cryptographic indistinguishability or resistance to stronger
global amount/ownership attacks. All C/C+P/C+P+A, horizons, four fixed variants,
selective coverages, denominators and clustered bounds are in the machine result.
The exact-opening diagnostic is also0/290 for the two policies at200/500.

The fixed45-KAS prior hit57/290 within10% in these sampled primary cases. Its
unchanged distribution-level success is21103/100025=21.09772557%, already above
the adopted20% cap. The sampled result does not erase that mathematical failure.
Eight clusters and10,000-comparison bounds cannot qualify the privacy gates;
the result explicitly says privacy_qualification=false and fee_qualification=false.

Fee pressure also remains a privacy problem. Revealing minimum/fee fallbacks
were retained at every horizon: P0-then-REVEAL used2/2/15 at100/200/500;
private EXIT used0/0/7. The60M control confirms that a sole60M input cannot
produce a legal old P0 positive output after fees. A continuing private EXIT
can pay41,000,100 at100 or22,000,200 at200; at500 its fee cannot be funded by
that claim while preserving the10M payout floor. REVEAL is a separate,
privacy-degrading escape, never evidence of private-only recovery success.

## Evidence boundaries and execution

The model's fee dimensions are grounded in the already published
[eight actual-body metric checks](../native/ACTUAL-FEE-PROFILE-01.json), then
recomputed by pinned integer KIP9 arithmetic for each modeled amount context.
Those new contexts are source arithmetic, not repriced signed authorizations.
Separately, the [seven-transaction genuine native lifecycle](../lifecycle/RESULTS.md)
passed supplied-context Full validation with actual fees84,658,300 sompi and
failed the2% target. That is real native execution evidence; this population
model neither extends it to72 native traces nor supplies testnet acceptance.

The [method](POPULATION-METHOD-01.md) and
[revision2 freeze](population-01/PRE-RUN-FREEZE.json) were reviewed before data.
Public controls ran before fresh private seeds were drawn. A source-restricted
trusted host generator had full host filesystem access, with actual Internet
socket denial; only fresh experiment material and curated sources were read.
Observers had separate narrow filesystem/network sandboxes and no truth,
seeds, other configuration or economic target mask. Each prefix response was
sealed before a later prefix was sent; a global barrier preceded separate scoring.
Synthetic role/note truth is published afterward for checking. No root seed,
ownership secret s, native/delivery secret key or proving parameter is published.
Native public keys and each deliberately revealing REVEAL k remain public.

The original batch used176.356s controller wall time. Systemd recorded176.432s
service runtime,630.636s aggregate CPU,268MiB peak memory and zero swap. Live
limits were four CPUs/4GiB/zero swap, with verified AF_INET/AF_INET6 denial.
These measure this model batch, not wallet/reference-device/prover performance.
The service completed inactive/dead with MainPID0. No model work remains running.

Two operational namespace probes established that nested sandboxes fail on this
host. The unexecuted first source/method/freeze and no-data probe receipts remain
preserved. The revised runtime changes no workload, attack or threshold.

## Preserved summary failure and mechanical repair

All72 per-case scores were successfully saved before the original controller's
metadata merge raised `TypeError` for its duplicate `complete` keyword. The
[original summary](population-01/run/RESULT.json),72 failure records and
[original execution receipt](population-01/run/EXECUTION.json) remain unchanged.
They honestly report the packaging failure; they must not be cited as a
successful final summary.

A [separately pinned repair](population-01/AGGREGATION-REPAIR-FREEZE.json),
reviewed before execution, read the same72 sealed score JSON files and invoked
the exact original aggregate function with a nonduplicated metadata merge.
It performed **no generation, attacker evaluation or hidden-truth scoring**.
The [repair receipt](population-01/run/REPAIR-EXECUTION.json) records one original
batch and one aggregation-only postprocess. All original source, barrier and
score hashes remain unchanged. Independent artifact closure checked the source
pins, all288 pre-score barrier pins and all72 score identities without rerunning
any classifier, scorer, crypto operation or aggregation.

Authoritative repaired result:
[REPAIRED-RESULT.json](population-01/run/REPAIRED-RESULT.json), SHA256
`abdf6a256d92913e6d188d610f50dfc536f2317f9adf5d13d0a5394c1156b877`.
Original failed summary SHA256:
`2f84da92bf478a25e6277f7836d5e6a6c68555e66d334eabe861faf2f73eb704`.

The reusable active controller subsequently received the same metadata-merge
fix, with one public mocked-scorer regression. The exact executed controller,
freezes, failed summary and mechanical repair remain unchanged. This
post-experiment code fix performs no generation, attacker run, actual scoring
or aggregation; its receipt and regression output are separately retained.
