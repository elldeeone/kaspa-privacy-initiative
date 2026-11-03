# Compact-pool privacy audit

**Stage 2 result: audit complete; the candidate needs a different normal
withdrawal policy.** A chain-only observer identifies the transaction that
created Bob's withdrawn note in both retained H6 runs. Waiting through two or
100 additional payments does not hide that source when the old proof is reused.
This does not identify his exact commitment, private owner key or real identity.

Keep reusable proofs for independent exits. Test fresh authorization against a
recent anchor as the normal privacy path before expanding wallet features.
An abstract small-trace control increases compatible source transactions from
one to three, including after complete drain. That selects a useful next test;
it is not an accepted fresh-proof transaction or measured real-world anonymity.

Recorded 2026-10-19, baseline `af9bae8`. This is offline reanalysis of earlier
synthetic TN10 experiments, not new network traffic. **New transactions: 0;
new fees: 0 sompi.** [Audit specification](PRIVACY-AUDIT-SPEC.md),
[primary-source comparison](../../research/compact-privacy-source-review-2026-10-19.md),
[decision](../../docs/adr/0021-separate-exit-fallback-and-privacy-policy.md).

## Exact observer information

The observer receives only transaction bodies and retained accepted block-header
fields projected from the earlier chain receipts. It derives pool order from
reserve ancestry. The input includes every serialized transaction field: native
inputs/outpoints, output amounts/scripts, signature scripts, payload, version,
lock time, subnetwork, gas and mass metadata. Its attacks use the pool's order,
not local RPC arrival timestamps. A global chain observer can also inspect earlier
funding ancestry and later spends of payouts; this minimal attack needs neither.

| Chain field | Implemented encoding and implication |
| --- | --- |
| Shared reserve | One native input; output 0 continues the reserve until terminal exit. Initial funding amount, funding inputs/change, pool lineage, exit payouts and destination scripts are public. Native fee is input value minus outputs. |
| Signature script | 12,421 bytes: pushes a 128-byte proof and 12,288-byte redeem script. Redeem bytes 1–32 hold domain; bytes 36–140 hold compact state. State is version 4, u32 commitment/spend counts, and three 32-byte roots. The immutable suffix contains covenant/verifier rules. |
| Payload | 3,892 bytes: magic at 0–7, authorization at 8–272, ciphertexts at 273–642, successor state at 643–747, public witnesses at 748–3891. Transfers and exits are distinguishable. |
| Authorization | Relative offsets: domain 8–39; historical count 40–43; root 44–75; nullifier 76–107; two output commitments 108–171; mode 172; payout 173–180; exact fee 181–188; payout script 189–224; bootstrap value 225–232; ciphertext digest 233–264. Hash halves form the proof's public inputs. |
| Public witnesses | Historical-root path; nullifier predecessor index, leaf and path; new-nullifier append path; two commitment append paths; history append path. All paths have 16 siblings. Exit-only unused append paths are zero. |
| Ciphertexts | Two fixed 185-byte sealed boxes for a transfer; zero padding for full exit. Public bytes do not include decrypted owners, note values, note randomness or private membership paths. |

Sources: [format/settlement](src/compact/mod.rs), [private constraints](src/compact/circuit.rs),
[native covenant](src/compact/covenant.rs), [trees](src/compact/tree.rs),
[note encryption and payout keys](src/protocol.rs).
All byte ranges above are zero-based and inclusive.

The public predecessor index locates a **nullifier-tree leaf**, not the consumed
note's position. The positioned nullifier includes the private note position
under a secret HMAC key; the observer cannot simply read that position from it.
Commitment positions and creation transactions are public because commitments
append in pairs. Exact duplicate commitment bytes at different funded positions
must remain separate candidates. No address-book/owner list is provided.

The observer knows the circuit's one-input/two-positive-output transfer rule,
60,000,000-sompi note floor, integer bounds, full-note exits and conservation.
Therefore every full withdrawal reveals its consumed value as `payout + fee`.
Fresh recipient scripts do not hide their public values or pool ancestry.

Assumptions: accepted valid transitions, intended covenant, sound/uncompromised
experimental setup, hiding commitments/zero-knowledge proofs, and authentic
retained history. The parser checks framing, ancestry, anchors, script continuity
and accounting; it is not another consensus/proof verifier. Candidate sets are
possibilities under the modeled public constraints, not demonstrated alternate
openings of the actual cryptographic commitments or anonymity guarantees.

RPC queries, IP addresses, broadcast origin, archive requests, private wallet
reports and experiment labels are excluded. Ordinary RPC use in H7 exposed
connection metadata; that remains a separate unmeasured observer surface.

## The counterexample

1. The first reserve state contains one note. Its first transfer must spend it
   and creates positions 1 and 2. Both positions have the same source transaction.
2. Bob's later withdrawal names historical count 3. Position 0 is already spent;
   positions created by subsequent payments were never in this anchor.
3. Positions 1 and 2 remain possible under the public constraints. Both point to
   the first transfer. The source transaction is therefore uniquely identified.

No private amount, wallet label or guessed timing distribution is needed. A
single-spend matching attack respects all observed spends jointly; it does not
mistake an already forced-spent note for a live candidate. The proof's anchor
cannot be changed by public rebasing because its digest is bound by the proof.

## Results and coverage

The observer ran without home-directory access, wallet/truth files or network
access. All three input projections and output/source hashes are recorded in
[provenance](evidence/2026-10-19-privacy-audit/provenance.json). Scoring happened
separately afterward, using the already documented first-transfer source of the
two H6 target exits. These are selected exploratory traces, not blind trials or
independent samples from a real-user population.

| Retained trace | Native transactions | Withdrawals | Unique source predictions / coverage | Target/source candidates |
| --- | ---: | ---: | --- | --- |
| H6 two-payment rehearsal | 8 | 4 | 1/4; 3 abstentions | First exit: 1 source, 2 note positions |
| H6 100-payment trial | 204 | 102 | 1/102; 101 abstentions | First exit: 1 source, 2 note positions |
| H7 three-wallet recovery | 6 | 3 | 0/3; 3 abstentions | Each exit: 2 sources, 4 note positions |

These counts hold both at each withdrawal's observation horizon and after its
trace drains. The two selected singleton predictions match documented truth:
2/2 at each horizon. This is **not** a 100% trace-wide success rate. The audit
does not score unknown owner identities, derive precision for arbitrary traffic,
or treat abstentions as private withdrawals. All 109 full exits expose their
consumed amounts. Deposit-ancestor inference is trivial within each trace: one
initial deposit, not independently funded users in a shared pool.

Joint integer conservation/floor/spentness analysis confirms the same source and
note sets for the small H6 rehearsal and H7 trace. We do not run the large trace's
joint-value solver: the old-anchor certificate already decides the audit gate.
Its other exits' 100-source/200-position matching sets are upper bounds before
amount analysis, not 100 plausible users or a privacy result.

The report includes source-order recency tie sets and a uniform-over-compatible-
sources reference. For the selected singleton targets, both predict that same
source with certainty under the model. The reference is a declared equal-weight
baseline, not an inferred distribution over histories. Full-coverage timing/
amount-attack accuracy and confidence intervals are unmeasured because no
population workload comparison was run.

## What the policy comparison can and cannot tell us

| Candidate policy | Audit decision | Delay, costs and changes |
| --- | --- | --- |
| Bounded randomized delay with unchanged authorization | Reject as the remedy for this counterexample. The historical input universe is unchanged; later information can narrow it further. Timing heuristics among several eligible sources could still change in other workloads. | No extra native transaction inherent in waiting, but added delay cannot remove this source certificate. No delay distribution or fee-rate stability is empirically evaluated here. |
| Equal public payouts with private change | Do not port it merely to repair this link. It cannot enlarge an already fixed historical universe by itself. | Absent from compact state. Requires changed private relation, authorization/covenant commitment updates, setup and wallet tests. Eventual change exits add costs and may add links. Modified fees and efficacy are unknown; H2's different layout is not a compact fee estimate. |

The plan's old-anchor stop condition is met. The 25% relative inference reduction,
25% fee increase and 30-minute p95 delay thresholds remain **untested**, not passed
or numerically refuted. The singleton/two low-activity regimes and independent/
shared-funding workload matrix were conditional on getting beyond this audit.
Current compact state cannot accept later independent deposits. A simulator that
pretends otherwise would test a proposed protocol, not the implemented pool.
No funded privacy trial or traffic simulator was justified by this result.

## Next design decision and cost

Changing only the **abstract** first H6 rehearsal exit's eligible historical
count from 3 to the then-current 7 gives three source transactions and six note
positions under the small joint-value model, including after all payouts. The
unchanged recorded proof would reject that change; no replacement transaction
was produced. H7 is a useful actual-layout control: its newly created proofs
already use count 5 and leave two source transactions for each exit. It is a
different ledger, so its scores are not a paired mitigation experiment.

The smallest next test is a paired offline comparison of an old fallback proof
and a genuinely generated fresh authorization for the same note/payout, keeping
the ledger and observation horizon fixed. Select several recent anchors, check
the actual serialized transactions, and apply joint amount/history constraints
through eventual drain. Keep the fallback independently usable but do not
publish both authorizations: they share the note's nullifier and would reveal
the old membership restriction. Attempting both must never permit two payouts.
No operator, new token or consensus change is needed for this test.

Replacing the chosen exit proof does not inherently add a native transaction or
increase its fixed encoding size. At the previously measured 100 sompi/mass rate,
the existing exit fee is **21,729,600 sompi (0.217296 tKAS)**. Additional native fee
for choosing a new anchor is expected to be zero at the same transaction shape
and rate; this is an estimate, not a new relay measurement. H6 warm private
proofs took about 9.4–9.9 seconds; H7 restore proofs took about 12.2–12.4 seconds
plus roughly 105 seconds of cold parameter loading. Actual fresh-proof work
must be measured. No new proving work was performed in this audit.

Stop the follow-on if fresh proofs still leave a unique source under joint
constraints, if gains need invented background users, or if proof work defeats
the intended use case. A fresh anchor removes one bound; it does not add real
participants, hide full-exit values, or prove useful anonymity. Keep Stage 3–4
expansion behind this privacy redesign decision.

## Reproduction and review

Use Python with `z3-solver==4.15.4.0` and Linux `bubblewrap`. The existing observer
environment reports Z3 4.15.4. From the repository root:

```sh
/path/to/venv/bin/python -m unittest discover -s poc/shared-pool -p test_compact_observer.py -v
python3 poc/shared-pool/run-privacy-audit.py /tmp/new-privacy-audit --venv /path/to/venv
```

The output directory must be new. Inputs are reconstructed from retained evidence;
no RPC call, parameter download or wallet secret is needed. Twelve control tests
pass, including exhaustive matching against brute force for 340 small systems
(1,252 target queries), malformed chain projections, future-note exclusion,
conservation, multiple feasible histories and old/fresh-anchor controls.
[Second-pass review](PRIVACY-REVIEW.md). These checks support the audit software,
not cryptographic correctness, mainnet readiness or real-world anonymity.
