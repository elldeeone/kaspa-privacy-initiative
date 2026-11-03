# Matched batch proofs, linkage and recovery

**The cheaper batch now completes with genuine proofs:** 32 useful 10-KAS
payments, 32 independent withdrawals and zero terminal reserve, at complete
supplied-context fees of **1.9486784375%**. All 32 original backups recover their
spent receipts and per-claim payout keys. The first owner actually fetches the
real compact proving key through a fallback after original-source/cache loss.

This fresh instance is unfunded local research. Native Full validation uses
supplied UTXO contexts; it does not establish accepted-chain backing or new
confirmed payouts. The stronger frozen linkage study finished all 96 views;
61 are complete and 35 remain incomplete. The additive public competing-spend
controls are complete. Existing failed privacy measurements,
individual-payment fees and prior testnet instances remain unchanged.

## Complete financial route

The [closed financial record](lifecycle/main-synthetic-01/FINANCIAL-CLOSURE.json)
and [independent economics review](review/NATIVE-ECONOMICS-REVIEW-01.md) cover
one ordinary entry, one wide32 transfer and 32 owner-local compact withdrawals:

| Quantity | Verified result |
| --- | ---: |
| Genuine owner proofs | 33 |
| Exact native Full bodies | 34 |
| Useful payment principal | 32,000,000,000 sompi |
| All entry/transfer/withdrawal fees | 623,577,100 sompi |
| Native payouts including terminal refund | 32,000,149,500 sompi |
| Terminal reserve | 0 sompi |
| Complete fees / useful principal | 1.9486784375% |

Exact conservation is:

```text
42,623,726,600 source
= 10,000,000,000 ordinary change
+ 32,000,149,500 native payouts
+    623,577,100 all fees
+              0 reserve
```

The 149,500-sompi terminal refund, gross fee credits, ordinary change and dummy
outputs do not enlarge useful principal. All 33 actual quote identities were
reproduced from their exact selected bodies/contexts. Private-action compute
budgets remain 1600 throughout; no smaller-budget result is claimed. This fixture has no
separate funding-preparation transaction; a future route that needs one must
include its fees. Final CM cursor 126, delivery count 95 and NF count 67 are below
capacity; full-capacity private-exit liveness remains open.

Each owner runs with one original seed backup, public history, authenticated
compact parameters and read-only selected software. No payer seed, other
backup, amount/issuance map, controller plan or prior private output is mounted.
The final 32 independent closed scans replay all 34 bodies before seed access,
recognize the owner's spent receipt and match its rederived payout key and
amount. This proves the selected local recovery path, not current unspentness
or independent consensus.

## Matched relations and prover performance

| Role | Constraints | Witness variables | FFT domain | Public PK bytes |
| --- | ---: | ---: | ---: | ---: |
| compact2 | 3,284,767 | 3,248,304 | 4,194,304 | 1,307,894,256 |
| wide32 | 7,448,842 | 7,361,092 | 8,388,608 | 2,892,421,872 |

Compact terminal and continuing modes share finalized matrix 98c92c77…; wide
uses be86280d…. Fresh setups reproduce the selected dimensions, source, role
and exact VKs; setup plus serialization/readback takes 18.334s and 44.673s.
Cold known-public owner proofs take approximately 12s compact and 27s wide;
actual selected first owner and wide payment take 13.006s and 28.736s. These are
individual observations, not p95 or wallet-resource qualification. Both setups
exit; randomized development setup honesty and cryptographic soundness are
not established by successful proofs.

The implementation has 28 public/parser/hash controls,14 deliberately invalid
constraint rejections and one intentional SAT/native-owned CMroot boundary.
The latter has a genuine proof that native validation rejects before G16.
Genuine known-public compact continuing, terminal and wide proofs pass native
Full. Their deliberately tiny 1000-sompi fees fail reference-rate relay pricing;
they are interoperability controls, separate from the complete fees above.
Foreign-role/foreign-statement transplants reject at G16; they do not alone
isolate same-note competition. See [prover evidence](prover/RESULTS.md).

The separate [same-note competition controls](lifecycle/competition-01/RESULTS.json)
now close that gap with three additional genuine public proofs and eight native
outcomes. Compact and wide alternatives consume the same two real nullifiers;
a revealing exit rejects after either private alternative. After a successful
revealing exit, a newly generated current-state private proof still verifies
privately, but native validation rejects its authenticated occupied nullifier
at 158,752 units, before G16. Its 31B reserve exceeds the 2B input sum, avoiding a
reserve-shortfall explanation. Two older-proof rebases are separately labeled
stale Auth controls. These are local mutual-exclusion checks, not live network
races, privacy or correctly priced public-canary payments.

The original compact audit spent about 59s in tiny parallel SAT evaluations.
Executing identical checks inside the selected worker pool reduces the full
compact audit to 6.33s, with unchanged matrix and checks. Setup/proving retain 14
workers. The cache-setting probe did not materially help; slow/incomplete
attempts are retained. CPU scheduling improved the implementation, not the
native verification tariff.

## Source-loss recovery and availability

[Actual portability evidence](recovery/actual-portability-01/README.md) covers
the real 1,307,894,256-byte compact PK, full length/hash authentication and
fallback HTTP retrieval with the preferred source stopped, original producer/
cache absent and no mirror filesystem mounted in the retrieval client. The
same first main withdrawal then uses restored material and its original seed;
it is not a second counted proof. The owner authenticates READY before backup
read and has no wide PK mounted.

Separate small-file controls cover substituted/corrupt/missing objects, wrong
external roots/roles, backup aliases before opens, HTTPS/redirect faults and
source/cache loss. These are transport controls, not additional real-owner or
provider-independence results. Recognition needs no PK; spending needs the
exact compact PK. A capsule's own hash selects neither authority nor code and
cannot recreate a missing randomized setup or delivery record.

The [distribution plan](recovery/DISTRIBUTION-PLAN-01.md) specifies exact-hash
chunks, independent HTTPS copies and offline copies. Its optional chunk adapter
now reconstructs both real PKs from fixed 1 GiB chunks: two for compact, three for
wide. The final current-source roundtrips take 23.106s total under 4 CPU/4 GiB/swap 0,
with original source/cache/repo paths absent and independent whole-file
readback. The caller's independently selected complete length/hash remains
authority; neither chunk hashes nor the index can replace it. Existing capsule
schemas, role selection and loader authentication are unchanged.

Review found a real one-shot-iterator bug: an initial exclusion check could
consume the caller's paths, leaving later file-alias checks empty. All four
outer transport APIs now freeze those paths once before reads; 46 current
controls pass, including calibrated no-content-open regressions. Earlier
list-based owner recovery remains valid historical evidence.
[Source supersession](recovery/chunk-transport-01/SOURCE-SUPERSESSION.json)
preserves each old executed preimage and binds the corrected current source;
old manifests and failures were retained.

No release, provider upload or durable independent host was created. Long-term history/parameter
retention, software cold build/distribution and fresh accepted-state
reconciliation remain unresolved availability obligations.

## Rigorous linkage study

The [frozen method](privacy/PLAN-PROPOSED-01.md) compares wide batching and
serial compact payments across 16 paired synthetic ledgers and 96 isolated
observer views. Four independent economic clusters, overlapping/staggered
timing, prefix/full-drain horizons and C/C+1/C+8 participant facts are fixed
before heldout generation. Every prediction must be sealed before any private
truth is scored; timeouts remain UNKNOWN/INCOMPLETE without retries or refits.
All96 predictions were sealed/fsynced before any scoring; all 96 scores and the
aggregate were then produced. There are 61 COMPLETE and 35 INCOMPLETE views,
with no operational failure or OOM. An incomplete view supplies no privacy
metric. The four-cluster family-adjusted bounds cannot qualify the original
thresholds, and identity remains NOT_MODELLED.
All96 view-level compatibility checks over16 modeled ledgers passed. All35 incomplete
views report Z3's exact reason `canceled`; the record does not distinguish
timeout from every possible solver-internal resource cause. Wide has47/48
complete views and compact14/48, with all24 staggered compact views incomplete.
Those are computational coverage counts, not a privacy ranking.

The [public coverage record](privacy/heldout-study-01/COVERAGE-01.json) shows:

- In completed staggered wide public-C views, all64 early exits across the four
  clusters have forced original funding ancestry; this is64/256 exits at full
  drainage. It is ancestry, not human identity.
- With C+1 invoice facts, the fixed same-birth heuristic labels the modeled
  payer role correctly for248/248 other payment outputs in each complete wide
  cell. These repeat the same paired obligations, not extra independent samples.
- Forced honest-economic CM-to-cashout links are zero in complete cells. This
  neither resolves the35 incomplete views nor establishes cryptographic ownership
  ambiguity/anonymity. All-public exact-value counts include forced zero padding;
  they must not be presented as positive-payment amount disclosure rates.
- The fixed45-KAS prior hits55/256 unique requests within10%. The unchanged
  distribution-level failure remains21103/100025 (21.10%), above the20% cap.

The [study report](privacy/heldout-study-01/REPORT-01.md) and13.17MB public archive
retain96 exact observer inputs,96 sealed predictions,96 keyless scores and
their source/barrier inventories. All322 payloads match the finite member list.
Available modeled private material passes a literal scan over26,144 values and
273,320 textual encodings plus raw patterns; unretained sealed-box ephemeral
secrets and arbitrary transformations are outside that scan. Private truth and
keys remain withheld, so public certificate checks do not independently
reconstruct the hidden-truth scoring oracle.

This is a prospective varied-positive-demand arithmetic model, separate from
the actual uniform32 financial demonstration. Public-current uniform32 is a
retained negative control. Alternatives model original funding lineage and
positioned-note/value arithmetic under the honest one-real-input/full-cashout
wallet policy. They do not prove alternative cryptographic ownership, arbitrary
two-real-input circuit behavior, current economic sender or human anonymity.
Per-claim payout derivation is preserved; participant counterparty facts are
not silently equated with funding lineage. The original price-prior failure
and qualification thresholds are unchanged.

## Remaining fee blocker

The [exact pinned-source analysis](fees/NEXT-FEE-BLOCKER-01.md) establishes a
**2.95% verification-only floor** for one private payment plus an independent
private withdrawal of 10 KAS at reference rate100. Byte cleanup and more proving
CPU cannot erase two native verifier charges. The 32-payment batch amortizes one
transfer verification; it does not qualify isolated or later separate payments.

Lower budgets and smaller genuine batches are explicitly unimplemented
counterfactuals. The largest design question is whether established proof
aggregation/shared settlement can amortize independently initiated payments
while preserving recoverable, priced unilateral exits, data availability and
bounded delay. No new aggregation subsystem or vProgs requirement is selected.
The [compatibility analysis](fees/AGGREGATION-COMPATIBILITY-01.md) identifies why
existing owner proofs cannot simply be wrapped into one accepted settlement:
current state, nullifier absence/updates, outputs and fee authority remain
native obligations. It also distinguishes state dependency from proof timing:
version1 transaction IDs exclude signature/proof bytes, so fixed public bodies
can permit overlapping proof generation. No new aggregation or speed result is
claimed. The next small experiment specifies a two-action public transcript
and its rejection cases before selecting any new cryptographic implementation.

## Recheck the retained public packet

From the repository root:

```sh
python3 research/next-session/compact-batch/verify_publication.py
```

The checker verifies the finite root inventory and resolves historical transport
source entries through the explicit preserved preimages. It does not read any
backup/PK, rerun proofs or establish financial, chain or privacy correctness.
Git publication contains the public source/evidence packet. Child no-upload
fields record packet creation before Git publication. Proving keys, private
truth and owner material stay outside Git; independent parameter hosting and
release deployment remain open.
Excluded development snapshots and raw logs are retained outside Git in a
private local directory;68 files were moved without deletion. The finite public
inventory defines what this commit publishes.
