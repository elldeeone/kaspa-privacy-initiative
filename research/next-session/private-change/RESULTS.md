# Private change and repeated spending

**The complete change-and-repeated-spending route is confirmed on TN10.**
Original-backup cold clients recovered and spent two successive private change
notes, without saved issuance indices, receipt maps or the operator prover.
All three native payouts are confirmed; the reserve is zero. This is a smaller
functional pilot, not a financial-privacy, fee or production qualification.

## What now works locally

The new owner wallet prepares an exact partial native cashout with positive
private change, recovers that change from the original backup, spends it in
another private payment with new self-change, recovers again and completes the
remaining full native exits. It also supports exact-zero-change private payment
without imposing a retained balance. Public sizing has no witness; only the
legal actual candidate's own exact quote may reach proving and native release.

One fresh development setup produced six genuine proofs under the same new VK:
five for the main route and one independent public-synthetic C0 control. All
seven complete native transactions (six main bodies plus C0) passed native Full
and every input engine, with seven SDK roundtrips and five main prior-output
links. The main route ends CM9/NF11/reserve zero.

| Main stage | Exact result, integer sompi |
| --- | --- |
| Founding | 1,018,958,700 sender reserve; 79,780,700 ordinary change; 1,260,600 fee |
| Initial private payment | Bob 1,000,000,000 claim; 18,958,700 fee |
| Partial native cashout | 400,000,000 payout; 581,000,100 private change; 18,999,900 fee |
| Private payment from recovered change | Charlie 300,000,000 claim; 262,041,400 new self-change; 18,958,700 fee |
| Full continuing cashout | 243,041,500 payout; 300,000,000 reserve remains; 18,999,900 fee |
| Terminal cashout | 281,042,400 payout; reserve zero; 18,957,600 fee |

```text
1,100,000,000 synthetic source
= 79,780,700 ordinary change
+ 924,083,900 native payouts
+ 96,135,400 complete main-route fees
+ 0 reserve
```

Two actual encrypted positive-change recoveries used the unchanged original
backup before the subsequent payment/full spend. Fresh receiver reconstruction
rederived embedded invoice indices and checked current positioned NFs; no saved
change-index map was needed. Three final original-backup scans found zero private
tails. Spent original/first-change receipts were correctly unavailable afterward.
These are local supplied-context checks, not independent live acquisition.

The [sanitized local packet](lifecycle/local-public-01/FILE-ALLOWLIST.json) and
[independent review](review/LOCAL-REVIEW-01.md) retain scoped outcomes and selected
opaque proof/Auth hashes. Raw unbroadcast main alternatives remain private under
the [NF-intersection publication boundary](EVIDENCE-PUBLICATION-01.md).

Six further malformed/rebound native bodies were rejected. Four predicted early
error types matched; two coherent Auth rebindings reached Groth16 and failed with
`ZkIntegrity` rather than the predicted `VerifyError`. The original 4/6 typed
harness result and exit1 are retained, with a [source-grounded interpretation](lifecycle/NATIVE-NEGATIVE-INTERPRETATION-01.json); no checks were weakened or rerun.

## Software and resources

The baseline wallet controls passed 27/27, including actual established receipt
encryption, repeated seed recovery, slot permutations, C0 sizing, invalid amounts,
stale/replayed state and export exclusion; native/prover calls were mocked there.
Three focused selected-release/wiring checks then passed. The
[selected source release](wallet/selected-release-01/SOURCE-FREEZE.json) has 22
pins and separate independent review. Known accepted duplicate claims retain
spend authority; only a new requested self-payment reusing known own historical
receive fields is refused by the wallet privacy guard.

The fresh setup took 13.885 seconds. Genuine proofs took 7.972–8.203 seconds each
with 14 CPU workers; the whole process peaked at 4,951,035,904 bytes with zero
swap, including idle time. The native seven-positive batch took 3.236 seconds
under a 2-CPU/4-GiB ceiling. The operator prover stopped cleanly. The selected
client authenticated the complete new 1,290,878,896-byte public parameter blob;
12/12 loader/readiness controls passed before any owner witness was offered.

## Fees and privacy

This repeated-payment route remains above the unchanged complete-fee target.
The new native subtree component passed eight positives and 48 typed negatives;
for N32 it reduced redeem bytes 50,385→1,862, payload 17,488→1,456 and observed
units 392,747→19,003. These are Merkle component savings, not a financial policy.
[ADR-0056](../../../docs/adr/0056-compact-native-batch-fee-screen.md) now tests an
actual complete compact-policy emitter: 23,575 bytes, 55/55 expected native
outcomes (eight public-binding checks reaching the intentionally invalid G16
seam; 47 early rejections), and a source bound of 15,008,331 execution units
within the unchanged1600 budget. The [complete emitted-program fee projection](fees/WHOLE-EMITTED-COSTS-01.json) is **1.9491%** for 32 simultaneous10-KAS
payments and independent exits, or1.9679% with the payer2200 stress setting.
Separate-time payments with change still project4.7257%. This new profile has
no matched circuits or valid financial proofs; these are native binding and
cost results, not accepted backing, privacy or complete fee qualification.

The exact arithmetic observer's fixed public controls passed. It confirms the
important negative: a singleton partial cashout still exposes aggregate values
through reserve accounting even when CM roles are shuffled. Arithmetic alternate
models do not establish cryptographic or owner ambiguity. No heldout privacy
score or old 72-case result was rerun. The earlier failed price prior and fee
targets remain facts.

## Confirmed live functional pilot

The [prospectively selected smaller workload](LIVE-WORKLOAD-SELECTION-01.json)
kept the original60M private/10M native floors, exact requested amounts, integer
sompi and rate100. The original10-KAS local workload and adopted fee/privacy
targets are unchanged. Three provenance-verified archived ordinary test coins
funded this fresh identity; no faucet request or real funds were used.

| Actual accepted stage | Integer sompi |
| --- | --- |
| Ordinary funding merge |286,604,800 source →286,218,200;386,600 fee |
| Founding |218,958,700 reserve;65,628,400 ordinary change;1,631,100 fee |
| Initial private payment |200,000,000 recipient claim;18,958,700 fee |
| Partial native cashout |10,000,000 payout;171,000,100 private change;18,999,900 fee |
| Payment from recovered change |60,000,000 recipient claim;92,041,400 new self-change;18,958,700 fee |
| Cashout of recovered second change |73,041,500 payout;60,000,000 reserve remains;18,999,900 fee |
| Terminal cashout |41,042,400 payout;zero reserve;18,957,600 fee |

```text
286,604,800 actual ordinary sources
=65,628,400 ordinary change
+124,083,900 native payouts
+96,892,500 all seven fees
+0 reserve
```

The [confirmed-only public ledger](lifecycle/live-public-01/WHOLE-SOURCE-LEDGER.json)
binds seven exact accepted bodies and six prior-output/context links, ending
CM9/NF11. Each native payout was observed current after a >20 blue-score depth
check. The final fresh Electron acquisition independently fetched all six pool
bodies, matched the earlier Vector prefix, observed all three native payouts
and ordinary change current, and found every reserve point spent. Selected-node
accepted history and non-atomic observations remain trusted; this is not
independent consensus or immutable finality.

Five separate cold runs took12.612–12.916 seconds each under a14-CPU/
18-GiB ceiling with swap disabled. Only the original own backup, intended public
invoice when needed, fresh descriptor-only history, authenticated public
parameters and selected local software entered each client namespace. The
operator prover stayed stopped. Bob’s first recovery recognized one spent
original receipt and one live positive change; his next recovery recognized
two spent receipts and one live second change. No previous client output,
change-index counter/map or other owner seed was supplied.

Final separate original-backup scans from that fresh second-node capture
passed: Alice recognized1 historical spent receipt, Bob3 and Charlie1; all
three had zero current private claims. Their original backups authenticated
Bob’s two and Charlie’s one current native payouts. These recovery-only runs
took1.17–1.23 seconds under separate2-CPU/4-GiB ceilings, with no public PK,
prover, cashout helper, invoice or previous owner output mounted. No selected raw body is published
before exact confirmation; all discarded/unbroadcast alternatives remain private.
Private change and repeated individual spending still miss the adopted fee and
financial-privacy targets. The compact batch screen above is a separate unfunded
profile without matched financial circuits or proofs.
