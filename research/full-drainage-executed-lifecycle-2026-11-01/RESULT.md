# Executed full-drainage lifecycle result

**Checkpoint update, 2026-11-02:** the original live stronger-observer claim
below is superseded by [CORRECTION.md](CORRECTION.md) and
[NEXT-PRIVACY-RESULT.md](NEXT-PRIVACY-RESULT.md). Its supplied `M -> S` fact
excluded the actual executed history. The corrected limited known-owner model
retains two gross histories, exposes B's payment to M, and leaves other facts
ambiguous; it does not establish general payment privacy. All five native
payouts and zero terminal user principal remain supported. The
[public live evidence archive](run/tn10-attempt-06-public/README.md) preserves
the original reports without rewriting their bytes. The local and historical
results below remain for context; use the correction for the live privacy claim.

**Date:** 2026-11-02  
**Decision:** the depth-four TN10 profile completed its bounded live lifecycle:
two deposits, three private transfers, five owner-authorized exits, five native
payouts and seven receipt-backed settlements. Terminal principal and permission
accounting reached zero. The public-only score retained two plausible gross
histories, while the frozen strong observer selected one; the stronger result
remains a bounded privacy failure.

## What executed

Two fresh alternative worlds used one new depth-four Groth16 setup:

- verifier `2460a0b13c2afa27e3c739239b8de4772afd035f417f1a4f615168be9c889086`;
- domain `5e9328951d8235750f7108717773bf56357763b5c7f30d800178a877106b7528`;
- 180,229,776-byte proving parameters; 712-byte VK; setup 10.330s;
- per world: 2 credits, 3 genuine payments and 5 owner-authorized exits;
- total: 20 accepted wallet proofs in 120.830 proof-seconds;
- whole two-world run: 739.089 seconds, dominated by separate parameter loads;
- fixed wire sizes by kind: credit 723, transfer 908 and exit 538 bytes;
- every transfer had two 185-byte ciphertexts; exits had none; all app fees zero.

Wallets A/B/M/S ran in separate processes with separate `0600` secret stores.
The orchestration process supplied public state and payment commands but did not
serialize wallet secrets into requests or public evidence. This is process
separation on one host, not independent people, machines or custody domains.

Both worlds reached exactly:

```text
tree leaves:             8
economic nullifiers:     8
confirmed payout records: 5
reserve principal:       0
private liability:       0
pending deposits:        0
unpaid exits:            0
```

These were authenticated local deposit/payout fixtures. No native transaction
was broadcast or confirmed.

## Service-loss recovery

After the three payments in each world:

1. the default relay and all four original wallet processes stopped;
2. four new processes restored the owner backups and checked the same verifier;
3. each owner scanned the accepted public records; M recovered two notes;
4. all five exit proofs were prepared against one common pre-exit root; and
5. a replacement relay applied them sequentially with current-nullifier checks
   and confirmed all local payout fixtures.

No original relay state, operator secret, privileged signature, other user's
balance, delay, lock or MPC service was required. Preparing exits at one common
root exercised concurrent-valid intent handling; sequential application retained
the historical membership anchor while checking current nullifier spentness.
No reorg or independent-host data loss was exercised.

## Privacy result from actual transcripts

The two literal transcripts differ, as required for fresh keys, note randomness,
ciphertexts and proofs. The result compares compatible payment facts under the
frozen opacity assumptions; it does not claim alternate openings of a binding
commitment or byte-for-byte indistinguishability.

| Observer | Compatible event sequences | Gross histories | Result |
|---|---:|---:|---|
| protocol, owners known, unrestricted edges | 12 | 3 | ambiguous |
| plausible four-edge graph, owners known | 9 | 2 | bounded candidate passes |
| neutral relay plus known owners | 9 | 2 | relay added no payer identity |
| strong external fact: S was paid by M | 3 | 1 | ambiguity defeated |
| sparse known-owner failure | 1 | 1 | uniquely recoverable |
| payout owners unmapped | 3,888 | 972 | sensitivity only; not headline |

In the two-history known-owner set:

- `B -> M 20,000,000` sompi is exposed by the constraints;
- A's payment to M is `30,000,000` or `40,000,000`;
- S's `10,000,000` payment came from A or M; and
- M's public terminal note fragmentation is `30,000,000 + 20,000,000`.

When the observer knows M paid S, the complete H1 gross history is unique. The
stronger result therefore remains a privacy failure.

The relay actually saw operation order, arrival time, fresh relay token and the
JSON request representation. JSON request byte lengths varied because random
byte arrays use variable-length decimal text; the protocol wire lengths were
fixed by operation kind. The relay saw no wallet identity field, and the frozen
model supplied no timing-to-owner map, so those measurements did not add a payer
fact in this bounded score. This does not show network anonymity; IP/RPC origin
was not measured.

## Adversarial checks

Six executed harness controls rejected without creating successor state:

- wrong domain;
- wrong root/proof;
- accepted exit replay/current-nullifier double spend;
- unauthorized wallet discovery/exit;
- underpaid payout; and
- diverted payout.

The depth-four accounting/circuit tests passed 8 cases. The archived persisted
proof test failed at `domain/version/verifier/kind`, as expected: those committed
proofs belong to the older default domain. This failure is retained; it is not a
cryptographic rejection test for the new run. The unchanged default-profile test
suite is checked separately.

Passing proofs and tests establish behavior of the executed implementation only,
not cryptographic correctness or production safety.

## Fresh TN10-profile preparation

ADR-0019 implements a distinct opt-in profile rather than relabelling the local
evidence:

- domain `5228579a04c43c288ae4f715a497e6b1704d18764b62f1785b21f261cfc22bc1`;
- verifier `97ef3a85e5d03956150f9802d42697a8dcbb338a32a30efc811d1b3898157e32`;
- guest image `b80aa1fa8b9553b2021be9987647046ff8c15aa77206a4db858f13bf9c9a8688`;
- fresh 180,236,176-byte experimental parameters, fresh wallet operations and
  valid x-only native payout keys; and
- seven linked native batches with 39 distinct synthetic transaction inputs.

The fresh two-world wallet run accepted 20 proofs in 100.244 proof-seconds and
623.612 wall-seconds. Both worlds restored all wallets, prepared all exits from
one recovery state and ended with zero principal accounting. The selected H2
world compiled into the exact seven-batch native schedule. Local scripts accepted
the genuine path and rejected wrong domain/root, both cross-profile directions,
exit replay and 13 payout underpayment, wrong-recipient or reserve-diversion
mutations.

Exact guest CPU execution matched every expected journal:

| Batch | User cycles | Segments | po2 |
|---|---:|---:|---:|
| 01 | 140,115,121 | 143 | 20 |
| 02 | 139,735,495 | 143 | 20 |
| 03 | 46,274,838 | 48 | 20 |
| 04 | 46,443,318 | 48 | 20 |
| 05 | 46,599,013 | 48 | 20 |
| 06 | 46,934,007 | 49 | 20 |
| 07 | 2,850,602 | 131 | 16 |

The seven-batch plan is therefore measured, not estimated, and every batch is
below the frozen 160M-user-cycle limit. All seven batches produced genuine
223,930-byte Succinct receipts. Separate CPU processes verified every exact
image, journal, seal and official JOIN control; all seal, image, control and
journal mutation checks rejected.

The original batch-1 po2-20 attempt is still retained: it reached the final guest
proof marker and failed a 1,728,053,248-byte CUDA allocation on the 8-GiB RTX
3070. Pinned RISC Zero source supports smaller segmentation. Batches 1-6
completed at po2 19 in 181.541-544.527 seconds each with 6,213-6,229 MiB peak
sampled VRAM. This changed the prover resource profile only; the guest, inputs,
journals, program image, verifier, official JOIN control and native checks were
unchanged.

The complete receipt-backed rehearsal independently verified the seven receipts,
rebuilt all seven settlements, matched their frozen transaction IDs, executed
every issuance and payout script, and ended with zero reserve principal, private
liability, pending deposits, unpaid exits and permission rent. The separate
100,000,000-sompi state rent remained excluded.

## Executed TN10 lifecycle

Fresh trial `2ccbeefa3f2bb0fdd57c29756bb27e6147f7c79f5e912203b67c657d7398a000`
used free Testnet-10 KAS only. A synchronized v2.1.0 TLS route carried mutations;
a second independently operated synchronized route agreed on relevant UTXOs and
the terminal state. The locally owned node remained an asynchronous syncing
witness and was not treated as live authority.

The successful path confirmed all seven settlement transactions and all five
native payouts. Final corroboration found five exact owner outputs, all five
permissions spent, no reserve principal, the terminal state UTXO and only the
separately accounted 100,000,000-sompi state rent. The final checkpoint reports
zero reserve principal, private liability, pending deposits, unpaid exits and
permission rent.

The final CPU proof was safely replaced by an independently verified CUDA
receipt over the same immutable target after the CPU computation remained live
for about an hour. That long interval exceeded Node's single-string limit only
after the final settlement was accepted. No transaction was retried. Read-only
recovery retained two complete native response passes across 36 compressed
pages, reconstructed 24,754 selected-chain headers, retained every transaction
in KPI-lane-active blocks, and passed the unchanged pinned validator. The
omission and substituted-ID controls rejected; reordering was inapplicable to
the one-lane-transaction interval.

Five earlier fresh identities are retained as negative operational evidence:
an unsynchronized capture route, a moving-tip preflight guard, two long-gap
capture failures and one pre-broadcast moving-tip failure. None was reused after
its trial failure.

Official upstream heads were rechecked before this decision: rusty-kaspa
`4edcbbccb449f84832afb1ca157904b35f37d006`, Kaspa docs
`0ac77d043a802fc8196abfd5812ac2afbd97a2b9`, KIPs
`e4ae2332117b5cb68bd6188e065ef885b6d17939`, and vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e`.

## Evidence boundary

- Frozen selection: `SELECTION.md`
- Public score: `run/public/SCORE.json`
- Controls: `run/public/CONTROLS.json`
- Public transcripts: `run/public/trial-*`
- Secret stores, parameters and truth: retained outside Git under
  `/var/tmp/kpi-full-drainage-executed-20261101-v1` with `0700` directories and
  `0600` wallet/truth files
- First harness failure: preserved in `run/attempt-01-failed`
- Fresh TN10-profile local preparation:
  `tn10-depth4-preparation/README.md`
- Preparation manifest SHA-256:
  `7f993e5952004d4f4b4b6ce03a128a6a9cb7e70080ab286642c940f10a04cc42`

No MPC, merge, delay, withdrawal lock, privileged withdrawal key, paid compute,
mainnet action, public post, commit or push occurred. Passing this bounded TN10
trial does not establish cryptographic correctness, production safety, general
privacy or audit readiness.

