# Candidate C privacy integration checkpoint

**Result:** the review found a deterministic linkage in the first receive design
before proof/key freezing. The prospectively selected V2 invoice separates its
per-note incoming value from the stable delivery encryption key. The single
frozen V2 diagnostic confirms that separation in the actual recipient fixture.
It also retains the directory, key-reuse, rollback and historical-value leakage.
This is **not privacy qualification** or a complete private-payment trace.

## What changed

V1 put the stable delivery public key in every note's incoming field. Public
revealing openings therefore linked otherwise fresh notes; the proposed public
hash-only ADMIT would have linked them to ingress funding without a directory.
This follows directly from field equality and required no expensive experiment.

Root, architecture, privacy and independent adversary reviewed the explicit V2
revision **before the privacy evaluation**. It uses domain-separated per-index
`incoming_i = derive(b"INCOMING", i)` in the note and appends the stable
deliveryPK separately to versioned invoice208 (`KPX2IN01`). Note168, receipt216,
Auth484 and CM/NF hash layouts are unchanged. The sealed-box delivery library is
unchanged. The [V2 recipient snapshot](../recovery/V2-CONTRACT-SNAPSHOT.md)
records the exact design.

V1 recipient results remain intact. Its [privacy freeze](PRE-RUN-MANIFEST-01.json)
was cancelled **before execution** when V2 was selected; the
[cancellation receipt](PRE-RUN-CANCELLED-01.json) records zero V1 runs. No V1
privacy result is silently replaced. The [V2 contract](CONTRACT-V2.md) froze the
new question and all observer/target boundaries prospectively.

## One executed deterministic evaluation

The input is the actual new recipient implementation's **offline synthetic**
export: three derived invoice records, three encrypted receipt records and two
unordered unbroadcast revealing-opening snapshots. These are not accepted
transactions, relation-valid payment history or proof-backed liabilities. Owner
labels and invoice fields belong only to the separately declared directory
observer; synthetic payment truth is not an attacker input.

| Check | Observed result | Meaning and limit |
| --- | --- | --- |
| Invoice208 and public openings | Exact canonical bytes, CM/NF, domain/position, ranges and `V=payout+fee` match. | Reference field conformance, not native signature/proof/backing validation. |
| Fresh per-note fields | No repeated O, incoming, K or nativePK across three invoices or the two public openings. | The V1 stable-incoming equality is absent in these source-derived fields; absence of equality is not a hiding theorem. |
| Directory delivery key | Invoice records 0 and 2 share deliveryPK. | Directory/counterparty records still link those recipient invoices. Each invoice also matches its exact later reveal. No directory fields are supplied to C. |
| Byte-channel canaries | All five individually repeated fields are detected exactly. | These are malformed byte-level controls, not accepted notes. |
| Disclosed-key scan | Revealed k recognizes selected and reused-key sibling NFs in a three-CM public set; the distinct-key control is unmatched. | Sibling CM/K/NF hashes are internally consistent; the observer is not given sibling opening or key assignment. No private/native acceptance is claimed. |
| Chain rollback | Restored unspent state still permits recognition of the later same-note NF from retained published k/opening. | Rolling back a transaction cannot roll back observer knowledge. No transaction race was executed. |
| Arity | Source-declared private one/two-real cases both insert two NFs; reveal inserts one. | Counter delta alone does not distinguish private real arity. Actual private bytes, dummy indistinguishability and capacity remain separate. |
| Direct-note values | The two synthetic historical direct-note amounts are exactly 120,000,000 and 240,000,000 sompi after opening. | The fixture binds payment to V; this illustrates later disclosure, not evidence of a real private-payment history. |

The stable delivery key remains available to a sender/directory observer, and
cryptographic recipient privacy of the ciphertexts is not established by this
equality screen. Reusing k remains dangerous even when native public keys are
fresh: after publication, an observer can scan **every public CM/position** and
match existing or future NFs. Rejected, pending and orphaned disclosures remain
in the observation horizon. A prior claim cannot be frozen or erased merely
because a later duplicate invoice is flagged.

Public hash-only ADMIT byte conformance, real historical private-payment
disclosure and full C/P/A/I privacy qualification remain **incomplete in this
input bundle**. No actual ADMIT/native/private proof history was manufactured to
close them. The previous common-price workload still has the unchanged
`21103/100025 = 21.0977255686%` prior floor, above the adopted 20% amount gate.
No sample, workload, observer exclusion or threshold was retuned.

## Exact evidence and resources

- [Pre-execution V2 manifest](PRE-RUN-MANIFEST-V2-01.json):
  `d08516d0bd446c29d63047b2b2123c24d5d280a1e7e585465af90fd8739ad77f`.
- [Scorer](evaluate_v2.py):
  `abc0cbf8d7b205784094af2900e5510a026048b7a0c968aa4df784dad38afcc2`.
- [Result](result-v2-01.json):
  `ca288df89d4c3fcfdfd761ec3cd121bfc4735dabc01df578007cf72decf6648b`.
- [Execution receipt](RUN-V2-01-RECEIPT.json): exactly one V2 run, exit 0, no
  semantic rerun. Three input SHA-256s were independently matched to the
  recipient agent's frozen publication before execution.

One CPU thread was pinned to core 0, with a 2 GiB address-space cap. There was no
GPU, network, subprocess, prover, native execution, funding or broadcast in this
workstream. The tool reported 0.315823 seconds for the complete command. The
scorer reports 0.000831 seconds for its measured body (imports/startup excluded),
0.097282 CPU seconds and raw process peak-RSS high-water 1,950,208 KiB. These
different boundaries are retained; none is a wallet cold-start or memory
qualification. No process remains running after the command.

Independent source review covered observer separation, exact invoice layout,
CM/K/NF encoding, ranges, domain pins, malformed-control labeling and preserved
failure/qualification boundaries before execution. Input/result checksum
closure [completed independently](INDEPENDENT-CLOSURE.json): all nine source pins,
all three input pins, scorer, freeze and result hashes match. The reviewer also
checked the reported classes/gates against raw JSON without a duplicate semantic
run. Raw process high-water is not promoted into wallet resource qualification.

Sources: [RFC-0012](../../../../docs/rfc/0012-useful-privacy-requirements.md),
[prior information limit](../../../privacy-target-consistency-2026-10-22.md),
[V1 analytical findings](ANALYTICAL-FINDINGS.md), the V2 contract and source/input
pins above. This screen advances one concrete format decision while leaving the
complete native private-payment lifecycle and its full privacy assessment open.
