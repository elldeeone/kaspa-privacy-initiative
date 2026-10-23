# Candidate C invoice V2: prospective incremental privacy screen

**Status:** draft for root review, before any privacy evaluation. This is an
explicit prospective invoice revision following the V1 source-level finding;
V1 was not evaluated. Its [contract](CONTRACT.md), scorer and input freeze are
retained, with [zero-execution cancellation](PRE-RUN-CANCELLED-01.json). The V1
recipient's 25 passing tests remain evidence about V1, not V2.

## Change and hypothesis

The proposed V2 invoice uses a per-index opaque note incoming value derived
under the existing domain-separated HMAC role `b"INCOMING"`. It carries the
domain-stable sealed-box delivery public key separately:

```text
incoming_i = derive(b"INCOMING", i)
Invoice208 = b"KPX2IN01" || D32 || u64LE(i) || O32 || incoming_i32 || K32 || PK32 || deliveryPK32
```

This preserves note168, receipt216, Auth484 and exact CM/NF/private/native hash
encodings; recipient derivation and delivery routing are explicitly revised.
Native note openings disclose incoming_i but not deliveryPK. The sender uses
deliveryPK for the established sealed-box encryption library; no cryptographic
primitive is introduced. V2 requires a versioned contract/source/input freeze.

**Narrow hypothesis:** fresh derived O/incoming_i/K/nativePK across distinct
invoice indices do not expose the V1 stable-delivery-key equality in their note
openings. This is an exact equality observation, not a hiding theorem. The
stable deliveryPK still links invoices given to directory/counterparty observers.
An observer possessing an invoice can match that exact invoice to a later reveal.
Repeated index/k/K/nativePK, full opening/amount disclosure and prior/future NF
recognition remain in scope. Separating the delivery key does not erase them.

For a prospective public hash-only ADMIT, its note-opening fields would no longer
carry the stable delivery key. This removes the specific V1 equality channel by
construction if actual ADMIT bytes follow that layout. No actual native ADMIT
trace is present in the recipient fixture; that byte-conformance gate stays
**incomplete**, not a synthetic pass.

## Frozen observer and target boundaries

Use only the final, independently rehashed V2 recipient exports. Preserve C as
public accepted-format CM/position/ciphertext and NF records plus expressly
published reveal openings. These exports are offline supplied snapshots, not
accepted transactions, private-proof history or chain confirmation. The two
reveals are unordered unbroadcast references. Ciphertexts are opaque; do not
give C the invoice index, owner label, deliveryPK, seed, s, native secret or
unpublished k merely because the fixture developer has them.

The separate invoice-directory observer receives exactly its declared invoice
entries, including owner labels, per-note fields and deliveryPK. This P/I
addition may link those records. It does not convert them into C inputs.
Synthetic truth is consumed only for the conditional direct-note amount binding;
it is not an attacker input. This is a public deterministic fixture review,
not a blinded or held-out statistical experiment.

The existing common-price workload remains failed under the unchanged gates:
prior accuracy `21103/100025 = 21.0977255686% > 20%`. Identity 10%, amount 20%,
five-percentage-point advantage, selective precision and zero forced-disclosure
requirements are preserved. No workload, eligibility, target or threshold is
retuned. This screen cannot qualify the 32-role workload or network privacy.

## Cases, gates and stop rule

1. Independently validate the actual V2 wire boundary, invoice208 bytes and every
   revealed CM/NF, domain, position and whole-note `V=payout+fee`. Enforce the
   unchanged note/payout floors and MAX. Require explicit unordered, unbroadcast,
   arithmetic-only labels. No native signature/proof/backing validity follows.
2. Report exact equality classes over actual per-note O/incoming/K/nativePK,
   separately from directory deliveryPK. Different bytes show only absence of
   that equality test in these fixtures. Report the matching directory record
   for each reveal and any stable delivery-key grouping available to P/I.
3. Retain malformed byte-channel canaries for individually repeated fields;
   label them as not relation-valid notes. The key-reuse control instead builds
   source-shaped CM/K/NF relations with a fresh rho and the same k/K, then scans
   all public CM/positions under revealed k. Do not give the observer the
   sibling's opening or key assignment. Preserve the distinct-key negative.
4. Retain published k/opening knowledge when undoing chain spend effects. A later
   same-note private NF remains recognizable. This is a knowledge diagnostic,
   not an executed private/native spend race or authorization test.
5. Compare the source-declared fixed two-NF private shape for one/two real inputs
   against the one-NF revealing branch. Report only that counter distinction;
   actual private bytes, dummy indistinguishability and capacity are separate.
6. Report exact value of synthetic historical direct-note targets when the
   fixture explicitly binds payment amount to revealed V. Real historical
   private-payment disclosure remains incomplete without actual proof/history.
   Do not infer arbitrary economic allocations or waive later-horizon leakage.

All cases are deterministic canary/conformance checks. Missing source bindings or
invalid controls stop as **incomplete**; retain the failure and do not retune.
Source-level findings and failures are retained separately from passing
conformance. Any supported historical target forced by real observations would
fail its named claim. A quarantined duplicate cannot erase accepted backing or
freeze a previously owned claim; this privacy screen does not retest that wallet
accounting rule.

Run exactly one frozen V2 evaluation after root review, final source and input
hash pins, then perform independent source/data integrity review. Maximum one
CPU thread and 2 GiB address space; Python standard-library hashing/HMAC/JSON and
integer/equality operations only. No network, GPU, subprocess, proof/native
execution, wallet RPC, funding, broadcast or old attack-suite rerun.

Sources: [note/state contract](../NOTE-STATE-CONTRACT.md),
[RFC-0012](../../../../docs/rfc/0012-useful-privacy-requirements.md),
[retained prior information limit](../../../privacy-target-consistency-2026-10-22.md),
[V1 analytical findings](ANALYTICAL-FINDINGS.md) and the exact V2 recipient/source
pins to be recorded in the pre-execution manifest.
