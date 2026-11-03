# Offline funding/exit script-reuse test

Date: 2026-10-20 UTC (2026-10-21 Australia/Sydney).
Candidate: `dbf4dace0fe6d992c9add46e6b4cd8a8f8b7309b`.
Prospective specification: freeze this file and executable sources before the
first fresh wallet is generated. Preserve failures; do not change criteria after
observing an outcome. This is a constructed diagnostic, not a held-out privacy
rate measurement or the 32-role workload.

## Question and source basis

Does the current wallet permit a selected native funding output and later native
withdrawal to use an identical script? If so, can that extra public association
resolve a previously ambiguous internal payment in a small complete history?

The source-derived concern was recorded in [the calibration](EARLY-PRIVACY.md)
and the [population source review](../../research/shielded-kas-32-role-evaluation-2026-10-20.md).
`Backup::funding` and EXIT both use `native_key` and the existing
`KPI/payout-key/v2` derivation. EXIT requires its key index to be the minimum
selected note position. Funding accepts an explicit caller-supplied index.
This is an allowed configuration; it is not a default/index-frequency claim.

Reuse the current wallet, lifecycle helper, pinned Groth16 parameters, native
validator and public replay. No wallet, cryptography, key derivation or consensus
change is part of this test. The existing protocol-source reviews still delimit
their assumptions. A domain-separation redesign, if warranted, needs a separate
decision and recovery analysis.

## Paired native construction

Create fresh unfunded wallets A and B; never load a previous wallet's secrets.
Share A's initial reserve and bootstrap between two offline counterfactual arms.
Keep B's keys and pool domain the same between arms. This does not authorize
submitting conflicting histories to a chain.

| Step | Exact values and policy |
| --- | --- |
| Foundation/bootstrap | A starts with 2,000,000,000 sompi; one bootstrap fee leaves a 1,960,000,000 self-note. |
| Admission | B's synthetic ordinary parent provides 1,200,000,000; admission credits 1,160,000,000 at position 3. |
| Internal payment | A spends its bootstrap note, paying B 1,920,000,000 with zero change. Receipt is at position 5. |
| Final exit | B spends positions 3 and 5 together, receiving 3,040,000,000; reserve becomes zero. |

Every pool operation charges the unchanged 40,000,000-sompi fee. Each arm must
reconcile 3,200,000,000 entering = 3,040,000,000 payout + 160,000,000 pool fees.
Ordinary parent/founding fees are separate. Seven fresh proofs are required:
one shared bootstrap and three per arm. Every resulting pool transaction must
pass real proof/native verification and complete replay. Synthetic parent UTXOs
and offline heads remain explicit; no funding or chain acceptance is claimed.

The matching arm uses B's funding index 3. The different-index control uses 0.
Both EXIT requests use the mandated index 3. Neither index nor private selected
positions is an observer input. Identical economic schedules are deliberate;
commitments, signatures, proofs and ciphertexts need not have identical bytes.

## Observer and inference

The observer receives only actual native lineage/parent bodies, public descriptor
and verification key, plus an explicit association of the two funding sources
with two distinct wallet owners. These are funding-linked pseudonyms, not human
identities. The association and current wallet policy are assumptions, not facts
proved by different public keys. In particular, the funding controller is the
bootstrap/ADMIT shielded owner, and the EXIT native controller owns its selected
shielded inputs under this wallet. These bindings are not general v6 circuit
guarantees. The observer receives no backups, receiving
envelopes, private derivation indices, action files, wallet inspection output or
plaintext notes. An isolated process has no host home or external network.
Each observer sees only one arm: sharing keys across these deliberate
counterfactuals would contaminate the control if both arms were visible together.
The later combined public evidence export is not a valid isolated control view.

First compare the script of the exact consumed external funding output with the
actual payout output. Do not compare merely a funding transaction ID, all outputs
of a parent indiscriminately, or locally reported funding-command metadata.
Record exact matching outpoint/exit pairs before scoring against private setup.
Also compare against the founder's funding script as a wrong-owner control.

Then analyze the single ordinary PAY using exact integer conservation, positive
note floors, recipient/change ordering, one-or-two-input selection with a common
owner, and the final complete DRAIN. Self-payments must not be silently excluded;
unfunded recipients must not be silently treated as impossible at creation.
Use independently checked arithmetic encodings/controls for claimed uniqueness.
Selected inputs and plaintext values remain hidden variables.

Compare the same reduced public history with and without the owner association
derived from script equality. In the unlinked case, seek both concrete abstract
histories: A pays B 1,920,000,000 and B exits, or B pays A 1,120,000,000 and A exits.
These are arithmetic/ownership alternatives under the assumed cryptographic
hiding abstraction, not alternative openings or proofs for fixed commitments.
A satisfying alternative carries no probability weight and establishes no
cryptographic indistinguishability. Actual native history must independently
validate and its private truth must satisfy the observer relation.

The additional inference is conditional on this sparse history, the declared
funding associations and wallet behavior. Byte equality alone establishes reuse
of a native spending condition; it does not automatically identify a private
payment or real person. The causal ablation removes only the equality-derived
owner constraint. The native different-index arm checks that a normal valid
execution can avoid the equality.

## Success, failure and stopping criteria

1. **Boundary reuse demonstrated:** genuine matching-arm funding/payout scripts
   are byte-identical, while different-index and wrong-owner comparisons differ.
   Otherwise report the source hypothesis unconfirmed or the experiment invalid.
2. **Internal disclosure demonstrated in this diagnostic:** unlinked analysis
   admits different sender, recipient and amount assignments; adding only the
   public equality-derived owner constraint leaves one assignment, checked in
   both encodings and against sealed actual truth. A simple deposit/exit pair
   without that inference is only boundary linkage.
3. **Incomplete/invalid:** any failed proof/replay/accounting, observer access to
   secret data, inconsistent truth, solver unknown, failed negative control or
   disagreement invalidates the affected claim. Preserve artifacts and diagnose;
   do not weaken checks to obtain a finding.

Seal predictions before scoring. Keep fresh secrets and full truth in a private
directory; export only an explicit public evidence allowlist with hashes. Check
source/binary hashes before and after. Obtain an adversarial second review of
the inference, isolation, export and claim boundaries.

This experiment cannot qualify real-world privacy, cryptographic security,
anonymity rates, the 32-role persistent-payment claim, or current chain behavior.
A negative control is not a privacy pass. A positive internal-disclosure result
is a concrete reason to review funding/exit key separation; removing this link
would not fix unrelated amount/timing or ownership inference.
