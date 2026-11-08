# One-note exit leakage and private-merge screen: fixed before scoring

**Source checkout:** `research/native-kas-withdrawal-privacy` at `2b48c812`.
**Question:** does the *actual public operation shape* of the retained four-wallet
history narrow payment amounts beyond aggregate balances, and would one private
two-note merge materially repair that loss under unchanged L1 rules?

## Fixed evidence

Use the retained 47-useful-KAS, 40-KAS-principal offline `combined` run from
`research/cached-approval-verification-2026-11-07/run/`. It contains genuine
wallet proofs and native Full transactions, but uses a synthetic source UTXO;
the transactions were not accepted on chain. Read the public transaction
payloads, outputs, values, scripts and order; the actual registration-service
messages; and the fixed arrival schedule. Use the source wallet/circuit to
interpret the one-input/two-positive-output transfer and one-note EXIT rules.
Do not read the controller's private `actor-calls.jsonl` or wallet backups as
public evidence.

Pinned SHA-256 inputs:

| Input | Hash |
| --- | --- |
| `combined/MAIN.json` | `07c0e4fedf81d3776d66f2042c986ca1baf471b3fb6e0fbafb2bba798be45f69` |
| `combined/APPROVALS.json` | `1f221b5be0ea2b0f83f9115bd0dd6c1bcdb0f12dc9b4e32f219f9926c4e69ebd` |
| `combined/ARRIVALS.json` | `233b75b508f1f3052d72645c689cc9f764edb25e39d2f0bab2972e9f6b53b84d` |
| `registration/operator.jsonl` | `aae893908071bd6e5b9ce30976bdd6ddb691bf598f31245419e30fcf0f508255` |
| `poc/private-note-wallet/src/protocol.rs` | `2bf0e6e9d22acc68c61121671beb3b2ff2332e15ff06a0b4b5d75e4a5a0b5526` |
| `poc/private-note-wallet/src/wallet.rs` | `2e2d8a0baf5414afadf4576da076d9ebd8b9ed47f3fab0e1b922f7addc1521a9` |
| `poc/private-note-wallet/src/circuit.rs` | `2522a17d8a4251472bf06947860f028ec1658733f6db11b62e22385857fd5cdf` |
| `poc/cached-approval-verification/host/src/flow.rs` | `c57f03aaf475cf8b92771b02ec0f05ccec85096afe608c3124be072c8270cbbc` |
| `poc/cached-approval-verification/host/src/actor.rs` | `05f30ec31bd4e9645ee735706c124e85d84ad047b8e468e6b9a67f20106b1a88` |
| `poc/cached-approval-verification/common/src/lib.rs` | `f3d4ab70074485242374acff825ac3be7774e66c7c97a71ff8d7d3a576b0cd06` |

The seven executed private-payment values (20, 10, 10, 2, 1, 3, 1 KAS) are
**truth for the later score only**, not prediction inputs. Prediction may know
the seven directed contacts in order: A→B, B→C, A→D, D→A before group exit,
then D→B, D→C, D→A. This is deliberately strong auxiliary knowledge; the
experiment does not measure discovery of the contact graph. It may know group
payout owners A/B/C once each at 10 KAS, and final payout owners A for 2+1,
B for 1, C for 3, D for 3 KAS. Owner labels come from this research fixture's
restored-spend controls and are not automatic chain facts.

## Observer and candidate

1. **Public structure:** parse each actual native payload into packet mode,
   ordered operation kinds, public `exit_value`s, commitment/ciphertext counts,
   and proof lengths. Include transaction values/scripts, fee change/refund,
   and operation timing/order. Treat commitment, ciphertext, nullifier and proof
   bytes as opaque unless a public equality or verification failure exposes a
   relation. The existing Groth16 evidence is not a fresh ZK proof audit.
2. **Known-owner/contact amount attack:** enumerate complete, truth-retaining
   histories under the exact current wallet rule: one positive input note per
   transfer, one positive recipient note plus positive sender change, one entire
   note per exit. Do not assume which note was spent when several exist. Require
   every intermediate note inventory and every published owner-mapped exit
   amount to match. Primary amounts are positive integer sompi. Also report a
   whole-KAS grid sensitivity because all executed transfers are whole KAS.
   Score exact values of the seven *actual* payments, complete distinct amount
   vectors, and truth retention. Add a one-participant disclosure control where
   A truthfully shares the amounts of A's four own sent/received payments; do
   not pretend a participant is ignorant of its own transactions. No
   commitment-position multiplicity counts.
3. **Service/traffic:** report what the actual service transcript and fixed
   arrivals add. The registration service handles only the three group claims;
   it does not receive the controller's private payment instructions. The
   controller's fixed arrival schedule is an explicit strong auxiliary; absent
   an independently measured network/identity channel it cannot be converted
   into a probabilistic owner attack. Record this limit, not a fabricated score.
4. **Merge counterfactual:** after the three later payments, let A merge its two
   remaining positive notes into one 3-KAS note before the final native exit.
   Keep all seven payments, other owners' exits and all balances fixed. This
   changes terminal A's native outputs from 2+1 KAS to 3 KAS; it adds one public
   two-input operation with two nullifiers. It is an **offline model only**;
   current wallet/circuit/ledger do not implement it. Assume no hidden fee or
   new consensus rule. Count only changes in actual payment amount facts under
   the same observer, not a raw number of opaque labels.

## Stop rules

First, if the stronger actual-operation model fixes more payment amounts than
the prior balance-only model, correct the branch's headline interpretation.
Do not claim the exact proof bytes are shared by counterfactual histories;
compare only public field structure and declared cryptographic opacity.

Implement a two-input merge **only if** its offline counterfactual makes an
actual previously exact amount non-exact, changes a real payment relationship
fact, or gives another concrete and material privacy advantage under the
whole-KAS sensitivity and strong known-owner observer. A larger sompi-only
candidate count is insufficient. If the merge fails this gate, stop before
circuit/prover/Testnet work and retain it as a rejected candidate for this
workload. Run a new complete cost campaign only if privacy survives this gate;
otherwise report the existing 47-KAS 8.2123% proof-and-fee subtotal and do not
present it as complete service cost. No mainnet, real funds, consensus changes,
protected-host access or upstream posting.
