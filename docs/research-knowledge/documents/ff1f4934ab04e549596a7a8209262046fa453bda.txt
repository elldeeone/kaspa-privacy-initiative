# Shielded payment specification-to-code review — 2026-10-18

Implementation follow-up: the [offline recovery prototype](../poc/shielded-design/RECOVERY.md)
now addresses a model-level part of G4/G5 under a separately trusted checkpoint.
The gap assessment below refers to the original reviewed base; it is not a claim
that these real-protocol requirements are closed by the prototype.

**Conclusion: specify authenticated recovery records and wallet backup/restore
boundaries first. In parallel, finish the existing proof-cost qualification.
Do not extend the proxy classifier into a payment system by treating its
temporary balance or repeated-intent check as note accounting.**

This review identifies **eight work gaps** below. They are implementation/design
gaps against the proposed protocol, not eight demonstrated vulnerabilities in a
deployed pool. Seven affect the private lifecycle or recovery gate; migration
is a later requirement when another version is introduced.

Reviewed local and upstream `main`:
`c2037893936508d6d61dcb9ee78aea6ba4515aab`. The public issues and draft
[PR #42](https://github.com/olafweller/kaspa-privacy-initiative/pull/42) were read
on 2026-10-18. PR42 publishes the CUDA image and prepares guard-host checks;
it reports no live CUDA qualification. Its branch changes were not applied.

This is AI-assisted source review and offline verification, not independent
human cryptographic review. No new circuit, protocol implementation, proof,
funding, RPC observation or transaction was created. No architecture decision
or invariant is changed. [RFC-0001](rfc/0001-state-architecture.md) remains Open;
[RFC-0002](rfc/0002-shielded-payment.md) remains Proposed.

## Evidence levels

- **Model:** an ideal proof registry and in-memory synthetic wallets/state.
- **Proxy:** real cryptography for a smaller preimage/arithmetic relation.
- **Public backend:** public-account execution/settlement and recorded TN10
  payouts, with their original trust and retained-history assumptions.
- **Missing:** the required shielded integration is absent or not demonstrated.

These levels do not add up to a completed private protocol. Source requirements
are [RFC-0002](rfc/0002-shielded-payment.md),
[I-1–I-16](../SECURITY-INVARIANTS.md), the
[conditional trial](../poc/shielded-design/TN10-PROPOSAL.md) and the
[N-user recovery gate](ROADMAP.md#early-exit-and-recovery-gate).

## Requirement-to-code map

Source links refer to files at the reviewed base above. Function names and line
anchors make the enforcement boundary inspectable; tests cited here remain
model/fixture tests unless explicitly stated otherwise.

| Required behavior | Actual enforcing code / evidence | Coverage and remaining gap |
| --- | --- | --- |
| Canonical integer sompi, range and sum bounds; I-1/I-2 | Model [`amount`, `total`](../poc/shielded-design/model.py#L28), [`invariant`](../poc/shielded-design/model.py#L197); proxy [`WalletCircuit::generate_constraints`](../poc/groth16-comparison/common/src/circuit.rs#L39) | Model rejects bool/float/range errors and aggregate overflow. Proxy constrains four u64 values and their sum, not the complete note/reserve economy. |
| Hidden membership and spend authority; I-3 | Model [`ProofOracle.spend`](../poc/shielded-design/model.py#L138); compatibility [`wallet-guest`](../poc/shielded-design/compat/wallet-guest/src/main.rs#L14) | Model checks a supplied commitment list and wallet key. Real compatibility proof checks a secret hash and checked sum. No complete hidden membership/ownership circuit. G1. |
| One stable nullifier per economic note; I-4/I-6 | Model [`Wallet.nullifier`](../poc/shielded-design/model.py#L85), [`Pool.process`](../poc/shielded-design/model.py#L233) | HMAC identifiers are explicitly model-only. Historical anchors use current persistent model spentness. Proxy [`seen`](../poc/accelerated-bn254/classifier-guest/src/main.rs#L47) is local to one invocation and keyed by intent, not a note nullifier. G1/G2. |
| Atomic state and cross-batch duplicate rejection; I-4/I-15 | Model [`Pool.process`](../poc/shielded-design/model.py#L215); [`test_duplicate_spends_same_and_later_batch_are_atomic`](../poc/shielded-design/test_model.py#L48) | The test reuses one live Pool object. It does not restore a checkpoint or prove two successive shielded batches. G2/G4. |
| Intent/proof/native-ID binding; I-5/I-6 | Proxy [`journal`, `operation`](../poc/proof-classification/protocol.rs#L69); [`classify`](../poc/accelerated-bn254/common/src/lib.rs); classifier [`main`](../poc/accelerated-bn254/classifier-guest/src/main.rs#L17) | Proxy avoids proof/ID circularity and reconstructs native IDs. Its domain is synthetic and expected ordering root is an input; no private payload is yet tied through real accepted-lane settlement. G2. |
| Forced valid/invalid outcomes with continuation; I-5/I-15 | [`Verifier::classify`](../poc/accelerated-bn254/common/src/lib.rs); [24 execution cases](../poc/outer-proof-128m/RESULTS.md) | Checked proof decoding/equation and valid-invalid-valid execution exist. The full outer receipt remains absent; five partial diagnostic receipts do not bind the complete program/journal. G2. |
| Authenticate the prior economic state and accepted ordering; I-6/I-11 | Public [`takeover::execute`](../poc/takeover/common/src/lib.rs#L41), reference batch/aggregate; [recorded feasibility](based-app-feasibility-2026-10-17.md) | Public-account path demonstrated. Proxy starts with an input scalar balance; no shielded state root, anchors, nullifiers, deposits or pending claims are integrated into that path. G2. |
| Authenticate deposits and prevent double credit; I-1/I-7 | Model [`funded_deposit`](../poc/shielded-design/model.py#L185), credit branch; public [`apply_transaction`](../poc/native-value/common/src/lib.rs#L112) | Model assumes a validated event. Public backend authenticates native outputs/public credit. No private descriptor and credit binding combining these responsibilities. G3. |
| Recover a funded but uncredited deposit exactly once; I-1/I-7/I-10 | Model [`refund`](../poc/shielded-design/model.py#L270), [`credit/refund tests`](../poc/shielded-design/test_model.py#L147) | Refund mutates model accounting; it emits no native permission or payout. Old delegate helper does not implement this state machine. G3. |
| Keep exits/fees/rent backed until actual payout; I-1/I-2/I-12 | Model [`invariant`, `payout`, `pay_fee`](../poc/shielded-design/model.py#L197); public [payout builder](../poc/native-value/host/src/main.rs#L530), [accounting audit](../poc/takeover/audit.py) | Model payout is a caller invocation, not acceptance evidence. Public permission/payout is demonstrated separately. Private claims, canonical payout observation and rollback are not joined. G3/G6. |
| Exact native output/destination and final reserve disposition; I-7 | Public [`payout`](../poc/native-value/host/src/main.rs#L562) and balanced mutation controls | Helper handles one permission/recipient, converts amount to i64, and requires `delegate amount > payout amount` to retain nonzero reserve. The all-users-exit gate needs a supported terminal drain or explicitly conserved remainder. G7. |
| Recipient can discover and later spend; I-14 | Model [`Note.public`, `Wallet.discover`](../poc/shielded-design/model.py#L53), [receiver tests](../poc/shielded-design/test_model.py#L125) | Correct decryption/commitment/owner checks exist for supplied records. No authenticated restore, spentness filter, accepted-record completeness or complete delivery/spend circuit. G1/G5. |
| No private witnesses at executor/prover/RPC; I-16 | [Visibility contract](../poc/shielded-design/VISIBILITY.md), [public-field test](../poc/shielded-design/test_model.py#L140) | Model checks selected fields; roles share one harness. No enforced process/network boundary or fresh-device backup/restore. G4/G5. |
| Recovery after services vanish, pruning and reorg; I-9/I-10/I-11 | Narrow [`A1 Scanner.page`](../scripts/a1_recovery.py#L190); public [clean replay](../poc/takeover/remote/advance.py#L78) | Useful transactional pagination/replay patterns. A1 is a fixed claim; public replay uses retained same-owner/node captures. Shielded model is monotonic and has no archive/restore/reorg interface. G4/G6. |
| Permissionless fee access without principal diversion; I-7/I-8/I-10/I-16 | Model [`fund_rent`](../poc/shielded-design/model.py#L207); public [sponsor-input payout](../poc/native-value/host/src/main.rs#L592); [issue #23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23) | Separately funded rent and fees are visible. Independent fee/rent acquisition, sponsor disappearance and fee changes are not qualified for private exits. G7. |
| Versions share economic single consumption; I-4/I-6/I-13 | Model [version rejection](../poc/shielded-design/model.py#L219), stable model nullifier domain | Only version 1 supported. No migration, legacy recovery or shared spentness across allowed versions. Keep unsupported versions rejected. G8. |

## Eight concrete gaps

| Gap | Consequence / boundary | Smallest useful next artifact | Existing issues |
| --- | --- | --- | --- |
| **G1: complete private relation and recipient acceptance** | Small real proofs do not enforce note ownership/membership, note-derived nullifiers or output delivery correctness. Binding arbitrary ciphertext bytes does not prove recipient spendability. | Reviewable established-construction choice, full public/private statement and independent positive/negative vectors. Define recipient acceptance before coding the circuit; record resolved choices in an ADR. | [#4](https://github.com/olafweller/kaspa-privacy-initiative/issues/4), [#5](https://github.com/olafweller/kaspa-privacy-initiative/issues/5), [#6](https://github.com/olafweller/kaspa-privacy-initiative/issues/6), [#12](https://github.com/olafweller/kaspa-privacy-initiative/issues/12) |
| **G2: persistent shielded state and completed authenticated proof path** | Within-call intent replay is weaker than persistent economic spentness. Local root consistency does not establish real L1 inclusion/settlement. Outer proof completion remains unqualified. | Specify old/new shielded state commitment, current nullifier updates and journal bindings; prove two successive batches including duplicate-note competition. Complete current full-receipt gate before expanding cryptographic implementation. | #1, #3, #5, #6, #11 |
| **G3: native pending-deposit/credit/refund and exit integration** | A rejected credit needs an authorized native recovery path, not just a Python refund. A private debit cannot count as a payout. | Descriptor/recovery relation and credit-vs-refund race vectors; bind actual reserve/permission/output identities and unpaid claims throughout. | #6, #7, #8, #10 |
| **G4: authenticated recovery record and backup contract** | There is no versioned shielded export/restore interface or complete independently authenticated retained-data inventory. A manifest of supplied bytes cannot prove omitted bytes never existed. | Define accepted record/checkpoint/backup contents, completeness horizon and authentication source; fresh-process reconstruction with no producer object or oracle registry. [Test design](shielded-recovery-test-design.md). | #9, #10, #12 |
| **G5: discovery-to-spendability boundary** | Decryptable records may be unfunded, duplicated or already spent. Current helper deliberately has no accepted-history or nullifier input. | Specify separate discovered/accepted/spendable states; authenticate inclusion, deduplicate economic records and apply current spentness before reporting spendable value. | #4, #10, #12, #13 |
| **G6: reorg, crash and canonical payout lifecycle** | Lost/removed settlement or payout observations can leave stale anchors, double credit or prematurely dropped liabilities in a future restore implementation. | Define executed/proved/settled/paid observation states and rollback/commit rules; replay crash and removed-payout fixtures atomically. | #5, #6, #8, #10 |
| **G7: all-claim payout and independent fee/rent availability** | Current public trial helper refuses a final delegate drain and assumes sponsor candidates. Complete user recovery cannot depend on this exact helper unchanged. | Work out supported full-drain outputs/rent/refunds, value bounds and fee inputs; test last user and last fee claim, sponsor loss, fee changes and balanced diversion at the actual script layer. Do not weaken native checks. | #6, #8, #10, #23 |
| **G8: migration and legacy artifacts** | A future second verifier may fork nullifiers or strand dormant users. | Remain single-version initially; before enabling another route, specify one-time migration, legacy data/verifier/fee availability and cross-version double-spend tests. | #3, #5, #8, #19 |

G7's nonzero-reserve condition is a limitation of the inspected **trial builder**,
not proof that Kaspa or the underlying permission scripts cannot pay the last
claim. Native script behavior for that new shape still needs evaluation. G1–G7
do not require solving general migration or constructing an operator network.

## Reproduced helper boundary

Using existing public model interfaces and synthetic public fixture keys:

1. Create a Bob note and its ciphertext without funding/crediting it. An empty
   Pool has zero commitments, but `bob.discover([record])` returns that note.
2. Supply the record twice: discovery returns two entries.
3. Credit a different Bob note, request its exit and call the simulated payout.
   Discovery still returns its old record although private liability, unpaid
   exits and reserve are all zero.

These observations confirm G5's interface boundary. They do **not** bypass Pool
membership, nullifier checks or native authorization and are not a theft PoC.
Do not fix them by deleting a useful decrypt helper; put authenticated recovery
and spendable-balance semantics around the helper. Tests must distinguish an
absent payment from incomplete history before calling an empty result complete.

## Recommended work order

1. **Specify G4/G5 first, with G3/G6 fields included.** Extend RFC-0002 with a
   proposed accepted-record, backup and restore-result contract. For every field
   state who supplies it, what authenticates it, what detects omission, what the
   user retains and what breaks after pruning. Completion: a fresh environment
   has an exact input inventory and no unspecified operator database.
2. **Implement one offline restore slice after that contract is reviewed.** Start
   with authenticated commitment/ciphertext inclusion, current spentness and
   fresh-process reconstruction; then pending deposits and unpaid exits. Use
   R01–R06 below, with manually worked expected balances. A model acceptance
   oracle must be explicitly labelled; exporting its registry or accepting a
   producer's validity bit cannot qualify cryptographic recovery.
3. **Continue the existing G2 proof-cost work in parallel.** Reuse PR40/42's
   measurements/assets instead of creating another GPU control stack. A GPU
   speedup of two middle segments is not the full receipt; eventually require
   separate full image/journal/seal verification. If impractical, reopen the
   candidate comparison without discarding deterministic rejection or safety.
4. **Resolve G1/G3/G7 before the integrated private trial.** Select reviewed,
   licensed note/delivery components, specify native deposit recovery and final
   payout/fees, then implement the smallest real relation. Validate two-batch
   spentness and actual reserve/permission bindings rather than extending the
   proxy balance as if it represented notes.
5. **Run the complete recovery/exit gate only on the resulting implementation.**
   R01–R16 are a proposed qualification design, not passed tests. The later TN10
   gate must use real proofs and confirm every user's native payout, including
   the last claim. Timeout or safely detected missing data does not pass I-10.

This orders research and implementation dependencies, not extra approval
ceremony. Existing owner-authorized diagnostics retain their scope. No live
trial, paid provider work, public issue write or implementation is performed by
this review. The source comparison supporting these recommendations is in
[the recovery source review](../research/recovery-source-review-2026-10-18.md).

## Checks performed and limits

On the reviewed source, Python 3.12.13 with PyNaCl 1.5.0 and blake3 1.0.8 in a
temporary environment outside the repository:

- 24 shielded-model tests passed, including the seeded vectors within the suite.
- 15 A1 recovery/scanner/rehearsal tests and 5 A1 receipt-index tests passed.
  Synthetic validators/fixtures in these suites are not real native validation.
- Public PR33 audit rechecked 127 outer and 89 nested public members; order,
  state, fees and backing reconciled. PR32 audit rechecked 120 original members.
  These are offline archived-observation audits, not new chain queries or SDK
  cryptographic receipt re-verification.
- The three discovery probes above reproduced; no runtime source was edited.

No fresh Rust build, guest execution, proof generation or new recovery harness
was run. Existing 24 outer execution cases and diagnostic receipts are read
from retained reports, not newly executed here. Documentation checks validate
local links/structure, not external sources, protocol correctness or security.

## Adversarial second pass over this recommendation

| Risk | Required design response |
| --- | --- |
| Mint value or spend twice after restore | Reconstruct authenticated deposits and current nullifiers, not a wallet balance cache; include pending exits/fees and cross-batch competition. |
| Release native KAS incorrectly | Recovery must use the same authorization/conservation/permission rules; no owner/admin bypass, caller-paid flag or principal-funded rescue. |
| Leak sender/receiver/value | Keep private backups, selected witnesses and spending/viewing material out of public records and executor inputs. Report timing/fee/query linkage separately. |
| Dependency disappears | Independent data and artifacts must exist before shutdown; a same-owner copied directory or source build alone is insufficient. |
| Reorg or stale state | Bind a declared canonical horizon, reject mismatched snapshots, and remove orphan outcomes before deriving spendability or paid status. |
| Hidden new trust | Name archive, checkpoint, validating-node and verifier assumptions. Hash consistency proves byte integrity, not canonical acceptance or long-term availability. |

The recommendation adds no reserve authority and changes no security invariant.
