# Owner-local wallet, GN3 and history review

2026-10-24 UTC. **Corrected source and synthetic controls reviewed.**
Wallet selection is `SOURCE-02.json`, SHA256
`ada8a2f51abbcceb7f70cb178028f6467f54e890ef2eb02574e14b2c19ea4552`.
All eight selected source file hashes/sizes independently match. The selected
`CONTROLS-02.json` SHA256 is
`758e0ad626a3a09e54e45a161745d5f7056bc2529958ec1c67986b503950528d`;
its stdout/stderr hashes match the retained log showing **36 tests, OK**.
No tests were rerun by this reviewer.

This report identifies no remaining unaddressed source issue in the reviewed
wallet/history/GN3 scope. It does not authorize funding or claim a completed
genuine local, native or accepted-chain lifecycle. Review reads public source;
no original backup, seed, output map, ciphertext plaintext or controller-private
file was read or hashed. The companion JSON records reviewed source identities.

## Scope and positive source checks

- `bootstrap/gn3.py` reconstructs each complete public Note168/CM/CF/hash record,
  checks the existing integer note floor/MAX, distinct CMs, exactly three ordinary
  sources, source uniqueness and initial reserve equal to the checked sum of the
  three values. It reconstructs State112 under KPX8, initial n3/m1 and the
  externally selected immutable policy. Source-owned change and deterministic
  entry-fee allocation remain exact integer equations.
- Strict proposal validation is distinct from accepted-history validation.
  Accepted v1 budgets remain canonical u16 and require actual native execution;
  the proposal's chosen budget is not an ownership rule.
- `wallet/history.py` reconstructs all initial CM/CF/value records, both sparse
  trees, successive original-NF insertions and CM appends, genuine Spend/Output/
  Exit statements, conservation and the exact selected terminal/current
  checkpoint. History contains public records, not a saved owner map.
- `wallet/worker.py` now restores a four-field seed-only backup, derives the
  ordinary funding key at reserved index `0xffffffff`, recovers notes locally,
  and exports READY with NF/CVin but no recovered input CM or position. Owner
  secrets and the selected receipt/position remain private state.
- `wallet/support.py` authenticates the externally selected component profile,
  manifest/VK/domain/generator joins and complete required proving key before
  private seed access. Scan mode does not load a proving key.

These are source observations, not dynamic execution or cryptographic proof.

## Findings and disposition

### H1: malformed owned delivery could be silently omitted

The initial `claims()` caught every `ValueError` from `Receiver.open` and
continued. That operation combines ciphertext decryption, receipt parsing,
domain and invoice reconstruction. A successfully decrypted invalid owned
receipt or broken crypto dependency could therefore appear as an absent claim.

**Source correction observed:** the narrow selected crypto adapter preserves
only exact `{'error':'unseal'}` as the expected `crypto-unseal` category, and the
history scanner skips only that category. Successfully decrypted malformed
receipt/domain/descriptor and unexpected adapter errors remain fatal. A missing
`recipient` import noted during the edit was corrected. The selected controls
cover foreign versus owned malformed/wrong-domain/descriptor/dependency errors.

### H2: initial reserve needed strict integer parsing

The original history equality accepted an integer-valued JSON float by Python
numeric comparison. This did not demonstrate value creation but violated the
canonical integer-sompi contract.

**Source correction observed:** initial reserve now passes `uint()` before the
sum/range equality. The selected controls reject float, bool, negative and u64
overflow values.

### H3: pending mixed authorization blocked independent exit

The initial worker called strict `reconcile()` before both new mixes and direct
exits. A disclosed valid mixed authorization with an unspent original NF could
wait indefinitely if its coordinator vanished before acceptance, preventing an
otherwise valid independent exit of the still-current note.

**Root-selected correction:** strict reconciliation may continue to restrict a
new mixed retry. Independent scan/exit must preserve the old barrier and maps
but may act on the latest authenticated unspent original NF. The current native
outpoint and original NF arbitrate the old mixed body versus a direct exit;
neither timeout nor the new exit revokes the old authorization. Source edits
were observed: `reconcile(require_settled=False)` is used by independent exit
preparation/authorization, while a new mix retains strict reconciliation.
The selected controls cover strict new-mix refusal versus independent fallback,
the complete mocked Exit path after unsettled mixed authorization, and spent
note/current-checkpoint rejection. Actual native competing acceptance remains a
separate execution result.

### H4: payout key initially reused the consumed invoice key

Initial `exit_ready()` and `exit_note()` used `receipt.native_pk`. That did not
match the selected fresh-payout-key contract, especially for the publicly
admitted initial Note168.

**Root-selected correction:** derive an existing `Receiver.keys(index)` native
key using first8 little-endian SHA256 bytes of
`KPX8EP01|D32|actual_reserve_point36|original_NF32|counter_u32LE`, starting at
counter0 and excluding reserved and known own invoice indices. Full effects
bind the actual payout SPK. The exact derivation and reconciliation distinction
are now documented in ADR0064/CONTRACT. The current `payout_spk()` source
implements that derivation and both exit stages use it, including destination
equality before proving. The selected controls cover seed rederivation,
funding/initial-key separation, changed reserve point and changed destination.

### H5: accepted GN3 admission must be a mandatory join

The JS SDK stage deliberately reports that it performs no GN3/native semantic
verification. The wallet history loader verifies initial public records and a
selected checkpoint; neither alone authenticates admission into the actual
selected native policy. A supplied history JSON cannot assert accepted backing.

**Integration owner agrees:** live history construction must consume the actual
accepted Full GN3 case, invoke `validate_accepted_genesis` under the selected
profile/domain/trial/tail, and join its exact records, State112, sum reserve and
founding point into history. Native Full and accepted/current-chain checks are
separate mandatory stages. Local rehearsal remains explicitly supplied-context.
The final source adapter `chain/replay.py` is now reviewed: strict GN3 admission
is mandatory at its start, its records/state/reserve/point join the history
builder, selected descriptor/tail match the actual native emitter, and every
recorded native case passes Full/all-input execution before the financial head
is compared with SDK discovery. Decimal RPC strings convert once at the boundary
into strict Python integer sompi. Its result explicitly remains a recorded
validating-node observation, not independent consensus or continuously current
authorization.

### H6: terminal scan needed payout-key and empty-wallet assertions

The initial scan exported completion without asserting that every owned claim
was spent, and its History object discarded the prior reserve-point/NF metadata
needed to rederive fresh payout keys after terminal state.

**Source correction observed:** History retains public exit point/NF/SPK plus
prefix delivery/session counts. Final reconciliation reconstructs the original
invoice-index exclusion set for each own historical exit, derives its fresh key
from the seed and matches the published payout SPK. Terminal scan refuses an
unspent owned claim and exports reconciliation booleans, never an owner-to-note/
payout map or per-owner claim count. Actual native payout acceptance/current
UTXO observation remains the separate chain stage. The selected control rederives
the historical payout with terminal point None and rejects a changed historical
payout SPK.

### H7: durable barriers require parent directory persistence

The initial `new_attempt()` created `attempts` and its numbered child without
fsyncing their newly created entries in the parents. Persisting a later barrier
file/attempt directory alone does not establish ancestor persistence.

**Source correction observed:** creation now syncs the owner after the initial
attempts directory and the attempts directory after each numbered child before
GUARD and later disclosure barriers. Existing `write_new` persists the file and
its immediate parent. This is source/order evidence, not a physical power-loss
experiment.

## Founding and namespace joins

Owner-local `bootstrap/sign_worker.py` is now inspected: it checks its immutable
INITIAL-PUBLIC record, exact selected GN3 row/admitted value and complete native
body/fee quote before reading its seed; then rederives invoice0/receipt and the
reserved funding key, checks the designated source script and signs that input
only. Its launcher stages one original BACKUP and INITIAL-PUBLIC leaf without
host content reads. The separate `bootstrap/paths.py` is present; a preceding
listing was captured before creation, not a final missing-import finding. The
bootstrap owner retained a successful clean-environment `--help` control.

The wallet launcher separates private source staging/plan/logs from its one
public export, mounts only its own owner/MPC parent and designated peer invoice
leaves, and authenticates public assets before the worker. Restore mounts one
original backup leaf read-only and imports no map. Source-02 additionally records
root-approved four-thread Rayon calls and exact requested payment amounts; the
selected tests reject oversized/wrongly typed requests and require exact amounts
without publishing them in READY. Financial/native/recovery verdicts remain
separate. These checks do not replace the genuine owner-local rehearsal or actual
accepted-chain confirmations.

## Review outcome

The reviewed source and retained synthetic controls support proceeding with the
genuine local owner/wallet integration under the selected contract. H1-H7 have
observed source dispositions; there is no outstanding finding in this scoped
review. Future source changes require comparison against the companion snapshot.
Control crypto/encryption/CVs/proofs are explicitly mocked and unfundable. No
cryptographic correctness, privacy, local genuine proof, native acceptance,
accepted backing or confirmed payout is established by this review.

Same-host administrator/software/setup/RPC trust, transparent initial note
records, public native payouts, known privacy limitations and separately
administered long-term availability remain outside this source-review result.
