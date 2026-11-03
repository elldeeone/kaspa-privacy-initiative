# Exact backing and small reserve tails

**Finding:** correctly initialized, accepted no-rent v6/S7 transitions preserve
exact note backing. If a future profile preserves that property and every
remaining positive liability is a note worth at least 60M sompi, a whole-note
exit leaves either zero reserve or at least 60M. This is a conditional state
invariant, not a reason to remove the frozen 10M/20M failures or abandon an
existing smaller obligation.

Source baseline: `8d7d719f18ae5975e651a4a114f8cecceb3e8b7c`; pinned native
`01b532e8b553523216471682649693af92f0fd16`. Source/arithmetic review only;
no new VM execution, private proof, accepted backing or migration result.

## Existing no-rent path: source facts and induction

Let R be the actual continuing reserve UTXO amount. Let L be the sum of **all**
unspent positive note values at their distinct positions, including undiscovered
or lost-key notes. Zero-valued dummy commitments contribute zero; equal records
at different positions are not silently collapsed. Let G = R − L.

| Transition | Actual reserve change | Complete note-liability change |
| --- | --- | --- |
| Bootstrap | Starts from the actual singleton reserve R; then subtracts payout p and fee f. | The unique position-zero input has value R; new notes sum to R − p − f. |
| ADMIT | `+ deposit − f`, with no payout. | New notes sum to `deposit − f`; no existing real note is consumed. |
| Ordinary SPEND, including allowed payout | `− p − f`. | Consumed note values equal new note values plus p plus f. |
| DRAIN | `− p − f`. | Consumed notes total p + f; no positive output note. |
| Paired zero-payout SPEND | `− (f0 + f1)`. | The two genuine private relations conserve value; disjoint/current-unspent NFs exclude double consumption, so the same fee sum leaves L. |

Thus every transition preserves G. Initialization establishes G = 0; induction
then gives R = L. This depends on proof soundness, coherent CM/history/current-NF
state, exact native successor/value checks and the authentic initialized
lineage. It is not a new audit conclusion or a property of arbitrary supplied
roots.

Load-bearing source:

- [`two_input/circuit.rs:223`](../../../poc/shared-pool/src/two_input/circuit.rs#L223)
  bounds every positive output by `NOTE_FLOOR = 60_000_000`; real inputs have
  the same floor. Lines 255–274 enforce integer-bounded value conservation and
  bootstrap input value. The minimum native payout is a different 10M bound.
- [`two_input/covenant.rs:459`](../../../poc/shared-pool/src/two_input/covenant.rs#L459)
  binds the initial sole-note state, empty NF set and initial history, and checks
  actual reserve amount against the proved bootstrap value.
- [`two_input/mod.rs:175`](../../../poc/shared-pool/src/two_input/mod.rs#L175)
  and its native covenant bind admission funding exactly and compute
  `R' = R + deposit − p − f`, with exact outputs and no extra reserve input.
- [`s7_lifecycle/native.rs`](../../../poc/shared-pool/src/s7_lifecycle/native.rs)
  preserves these ordinary/initialization checks; `paired_settle` and its native
  body require one continuing reserve, exact aggregate fees and the selected
  state-aware outer proof. The
  [state core](../../../poc/s7-owner-lifecycle/state/src/lib.rs) alone accepts
  declared contexts and does **not** establish their genesis/backing. Neither
  its journal nor a supplied-UTXO Full pass substitutes for the induction.

These no-rent branches have no pending-withdrawal root, user rent balance or
refundable credit bucket. Founding-input change and its fee are outside the
reserved note principal. That statement does not cover every experiment in
this repository, especially vProgs permission rent.

## What the tail argument establishes

For a supported whole-note exit consuming V, with `V = payout + fee`:

```text
R' = R − V = L − V = sum(all remaining positive note values)
remaining notes empty  => R' = 0
remaining notes nonempty, each >= 60M => R' >= 60M
```

This applies to every exit ordering under those assumptions. A 10M native
payout is paid outside the reserve; it is not a new 10M shielded note. Authorized
fees leave reserve and liabilities together, rather than accumulating as an
unaccounted reserve tail. Ordinary partial payout must still create only zero
or at-least-60M private change.

For terminal R = V alone, the weaker complete I-1 already suffices:
`V <= L <= R = V` implies no other liability. The stronger exact-backing/floor
condition is what excludes a small **positive continuing** remainder.

The existing I-1 is only `complete liabilities <= reserve`. It does **not**
imply the stronger premise. For example, a 60M note plus 20M unassigned surplus
can satisfy I-1 with R = 80M and leave a 20M surplus after that note exits.
Nor does exact backing alone imply the floor: a fully backed unpaid 20M claim
or refundable credit is a real liability even though it is not a 60M note.

The frozen public
[candidate-C source-03](future-exit/source-03/src/main.rs#L630), SHA256
`29f4d40c0e9457fb541411ad5b92beed3b357c2e0e8e9b4de8816686a3691bf8`,
constructs its continuing 20M/10M cases
with an additional unspent note opening of precisely that value. Those are
genuine supplied-context resource boundaries but violate the proposed
all-positive-notes-at-least-60M condition. Their original native/mass results,
labels and failure outcomes must remain unchanged. Classify this condition
separately; do not retroactively claim those cases passed. The high-index
supplied fixture also does not by itself establish exact accepted backing.

## Donation, pending claims and refunds

An existing UTXO's amount cannot be changed by someone sending to its script.
Another payment creates a distinct outpoint. It is not automatically added to
the canonical continuing reserve. The existing ordinary branch admits an extra
input only as an explicitly bound/proved ADMIT deposit; its note outputs and
fee account for that deposit. The one-input paired branch has no top-up path.
An arbitrary copy of an advanced state script funded at a new outpoint is not
evidence of membership in the authentic pool lineage.

A future donation/merge path would need explicit rules for any resulting
surplus. It cannot quietly identify surplus with a user's note, burn a credit,
or add an administrator's withdrawal right. Keeping unrelated donations in
separate outpoints preserves the exact-reserve equation only if they truly
carry no user entitlement and are not counted as backing.

For a more general design, write the complete equation explicitly:

```text
B = L_notes + L_unpaid_claims + C_refundable_user_credits + S_surplus
```

Dedicated ticket backing may be in separate UTXOs, so B need not equal the one
shared reserve's R. Pending claims remain liabilities until paid. Reducing a
60M note by a 40M authorization fee can create a legitimate 20M pending claim;
the note floor does not outlaw it. Refundable rent of any size belongs in C,
not free surplus or an invisible sponsor fee. Such obligations need their own
costed payout/UTXO treatment; their existence defeats the simple reserve-tail
theorem. The
[complete-obligations review](EXIT-OBLIGATIONS-REVIEW.md#conservation-invariants)
and [permission-rent source review](PRIMARY-SOURCE-OPTIONS.md) keep those buckets
separate.

## Candidate condition and limits

A separately versioned **note-only, no-rent/no-pending-credit profile** may
propose `R = L_notes` plus the existing 60M positive-note floor. It must establish
exact genesis backing and preserve both conditions in every accepted branch,
including private admission/transfer, revealing exits and any future migration.
The native reveal can check exact V/payout/fee/reserve conservation; it cannot
learn the global hidden L from a single opening. The complete private circuit
and authenticated lineage provide the missing inductive premise. Merely adding
`R' == 0 || R' >= 60M` checks a balance range, not complete backing or the
absence of small obligations.

This condition does not change today's I-1, the 60M minimum recoverable claim,
the 10M payout floor, or the unchanged fee/privacy targets. It cannot erase old
supported sub-60M pending claims/refunds, change existing immutable covenants,
or rescue an economically stranded historical liability. Migration must retain
each obligation and its owner authority, or leave it in the old supported lane.

The condition removes one specific small-*reserve-remainder* case from a
prospective reachable note-only state space. It does not establish that every
60M note can pay the actual native full mass at rate 500, that a larger combined
script fits, or that the complete lifecycle meets R8. Those remain measured
economic gates, with all frozen failures retained.
