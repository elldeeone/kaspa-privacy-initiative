# Compact whole-policy fee screen

The complete emitted program fits the2% **byte/mass feasibility screen** for
one already demanded32-recipient batch. Its projected complete fees are
**1.949145625%** at unchanged budget1600, or **1.967895625%** with a2200 payer
budget. Matching compact/wide circuits, genuine proof/native acceptance,
testnet payouts, useful financial privacy and full-capacity recovery remain
unqualified. No new setup, PK, private owner input, funding or RPC was used.

## What actually ran

1. A public Merkle-kernel comparison:8 exact NativeFull/all-engine accepts and
   48 isolation-PASS typed VerifyError rejects. N32 baseline→subtree:
   redeem50385→1862 bytes, payload17488→1456 bytes, units392747→19003.
   This kernel has no financial authorization, NF, ownership or G16 policy.
2. A public offline Rust build of a separate complete emitter. Its old-source
   snapshot exactly reproduces the sealed24417-byte original template. The new
   common framing and entire ADMIT/REVEAL branches match after only explicit
   domain/Auth-magic/selflength substitutions.
3. One whole-program native batch: **55/55 expected typed outcomes**. Eight
   cases reach the final G16 zero-proof serialization failure;47 malformed
   public bindings fail earlier with isolation PASS and exact VerifyError.
   **Zero financial acceptances.** No NativeVM repeats were needed.

The measured complete redeem is **23575 bytes**, including both VKs, all
branches, both native indexed-NF updates, successor self binding and framing.
The two VKs are valid public328-byte placeholders from older, unrelated
relations. They are not parameters for this new profile. Exact mode→VK routing
is source/operand checked; equal zero-proof failures cannot verify key roles.

| Private shape | Payload bytes | Observed zero-proof units | Native normalized mass |
| --- | ---: | ---: | ---: |
| Wide32 P0 | 12672 | 14969462 | 197017 |
| Compact2 P0 | 3920 | 14945794 | 188265 |
| Compact2 continuing payout | 3920 | 14945926 | 188677 |
| Compact terminal payout | 2848 | 14841244 | 187182 |

The abstract source upper bound explores every private branch with bounded
stack/context widths: **15008331 units**, below the1600 allowance16009999.
No lower budget is credited. Additive source analysis bounds retained ADMIT at
188357 units and REVEAL at304293, both below their unchanged200 allowance.
Those branch signatures were not newly executed. Their byte/transient costs
remain in the whole program and are separately priced in the cost output.

## Complete integer cost projection

For32 independent useful native payouts of1000000000 sompi each, every
recipient note prepays the same continuing fee18867700 sompi. The last owner
also pays that ceiling, explicitly overpaying the terminal minimum by149500
sompi. No fee reduction depends on learning the exit order.

At payer1600:

`42623726600 = 10000000000 ordinary change + 32000000000 native payouts + 623726600 fees + 0 reserve`

Fees include the conservative direct-entry charge258500 sompi, the wide payer
fee19701700 and32 independent owner fees18867700 each. Every intermediate
integer KIP9 storage mass is calculated and fits its mass ceiling. The projected
tree ends at physical CM count126 and NF count67, including31 initial skipped
empty slots and62 CM slots used by continuing exits. Entry2585 is the retained
conservative source charge, not a new accepted founding measurement.

The stress2200 payer adds6000000 sompi: total fees629726600. Both projections
use the actual emitted bytes and native mass formulas, not component-only
savings. Actual synthetic native cases offered50000000 sompi fees; the lower
lifecycle charges above are a checked projection, not funds paid on a network.

Two **separate-time** private payments with retained payer change still require
two payment proofs and three independently owned cashouts. Including entry and
the same exit ceiling gives **94514600 sompi / 2000000000 useful sompi =4.72573%**.
Payer change is returned but never counted as a useful payment. Faster proving
does not lower native verification fees. The prior two-recipient verifier-only
floor2.2125% and wider per-leaf optimistic failure2.099209% remain unchanged.

Retained transparent REVEAL fallback shapes price at52112/52006 normalized
byte/compute mass, and ADMIT with/without change at50982/50878, before any larger
amount-dependent storage charge. These are additional route costs, not private
fee alternatives; ADMIT adds a funding transaction and REVEAL discloses its note.

## Limits that remain

- The [obligation table](../../../../poc/compact-private-policy/OBLIGATIONS.md)
  distinguishes retained native checks from pending proof constraints. Native
  pairwise CM inequality is replaced by a pending N-way derived-CM distinctness
  proof obligation. Consistently rebound duplicate-CM controls reach G16.
- Empty skipped slots rely on the reachable-state suffix invariant. Fabricated
  occupied-gap controls intentionally violate it and reach G16; occupied-target
  controls violate it inside the authenticated block and reject earlier. See
  [the induction/capacity argument](EMPTY-SUFFIX-AND-CAPACITY-01.md).
- Native NF exclusion/insertion and current context binding remain intact.
  Future roles must share the original positioned real NF derivation so a note
  cannot be consumed once per role. Ownership, note conservation, exact private
  outputs, zero/dummy semantics and payout-key inequality need matched circuits.
- A full CM tree can still block a continuing private exit. No no-append mode
  with remaining reserve is implemented or counted as a fee saving.
- This projection requires32 genuine simultaneous demands. Dummies, extra
  identities, later arrivals and pooled owners' private witnesses cannot supply
  the denominator. Neither population privacy nor receipt validity was tested.

## Evidence and retained failures

Kernel result SHA256: `318a373ed571b07bf3127ccc650c016d892e7be478a3b206d09fcef6a6cee7a4`.
Whole native result: `9e6675f6f0482b86e62fc2d5968933a4ab7798a481f2c5ec0df1c6699e921d68`.
Complete cost output: `c4f7043c4f0cdd3c4509a3d93a02558b506e731aead243fc67a431f9db2d8d82`.

The whole batch ran network-off with only public code, SDK, ordinary read-only
emitter/native binaries and public VK operands mounted. Actual cgroup limits
were4CPU/4GiB/swap0. Harness wall time1.01s; systemd observed CPU1.834s and
memory peak182.4M. GNUtime measured the outer bwrap wrapper, so its2336KiB RSS
is not reported as application peak. Cleanup observed collected/not-found,
inactive/dead and MainPID0; unavailable kernel-process observation remains null.

The failed first kernel preparation/manager launch, superseded scalar envelope,
unexecuted first whole freeze, initial byte-normalizer omission and initial
postprocessor SPK-version charge error are retained. Fixes did not weaken policy
checks or rerun native batches. Earlier source snapshots and originals remain
byte-identical. [Next work](IMPLEMENTATION-NEXT-01.md) requires separate authority.
