# Private exit proof: prospective implementation and measurement plan

Status: the separate unfunded ActionCircuit is implemented under ADR-0050. Its
frozen full-relation controls completed with 8 SAT and 41 UNSAT results. One fresh
resident-key setup and five distinct genuine proofs have completed with checked
verification under the same VK. Native validation and chain backing are separate.

## Reuse and change

Reuse the existing note, separated s/k ownership, positioned original HMAC NF,
two real/dummy input slots, two private output slots, current raw-CM membership,
integer-slack bounds and checked Groth16 framing. The selected-HMAC source has
3,199,529 measured constraints and uses established exact SHA/HMAC identities;
its changed matrices cannot load an older PK. Original sources, keys, funded
instances and retained measurements remain untouched.

The candidate follows the public value-balance separation studied in
[Orchard](../../../zcash-orchard.md): public movement out of the shielded
domain is an additional term in conservation, not publication of the spent note.
The [Aztec comparison](../../../aztec.md) likewise separates proof-authorized
withdrawal from data discovery and exit liveness. Neither protocol's security
result transfers to this implementation.

ADR-0050 selects a unified private action and Auth528:

- Existing Auth484 prefix under a new action magic.
- Public payout P as u64LE at484.
- Exact version-zero P2PK script-public-key36 at492.
- Public input remains SHA256(Auth528) split into two unsigned LE128 Fr limbs.
- P=0 requires the 36-byte destination to be zero and no external payout.
- P>0 requires the exact canonical P2PK format, minimum payout and exact native
  destination/value binding. It also requires payoutPK to differ from each real
  input note's emergency key. This guards only exact consumed-key reuse, not
  global freshness, randomness or control. Wallet key validity/control remains
  a separate responsibility; format checks alone do not prove a secp256k1 point
  is spendable.

The central equations are:

```text
0 < sum(real private inputs) <= reserve <= MAX
sum(real private inputs) = sum(private outputs) + P + fee <= MAX
reserve_after = reserve - P - fee
```

Nonterminal reserve_after is at least60M. It preserves two CM appends, two NF
insertions and existing canonical padding. P=0 requires at least one positive
private output; P>0 permits zero, one or two positive private outputs.

Terminal reserve_after=0 requires P>0; both complete output Note168 values,
Auth output CMs, ciphertext528 and CM-append witness1024 are zero. No CM append
occurs: n and CM root remain unchanged. Two NF insertions still occur, m+=2.
This avoids forcing a revealing exit at full CM capacity. Under exact backing,
the equations force all remaining positive reserve value to be authorized by
the consumed input notes. The ordinary/native transition still authenticates
all current NF updates, exact actual outpoint/reserve and immutable policy.

## Positive scenarios

1. P=0 ordinary two-input private payment with two private outputs.
2. One-real-plus-dummy private exit with a positive change note.
3. Full owned-note exit with no private change while another owner's reserve
   remains; the two appended output records are canonical nonterminal dummies.
4. Terminal private exit consuming the complete reserve, without phantom CM
   appends, including a near-capacity current count.

The circuit remains fixed-shape across these modes. The new Auth adds one SHA
compression block relative to Auth484; the actual full constraint count/domain,
memory and proving cost must be measured rather than extrapolated.

## Required negative and replay evidence

Full R1CS controls must cover wrong s, wrong k, copied k without s, malformed
dummy/real fields, wrong current CM root/path/position, duplicate real positions,
incorrect NF, zero/duplicate public NF, wrong D, invalid counts, out-of-range and
overflowing sums, fee/reserve mismatch, output-CM mismatch, payout conservation,
P=0 with nonzero destination, P>0 with malformed or reused input-key destination,
and each forbidden
terminal output/CM/cipher/state/count combination. Input, output, payout and
remaining-reserve boundaries are tested independently. The previous17 full
optimized-transfer negatives were not executed; prior gadget KATs do not replace
new full-relation controls.

Several checks deliberately belong at a different seam:

- A valid alternative destination is a valid *new owner-authorized statement*.
  Reusing the original proof for it must reject; a fresh proof need not be
  unsatisfied merely because the owner chose another destination.
- A different actual outpoint is bound by the public statement and checked
  against the native consumed outpoint. Circuit-only proof of accepted ancestry
  is not claimed.
- An occupied original NF can satisfy the private ownership relation. Actual
  native current-NF insertion must reject it, including both spend/exit orders.
- Correct encryption is not proved by the circuit. Ciphertext binding and strict
  recipient recovery remain separate; terminal cipher bytes are canonical zero.

Freeze genuine proof replay controls for changed destination/value/fee/domain/
outpoint and current native context after the source and fixture review.

## Resource and evidence order

Build the separate package with4 CPU /6 GiB, no network/PK/old matrix mount.
Cheap parser/hash/wire controls and one frozen complete sizing/SAT run at2 CPU
/4 GiB have completed. Full controls used up to10 concurrent1-CPU cases, each
at2 GiB with zero swap and no network. The relation has3,231,025 constraints,
3,195,131 witness variables and3 public instances including the constant. Only
after review may one fresh
development setup and genuine proof use up to14 CPU /18 GiB, swap0. Keep the
fresh PK resident or serialize official uncompressed bytes directly; never pay
for a needless compressed-key reload. Record whole and phase resources and stop
all owned units. Keys/executables remain outside Git, with public hashes only.

## Limits and fee frontier

Private proof exit removes the direct public note-opening channel; it does not
hide native payout amounts or ensure financial privacy under singleton activity,
known receipts, arithmetic constraints, later revealing fallback or full drainage.
Those attacks belong in the separately frozen observer experiment.

At reference100, the direct verifier floor is147,500 mass. Even amortizing one
payment proof over two useful10-KAS payments gives73,750 mass per payment; one
independent private exit adds147,500. The combined floor is221,250 mass, or
22,125,000 sompi, already above the20,000,000 complete-lifecycle target before
funding, admission, payload, storage or service costs. This is a necessary
low-end fee failure for that route, not an actual new body measurement. New
privacy cannot be reported as a complete fee qualification.
