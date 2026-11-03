# Joint public-CV leakage with a corrupt P1 and owner 1

Date: 2026-10-29  
Repository baseline: `b58de1a182347c4223ebe84f92bb0bdd6c88d003`  
Status: source analysis only; **no source assumption is selected by this note**

## Decision

The three public input CVs, six public output CVs, total fee, and public
`Delta` must be modeled as **one correlated Pedersen transcript**. They are not
nine independently hiding fields.

The transcript directly reveals and permits checking exactly this aggregate
equation:

```text
sum(I[0..3]) - sum(O[0..6]) - total_fee * V = Delta * R
```

For the two honest owners after owner 1 is corrupted, the same equation remains
after subtracting owner 1's known input, two outputs, fee, and blinding
difference. It is invariant under every relabeling or regrouping of the two
honest inputs and four honest outputs. Therefore this public algebra alone does
not prune an honest-owner mapping candidate.

A full individual owner delta would change that conclusion: with a known
per-owner fee, it gives an exact candidate-pair test. P1's captured **local
authenticated shares and MAC shares** of the delta bits are not a full delta.
Treating the complete P1 view as hiding those bits requires the exact joint
MASCOT plus DDNNT source assumption; that composition is presently unselected.

## Exact selected algebra

The pinned value-commitment implementation is over the prime-order Baby-Jubjub
subgroup and computes

```text
CV(v, b) = v * V + b * R.
```

The exact generator transcript, canonical point/scalar decoding, and
commitment are in
[`relation/src/cv.rs:17-30,41-78,107-157`](../poc/local-private-payment/relation/src/cv.rs).
The source SHA-256 is
`350153426d8ff86905a7956a76311726812151bbe301b319ee254336b33c2f05`.
The implementation uses Arkworks Pedersen; the pinned upstream implementation
is [`ark-crypto-primitives` at `ba00127b...`](https://github.com/arkworks-rs/crypto-primitives/blob/ba00127bf673d93d73a3e8bf969cb9eeced20d12/crypto-primitives/src/commitment/pedersen/mod.rs#L39-L105).

For owner `i`, let:

```text
I_i       = CV(v_i, b_i)
O_i,0     = CV(y_i,0, r_i,0)
O_i,1     = CV(y_i,1, r_i,1)
f_i       = the owner's private fee
delta_i   = b_i - r_i,0 - r_i,1 mod q.
```

The selected circuit enforces both

```text
v_i = y_i,0 + y_i,1 + f_i
I_i - O_i,0 - O_i,1 = f_i * V + delta_i * R.
```

See the selected baseline
[`private-batch-relation/src/circuit.rs:175-216`](https://github.com/olafweller/kaspa-privacy-initiative/blob/b58de1a182347c4223ebe84f92bb0bdd6c88d003/poc/local-private-payment/private-batch-relation/src/circuit.rs#L175-L216).
The current worktree only adds layout-column identities around this code; it
does not change these equations.

The joint constructor computes canonical

```text
Delta = (delta_0 + delta_1 + delta_2) mod q
```

with an exact quotient in `{0,1,2}`, sorts the three `(NF,CV)` rows by NF,
randomly permutes the six output rows, and emits the public effect bytes. See
[`joint_trace.rs:253-343`](../poc/local-private-payment/private-batch-relation/src/joint_trace.rs)
and the independent exact circuit equality in
[`gadgets.rs:75-95`](../poc/local-private-payment/private-batch-relation/src/gadgets.rs).
The native public validator checks the resulting group equation at
[`cv.rs:160-178`](../poc/local-private-payment/relation/src/cv.rs) and calls it
from
[`wire.rs:282-291`](../poc/local-private-payment/private-batch-relation/src/wire.rs).

## Exact public bytes and direct model coverage

All offsets below are relative to the 10,492-byte effect body after the
193-byte projection prefix:

| Field | Body offsets | Count/width |
|---|---:|---:|
| total fee | `364..372` | one `u64le` |
| public `Delta` | `372..404` | one canonical 32-byte scalar |
| input CV `i` | `436 + 96*i .. 500 + 96*i` | three 64-byte points |
| output CV `j` | `724 + 520*j .. 788 + 520*j` | six 64-byte points |

These positions follow
[`wire.rs:95-122`](../poc/local-private-payment/private-batch-relation/src/wire.rs)
and
[`privacy_capture_model.py:594-625`](../poc/local-private-payment/private_batch_trial/privacy_capture_model.py).
At the start of this audit, the public-projection ledger inventoried CM, fee,
proof, raw bytes, and shape but did not name the nine CVs or `Delta`, and its
parser did not perform the canonical subgroup/scalar and aggregate-balance
checks above. That direct coverage gap has since been implemented in
`privacy_capture_model.py`: all nine CVs, `Delta`, total fee, canonical
Baby-Jubjub decoding/subgroup membership, and the aggregate group equation are
validated and represented as one joint field family:

```text
effect.value_commitment_balance = {
    input_cv[3], output_cv[6], total_fee, Delta,
    canonical_subgroup_decoding,
    exact_aggregate_equation
}
```

The complete current-tree model suite is now 29/29 green, including the exact
102-lane/10,685-byte projection manifest, canonical CV/subgroup mutations, and
aggregate-balance mutations. This establishes a valid public transcript
equation and exact direct inventory only. It is not an actual-run admission
receipt, a selected hiding assumption, or an owner-mapping result. Its
candidate-pruning count is zero unless another authenticated source supplies
an individual opening or delta.

## What owner 1 learns

Owner 1 knows its input value/blind, two created output values/blinds, fee, and
therefore `delta_1`. It can subtract its row from the public equation:

```text
I_h0 + I_h2 - (O_h0,0 + O_h0,1 + O_h2,0 + O_h2,1)
  - (total_fee - f_1) * V
= (Delta - delta_1) * R.
```

This is a sum over both honest owners. It is unchanged by swapping the two
honest input labels, swapping their output pairs, or repartitioning the four
honest output points into two pairs. It therefore supplies no honest-owner
edge by itself. Owner 1's own exact input/output rows and a decrypted incoming
receipt remain ordinary colluder-known constraints and must be applied
directly; Pedersen hiding does not erase them.

## Joint hiding statement, and its boundary

Assume each honest input blind and each of its two output blinds is sampled
independently and uniformly in `F_q`. Conditional on a fixed public `Delta`,
the honest blinding vector is uniform on one affine hyperplane. Replacing each
blind `b_j` by `b_j + t*v_j`, where mathematically `V=tR`, is a bijection.
Consequently the joint CV vector is uniform over point vectors satisfying the
one public aggregate equation and is independent of every honest value vector
with the same public aggregate balance.

This is the correct joint perfect-hiding argument. It does **not** require the
discrete logarithm between `V` and `R` to be unknown. Discrete-log hardness and
absence of a known generator relation are instead required for computational
**binding**. The implementation's deterministic generator transcript proves
neither property.

The selected owner path calls `secrets.randbelow(q)` separately for both new
output blinds
([`output_producer.py:105-125`](../poc/local-private-payment/private_batch_trial/output_producer.py))
and again rerandomizes the consumed input CV
([`lifecycle_worker.py:127-160`](../poc/local-private-payment/private_batch_trial/lifecycle_worker.py)).
Those calls are source evidence for the intended distribution, not proof of OS
entropy, independence, erasure, or fresh retry behavior.

The narrow source assumption that could cover the **public CV transcript** is:

> For the exact pinned Baby-Jubjub subgroup, canonical encodings, generator
> transcript, and selected relation, every honest owner's three blinds are
> independent uniform field elements, remain secret in the frozen auxiliary
> view, and are never reused across owners, fields, rounds, failures, or
> retries. The nine-CV transcript leaks the exact aggregate equation above and
> no additional value or partition information. Binding additionally assumes
> discrete-log hardness and no known relation between `V` and `R`.

That statement is still conditional on the aggregate and six Output proofs
being sound for the exact relation and statements. It does not cover P1's MPC
view.

## P1's delta-bit view

The owner-local relation represents each private `delta_i` as 256 canonical
bits and includes those columns in the owner input vector
([`lib.rs:69-78`](../poc/local-private-payment/private-batch-relation/src/lib.rs),
[`circuit.rs:218-247`](../poc/local-private-payment/private-batch-relation/src/circuit.rs)).
The selected P1 capture records:

- DDNNT `s,r,w,v,u` local value shares and authenticated share/MAC lanes;
- the common owner offset `d=x-s`;
- the derived authenticated owner inputs at scalar-capture site 6;
- the later authenticated scalar operations, field openings, MAC-key share,
  and peer transport.

See
[`owner_inputs_active.cpp:110-199`](../poc/local-private-payment/mpc-prover/owner_inputs_active.cpp)
and the selected finite callsite manifest at
[`p1_scalar_capture_manifest.hpp:13-40,60-106`](../poc/local-private-payment/mpc-prover/p1_scalar_capture_manifest.hpp).

A single local share is not an individual `delta_i`. However, the captured
share, MAC, preprocessing, offsets, openings, and peer messages must be treated
as one corrupt-party protocol view. Their joint independence from honest delta
bits is covered only if the exact MASCOT/OT composition and DDNNT client-input
mapping apply. DDNNT Section 3.1 and Lemma 1 supplies the five-value client
delivery simulator, while MASCOT supplies the authenticated arithmetic
security argument; neither paper alone proves the exact
`SimplestOT_C -> SoftSpoken -> MASCOT -> DDNNT -> local circuit` composition.
See [DDNNT, Section 3.1, Figures 1-2 and Lemma 1](https://eprint.iacr.org/2015/1006)
and [MASCOT](https://eprint.iacr.org/2016/505).

Therefore:

- the literal local share/MAC bytes are observed P1 state;
- their nonliteral implication for `delta_i` is a candidate `A1+A2` source
  assumption only;
- the assumption is presently **unselected**;
- active P1 deviations, chosen aborts, modified binaries, internal OT/PRNG
  tape, and physical-host leakage remain unqualified.

Known owner-1 masks do not justify reusing honest-owner masks. Every DDNNT
tuple and authenticated mask must be fresh and independent per field, owner,
attempt, and retry. Otherwise C1's known input can expose preprocessing
relations that the joint simulation assumes absent.

## Exact candidate attack if an individual delta escapes

If a source provides a full `delta_i` and the corresponding `f_i` (or a small
enumerable fee set), each candidate input slot `a` and output pair `{b,c}` can
be tested without opening any CV:

```text
D(a,b,c,i) = I_a - O_b - O_c - f_i * V
accept candidate iff D(a,b,c,i) == delta_i * R.
```

Positive matches must prune the candidate lattice; zero or multiple matches
retain ambiguity. A full individual delta is therefore mapping-dependent
leakage, not merely a forbidden-export counter. If only `Delta` and
`delta_1` are known, the analogous honest aggregate test is identical for all
honest partitions and must not manufacture candidate evidence.

The same rule applies to an exposed input/output permutation bit, complete
honest blind opening, or an authenticated source that binds one CV to a known
owner/value. Those are direct constraints. They cannot be replaced by a
generic Pedersen assumption.

## Retry and metadata limits

Each fresh attempt must regenerate all six honest blinds, the rerandomized
honest input blinds, every DDNNT tuple, owner offset, authenticated share, and
proof mask. A failed attempt may not resume a poisoned context or reuse a
partially emitted projection. Public-CV equality, `Delta` equality, partial
tails, abort phase, retry count, timing, frame length, direction, peer, fork,
and ordering remain explicit empirical leakage.

The joint hiding argument says nothing about those fields. A source assumption
must not mark them harmless; the frozen actual-view observer must apply their
real candidate constraints or retain them as unmodeled.

## Ledger disposition

| Field or implication | Honest disposition now |
|---|---|
| Nine canonical CV bytes + `Delta` + total fee + aggregate group equation | Direct joint constraint implemented after the audit-start gap; complete current-tree model suite 29/29 green, but no actual-run admission receipt yet |
| Public equation's effect on owner assignment | Zero candidate pruning by itself; partition invariant |
| C1's own CV rows, values, blinds, fee, and `delta_1` | Direct corrupt auxiliary input |
| Full honest `delta_i` or full honest blind/opening | Mapping-dependent direct constraint using the candidate equation above |
| P1 local share/MAC/offset/preprocessing view of honest delta bits | Candidate `A1-MASCOT-OT-COMPOSITION + A2-DDNNT-5N`; unselected |
| Joint CV hiding | Candidate narrow fresh-uniform-blind statement; do not split per CV |
| CV binding and unique-opening implications | Candidate discrete-log/unknown-generator-relation plus exact proof-soundness statement |
| Timing, order, shape, abort/retry/partial transcript | Empirical leakage; never covered by the CV or MASCOT theorem label |
| Modified active host, random tape, physical host, covert channels | Unqualified boundary |

No privacy gate can close the nine CVs by merely hashing them, checking that
they changed, or attaching a generic commitment label. It must first record the
joint direct equation and then either (a) apply every available
mapping-dependent opening/delta constraint, or (b) select the narrow joint
fresh-blind and P1-view assumptions with their exact applicability conditions.
