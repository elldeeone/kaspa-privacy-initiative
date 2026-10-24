# Proposed stock sorting-network substitution

Source proposal for an ADR0063 amendment; no engine or private session has
run. Financial circuits, tuple520, fixed2,695-byte owner ingress, scalar
field, isolated owners and separate public-only coordinator stay unchanged.
Do not qualify the earlier `secure_shuffle` path as maliciously sound.

## Reason for changing the selected API

At pinned MP-SPDZ113c4e47, `SecureShuffle.hpp:379` inputs secret Waksman
configuration values. Its malicious check opens only the sum of
`b_j*(1-b_j)` and requires zero. The traced SPDZ→Hemi→Beaver→ProtocolBase
dot-product implementation sums these products without random weights.
`b0=2/5` and `b1=-1/5` are nonboolean but produce `6/25-6/25=0` in the
selected field. Exact source hashes and field arithmetic are retained in
`UPSTREAM-SHUFFLE-QUESTION-01.json`.

This is a source/algebra counterexample to that check, not an actual wire
injection, complete privacy exploit or financial acceptance result. The
independent source reviewer is checking whether any other path constrains
those inputs. Do not change the stock engine or silently weaken the threat
model. No upstream message or disclosure has been sent.

## Existing alternative and exact call path

Use standard random-key oblivious sorting, entirely inside the same
selected malicious arithmetic engine:

1. Input the same six complete17-limb rows and three canonical beta values.
2. Set the standard compiler's integer comparison width to128 using
   `program.set_bit_length(128)`. Exact compile/runtime prime remainsQ and
   command-line workspace-F249 is unchanged. Raw field inputs and tuple
   fields are never truncated to this comparison width.
3. Generate six secret independent128-bit keys with stock
   `sint.get_random_int(128)`. These are engine-generated, not values chosen
   or revealed by an uploader or coordinator. Prepend a key to each entire
   row to form a `6 x 18` secret matrix.
4. Compute all15 pairwise key equality bits with explicit128-bit bounds.
   Combine them inside the MPC into one collision Boolean. Reveal/check
   only that global Boolean; invoke stock `runtime_error_if` on collision.
   An explicit basic-block boundary follows this abort before any tuple
   opening. Collision means a fresh session, not public tie-breaking.
5. Call `matrix.sort(key_indices=(0,), batcher=True)`. This explicit flag
   dispatches directly to stock `library.loopy_odd_even_merge_sort`; it
   does not execute radix_sort, reveal_sort, quicksort or secure_shuffle.
   The fixed public compare/swap network sorts by the secret key and swaps
   all18 columns together. For six rows it ignores out-of-range swaps using
   public indices; no secret padding/position is opened.
6. Discard the key column without opening it. Checked-open only six entire
   mixed17-limb rows and the same aggregate beta. Never output a key,
   permutation, original index, per-owner beta or output/proof grouping.

Conditioned on distinct uniform keys, each of the6! orders has equal
probability. The predeclared collision probability is at most15/2^128,
below2^-124. This is the established random-priority sorting construction,
not a new masking protocol, random generator or cryptographic primitive.
No repeated-key selection/tuning after observing ownership is permitted.

## Source-grounded semantics

- `Compiler/types.py:2654` defines `get_random_int` according to the selected
  security model. With these fixed options it calls `comparison.PRandInt`
  at line354, composing128 stock secret BIT instructions.
- `Protocols/MascotPrep.h:114` selects its malicious live preparation;
  `MascotPrep.hpp:85` routes prime-field bits to existing
  `buffer_bits_from_squares` (`ReplicatedPrep.hpp:400`). The latter uses
  authenticated square pairs and masked square opening/root normalization.
  This does not accept an uploader's unconstrained private switch values.
  The stock MASCOT preprocessing/MAC/security assumptions remain required.
- `Compiler/program.py:684` documents `set_bit_length` as the comparison
  integer width. `sint.__gt__` (`types.py:2911`) uses the key difference with
  width129; keys are in[0,2^128), so its signed bound is sufficient. The
  known-prime comparison implementation remains stock and check-enabled.
- `Compiler/types.py:7805` explicitly routes `batcher=True` to
  `library.loopy_odd_even_merge_sort` (`library.py:833`). Its comparisons
  invoke `cond_swap` at line761, which compares only the designated key and
  applies the same secret Boolean swap to every row element. It does not
  open a comparison bit or call the rejected shuffle API.
- `library.py:234` conditionally crashes on the public collision Boolean.
  Only that one global condition is exposed; keys stay secret. Subsequent
  tuple opens are in a later basic block and the wrapper accepts only a
  fully successful engine exit with the complete result.

Source inspection and a successful honest run are not a proof that these
implementations are maliciously secure. Modified-peer and full privacy
qualification remain separate claims. No honest participant's final
SpendG16 can be replaced by MPC JSON, transport authority or coordinator
assertions. The existing final effects authorization and balance gates
remain mandatory.

## Minimal implementation and execution scope

After ADR amendment/source review, change only the selected MPC program and
its frozen hash plus the public backend-selection label. Reuse the same
engine47d9, image5616, compiler/dependency closure and Source03 isolation/
fixed-width/canonical/private-ingress controls. Do not build or patch C++.

Initially retain the same3.8CPU/3,616MiB total cap. Freeze actual session,
program/schedule/source, observer and stop rules before real MPC. Feed the
six genuine owner-generated tuples, then require actual same-session output
agreement, each owner's direct own-engine receipt, genuine final SpendG16
authorization and complete native acceptance. An opaque-byte fixture or
sum-only run cannot substitute for that integration.
