# All supported values and reserve remainders

Arithmetic03's rows are exact integer costs for their declared contexts. Its
comment about the smallest other liability is shorthand for the continuous
envelope; a difference of floors need not itself be monotone. The separate
rational bound below supplies the missing integer-floor slack without changing
any prepared arithmetic03 fee, output or result.

Let K=10^12, V0=60M, selected fee f<50M, note V>=V0 and continuing reserve
r>=V0. Exact standard-p1 one-input storage is

`max(0,floor(K/(V-f))+floor(K/r)-floor(K/(V+r)))`.

For real x/y/z, `floor(x)+floor(y)-floor(z)<=ceil(x+y-z)`.
The continuous sum `K/(V-f)+K/r-K/(V+r)` decreases in both V and r on this
domain: each derivative is a negative reciprocal square plus a strictly
smaller positive one. Therefore every supported continuing context satisfies

`S <= ceil(K/(V0-f)+K/V0-K/(2V0))`.

For terminal R=V, the corresponding bound is
`S <= ceil(K/(V0-f)-K/V0)`.
Exact backing and a60M positive-note floor imply that a nonzero remainder is
at least60M. This is conditional on that invariant, not a way to discard old
10M/20M-liability failures or derive backing from a supplied UTXO.

The independent rational calculator checks these ceilings against the mass
already charged in every arithmetic03 profile. At16/24/32KiB, all100/200/500
fees cover the ceiling with no fee adjustment. Compute/transient domination
leaves ample floor slack. The old5,979-byte reveal-only profile is not promoted
to a real union or a universal500 fee; its exact minimum-remainder fee may need
integer-floor slack.49KiB remains a failed affordability profile.

This closes the stated storage/value envelope, not the new emitter, script-unit
budget, genuine private proof, accepted lineage, live fee market or full R8
qualification. [Calculator](storage_bound.py), [exact rows](storage-bound.json).
