# Empty gaps and capacity: exact premise of this screen

The new emitter reuses the existing depth16 SHA256 CM tree and indexed NF tree.
It changes the CM authentication schedule, not the hash or NF construction.
This argument assumes a valid initial singleton root and every predecessor
transition accepted under the intended complete new relation. The zero-proof
experiment does not establish that relation.

Let `n` be the next physical CM index. Initially, all positions at or above `n`
are canonical empty. Preserve that suffix as follows:

1. ADMIT authenticates empty position `n`, writes it and sets `n'=n+1`.
2. Compact/wide mode chooses `s=ceil(n/N)*N`, authenticates the complete empty
   block `[s,s+N)`, writes the ordered array and sets `n'=s+N`.
   The skipped `[n,s)` positions are empty by the prior suffix invariant.
3. Terminal mode and REVEAL carry the CM root and `n`.

Thus every reachable successor retains an empty suffix starting at its new `n`.
The native subtree check alone does **not** reject an arbitrarily supplied old
root that hides an occupied position in `[n,s)`. The deliberately fabricated
gap cases reach G16. The occupied-target cases fabricate the same prior-invariant
violation inside the authenticated block and correctly reject earlier. Neither
case demonstrates that arbitrary old state is a valid pool state.

All counts include physical gaps. The N32 projected lifecycle starts at `n=1`,
skips31 empty slots, writes32 outputs and reaches `n=64`. Its31 continuing
two-output exits consume62 more slots. The terminal exit carries `n=126`.
NF count starts at1, rises by2 for the payer and every owner exit, and ends at67.
No capacity discount is taken for a zero-valued output or empty gap.

One useful *conditional* NF-capacity invariant is
`m + 2*u <= 2*n + 1`, where `u` is the count of positive unspent notes.
Genesis has `(n,m,u)=(1,1,1)`. ADMIT increments both `n` and `u` by1.
For a private N-output step, at least one positive input is consumed and at most
N positive outputs are created, so the left side increases by at most`2*N`;
`n` increases by at least N. Terminal private consumption cannot increase the
left side. REVEAL decreases it by1. These claims require the pending proofs to
enforce real/dummy inputs, positive values and exact output arity/conservation.

If those premises hold, one outstanding positive note implies room for two
more NFs whenever `n<=65535`. This does **not** solve CM capacity: the current
continuing compact exit still needs an aligned two-slot block. A pool can reach
its CM limit while reserve and outstanding claims remain. The proposed
no-append-with-reserve mode requires a separately selected relation and privacy
analysis; it is not emitted here and is not used to meet the fee target.

Wallets/replay must reconstruct sparse physical positions from the accepted
mode/start/count. The old contiguous-append snapshot cannot be reused by
assertion. Missing receipt/history data or a stale current head must halt an
actual client. None of the native-only fixtures establishes network availability,
header validity, parameter honesty or private receipt delivery.
