# Independent capacity design review

Reviewed against base `5aaf99532d87`, the new [exit design](../exits/DESIGN.md),
and actual original private/ADMIT/REVEAL policy and circuit branches. Design ACK
for a **new instance/domain/relation/VK**; this is not implementation acceptance.
Existing selected parameters and instances retain their original semantics.

## Independent accounting

Let `n` be the physical CM cursor, `m` the NF entry count including sentinel,
and `U` the semantic number of unspent positive Notes. `U` is neither a new
public field nor a count of humans. The inductive invariant is:

`m + 2U <= 2n + 1`.

- Strict singleton genesis gives `(n,m,U)=(1,1,1)`.
- ADMIT advances `n` by one, carries `m`, and creates one positive Note.
- Private append consumes `r>=1` positive real Notes, inserts two NFs, creates
  `k<=arity` positive Notes, and advances `n` by at least `arity`. Its left-side
  increase is `2-2r+2k <= 2k <= 2*delta_n`.
- No-append private cashout consumes `r>=1`, inserts two NFs and creates no
  Note. Its left-side change is `2-2r<=0`.
- REVEAL consumes one positive Note and inserts one NF; the left side drops one.

These cover the actual original dispatch. Native ADMIT checks a positive value,
single CM append and unchanged NF state (`policy.rs:641`). Native REVEAL checks
positive value, positioned CM membership, original real NF derivation and current
absence/insertion (`policy.rs:423`). The private circuit explicitly requires at
least one real input and positive real-input values (`circuit.rs:356`), distinct
real positions and original shared NFs. No action may create NF entries while
consuming zero positive Notes without invalidating this argument.

Therefore `n<=65535` implies `m+2U<=131071`. While `U>=1`, every full-note
private exit has its two required NF slots. Sparse alignment gaps, zero output
slots and dummy NFs are already included conservatively. Maximum inserted NF
index is `131070`; the existing count bound leaves index `131071` unused.
No NF reservation field, owner map, witness aggregation, deletion or eviction is
needed under these premises. Counts alone do not authenticate arbitrary roots.

## Mandatory implementation boundaries

1. Separate `no_append=(mode==0)` from `terminal=(Rprime==0)` throughout circuit,
   parser/host checks, native policy, normalization and wallet preparation.
   Require terminal implies no-append; require no-append has a positive payout.
   Wide32 remains append-only/P0.
2. No-append fixes every output Note byte including rho to zero, carries the
   exact CM root/cursor, and uses canonical zero metadata/list digest/start and
   SHA256 of the existing zero ciphertext container. Original Auth528 hashing,
   positioned real NFs, actual-slot dummy NFs, current absence and two sequential
   inserts remain mandatory.
3. Remaining native backing chooses continuation independently of CM mode.
   `Rprime>0` must preserve the exact immutable program tail and remaining
   reserve; `Rprime==0` is terminal. Full-input conservation, payout destination,
   maximum reserve, integer ranges and complete actual fees remain bound.

The supplied `(65535,131067,U=2)` prestate and two exits reaching NF count
`131071` are decisive boundary fixtures. They do not establish a fully replayed,
accepted history reaching capacity. Direct-CS positives/negatives and genuine
proof plus Native Full checks remain required before an implementation ACK.

## Limits and remaining risks

The argument assumes strict valid genesis/history, sound proofs, shared real-NF
single spending, collision resistance/PRF behavior and available public data.
It reserves space for full-note cashout, not partial withdrawal/change at a full
CM tree. It does not pay fees or ensure inclusion; a Note still needs enough
value for the then-current fee and payout floor. Mode visibility leaks whether
an action creates change. Recipient delivery/I-14, stale/reorg reconciliation,
parameter availability and software authority remain separate obligations.

The independent [finite screen](capacity_induction.py) checks an overapproximation
of each transition class and calibrated counterexamples to all-dummy private
actions, zero-value REVEAL and admission without a CM slot. Its result is only
counter-accounting evidence, not cryptographic or accepted-chain proof.
