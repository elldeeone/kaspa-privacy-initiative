# Same-profile backup recovery and fallback design review

Design source: `settlement-wallet/DESIGN-01.md`, reviewed SHA256
`517bf864d5612d64cb2bfa702c15163fb6a6785f2b38ff97f377ccaa40f02d88`.
Decision: **ACK implementation**, with the explicit recovery and controls below.
This is a design review, not an executed owner proof or financial qualification.

The design joins the selected capacity child domain Dd55, manifest d6f0,
VK074c, PK6c518 and prover4ef to the actual W image633b/profile492a.
It does not relabel the completed old-D35 HTTPS recovery result. Only actual
outer transaction IDs become spend points; virtual child IDs describe the
proof transcript and never become independently accepted UTXOs.

Public replay precedes the seed and independently verifies the actual W body
and every subsequent direct exit with Native Full. Both private child proofs,
ordered NF insertions, CM append positions, ciphertext arrays, state and reserve
are derived from complete public bytes. The externally selected initial4B
state remains constructed, without a deposit, accepted backing or currentness.
Missing or unsupported history must remain incomplete.

One original backup must recover **all** recognized claims. Choosing two real
inputs is restricted to that same backup. Checked sums, distinct claims/NFs,
current CM membership, two sequential absence witnesses and exact noappend
cashout preserve the tested relation. Slot shuffling occurs before the ordered
NF witnesses and stays fixed during fee convergence. A continuing exit carries
the immutable W program and the reserve of every remaining claim; the child C
template cannot replace it. The full expected parameter READY precedes any
backup read, and quote/range/READY failures leave the witness pipe empty.

The root-selected payout rule keeps the established KPX3PAY message, minimum
physical-position anchor, rejection sampling and u32 retry. It skips a retry if
the destination equals **either consumed real input key**. A one-real exit is
compatible with the prior rule. Two-real recovery must reconstruct the exact
own co-consumed receipts from original NF matches and repeat that skip set;
the chosen retry can differ from the anchor-only rule on a collision. Unknown
NFs cannot identify other owned notes or distinguish a real row from a dummy.
Unavailable required receipts or an unmatched derived payout stay unresolved.
This is recovery of the bounded wallet default, not arbitrary destinations or
mixed-owner aggregation.

Clarification after the initial ACK: one owned NF match cannot identify hidden
real/dummy arity. The wallet may nevertheless derive the one-real candidate and
compare its public key to the **actual authorized payout SPK**. An exact match
establishes seed-controlled native payout-key recovery independently of arity;
it does not establish complete co-consumed-group reconstruction. A mismatch
stays unresolved. With both own receipts, the exact two-real skip set is
reconstructed. This preserves ordinary single-exit recovery without an operator
arity map or an assumption about an unknown NF.

Requested controls are a mocked collision against either input, both slot
permutations, one-real compatibility, exact recovered minimum anchor and payout
SPK, duplicate/foreign/spent inputs, integer/floor boundaries, ordered NF paths,
actual-versus-virtual history, W-versus-C continuation, and zero-write READY and
quote failures. The later phrase “unchanged default SPK” should refer instead to
the exact selected one/two-real retry policy. No exhaustive PRF collision search
is needed.

| Risk | Design obligation and remaining boundary |
| --- | --- |
| Inflation | Checked consumed sum; private balance; exact actual reserve and fee; noappend output witnesses zero. Actual code and proofs pending. |
| Double spending | Original NFs, current absence, both sequential inserts; replay exact actual W head. Fresh stale/occupied controls pending. |
| Unauthorized payout | Same-backup ownership, existing credentials, exact Auth/body destination and immutable W; no admin path. |
| Reserve release | Rprime=R−sum(consumed), P=sum(consumed)−fee; all other claims retain reserve. Complete four-note drain required. |
| Privacy | One invoice plus change remains publicly grouped; no anonymity or unlinked-payment claim. |
| Dependency loss | Backup plus retained public CF/history, selected software and public PK; full new-profile cold distribution is a separate gate. |
| Stale or reorganized state | Constructed supplied-context replay only; absent live accepted-current adapter cannot authorize a live spend. |
| Hidden trust | Trusted installation/host, selected setup, constructed initial state, recipient encryption and retained data remain explicit. |

Complete fees must include the outer action, **both owners’ incoming notes and
sender changes**, every exit and every final native payout. Constructed S0
cannot create an entry cost. Two same-backup two-real exits are an optimization
to prove; four single-claim exits remain the fallback. Neither the design nor
passing controls establishes cryptographic soundness, chain acceptance,
confirmed payouts, privacy thresholds or provider retention.
