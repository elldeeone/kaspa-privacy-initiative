# RFC-0011: Two-input payments, private change and partial withdrawals

**Status:** Open — documentation proposal only; no implementation or new results.
**Date:** 2026-10-20 (Australia/Sydney).
**Branch / inspected baseline:** `shared-pool-four-wallet` / `228e5d0`.
**Scope decision:** [ADR-0024](../adr/0024-two-input-private-payment-scope.md).
**Observer and adversarial review:** [review](../../poc/shared-pool/TWO-INPUT-PRIVACY-REVIEW.md).

## Decision to investigate

Retain direct native covenant settlement and reusable private authorization.
Replace the compact candidate's one-input, split-only relation with **up to two
private inputs and two private outputs**, hiding unused slots on the normal
path. Support varied payments, private change, merging two receipts and partial
native withdrawals. Keep a separate, independently executable full-note exit.

This addresses a restriction of our application, not an identified restriction
of Kaspa L1. No token, privileged withdrawal key, required relayer, vProgs
runtime or consensus change is proposed. It is not a claim of strong privacy.

**H13, proposed mechanical hypothesis:** within the declared fee, capacity and
public-data assumptions, two owned notes can fund a varied payment and private
change; a later partial withdrawal can leave spendable private change; and every
positive note can independently exit. A saved fallback for an unrelated unspent
note must remain usable with identical private proof/authorization after these
operations and new deposits, using only rebuilt public settlement witnesses.
Normal and fallback authorizations must never spend the same note twice.

The separate privacy question is whether the new public constraints leave useful
ambiguity under varied, interleaved activity and eventual withdrawals. H13's
mechanics alone cannot answer it. Neither H11/H12 percentages nor their
single-parent observer can be carried over as measurements of this relation.

## What exists, and what would change

| Property | Existing compact v5 pool / v4 relation | This proposal |
| --- | --- | --- |
| Private spending | One real input; transfer creates two positive notes | One or two real inputs; two padded output slots |
| Withdrawal | Whole input note; no private change | Normal withdrawal may retain private change; full-exit fallback remains |
| Independent admission | Two positive notes, existing virtual-input proof | Dedicated admission branch in the new relation; one or two positive notes |
| Native settlement | Historical private membership plus current public covenant checks | Retain separation; update two nullifiers atomically |
| Counts | One nullifier per consumed positive note | Two public nullifiers per spend, including padding; counts are not liabilities |
| Capacity | Depth-16 trees with existing rules | Depth-16 commitment/history trees; depth-17 nullifier tree; exits need no new commitment slots |
| Evidence | Bounded offline and TN10 reports exist | Specification and design review only |

Use a **new immutable candidate pool, provisionally v6**, with a new circuit,
setup, VK and covenant. Existing pools, source variants and evidence stay intact.
Existing v4/v5 proof bytes cannot authorize v6 claims. Proof preservation means
preserving proofs created within the same new pool across its later activity;
it does not mean migration or an in-place upgrade. No new parameters are created
by this documentation task.

BN254 Groth16 still requires trusted setup for the new circuit. Public parameter
hashes establish identity and availability, not honest setup or erased trapdoors.
Any later single-party experimental setup must remain explicitly unaudited;
compromised soundness can permit forged claims against the native reserve.

## Source grounding and reuse

Sources were inspected for this design; upstream heads were refreshed for the
assessment on 2026-10-20. Recorded older source snapshots below are not claims
that those projects have received a new implementation review today.

| Source | Reuse or rejection |
| --- | --- |
| [KIP 16](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0016.md), [KIP 17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md) | Active proof-verification and introspection primitives. More private witnesses do not inherently require a new L1 opcode. Script mass, metering and relay acceptance still need qualification. |
| [Rusty Kaspa Groth16 verifier](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/groth16/mod.rs) | Candidate remains BN254 Groth16 with two public digest limbs. This source check is not execution of the larger proposed covenant. Retain native experiment pin `01b532e8b553523216471682649693af92f0fd16` until an explicitly recorded change. |
| [Our circuit](../../poc/shared-pool/src/compact/circuit.rs), [format](../../poc/shared-pool/src/compact/mod.rs), [deposits](0010-compact-independent-deposits.md) | Adapt note ownership, positioned nullifiers, authenticated history, native backing and public rebuilding. Replace single-input and full-exit-only restrictions. |
| [Orchard ZIP 224](https://zips.z.cash/zip-0224), [wallet guidance ZIP 315](https://zips.z.cash/zip-0315) | Reuse padded spend/output slots, internal value conservation and keeping change shielded. These are design principles, not a port of Orchard's Halo 2 circuit or security argument. Public ingress/egress remains visible. |
| [Established-protocol source review](../../research/compact-privacy-source-review-2026-10-19.md#established-designs-and-empirical-work), [deposit review](../../research/compact-deposits-source-review-2026-10-19.md) | Retain RAILGUN/Aztec's distinction between historical membership and current spentness, Monero research's joint inference controls, and MWEB's visible native exit boundary. Do not import their runtimes, token models, consensus changes or historical privacy scores. These reviews also pin `kaspanet/vprogs` and `kaspanet/research`; neither is a demonstrated requirement for this relation change. |
| [Olaf's integrated wallet circuit](https://github.com/olafweller/kaspa-privacy-initiative/blob/05ea24a5cdb89ba5dd2cfec1041b1e69fa8de68d/poc/private-note-wallet/src/circuit.rs) | The inspected circuit still has one private input, two transfer outputs and no private exit change. Moving to its outer-proof pipeline alone would not supply this proposal's payment semantics. |
| [PR 56 recovery ADR](https://github.com/olafweller/kaspa-privacy-initiative/blob/cfee7e5f7cd25d9bac600eab5292a8ffcc52e7b3/docs/adr/0017-integrated-recovery-native-guest.md), [P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) | PR 56 was open at inspection. Its partial reserve release is not partial private-note withdrawal with new change. P13's separation of confidentiality, chain inference and network privacy remains relevant. Neither upstream approval nor a reply is a dependency for this independent design assessment. |

## Amounts and economic statement

All serialized amounts are unsigned 64-bit **integer sompi**. Each is bounded by
the pinned native `MAX_SOMPI = 2,900,000,000,000,000,000`. Use checked wide
intermediates and explicit range constraints; no field-modulus arithmetic,
wrapping, floating point or saturating acceptance. Aggregate native inputs and
private input totals must also fit the native amount bound.

Let `R` be actual consumed reserve value, `D` actual admitted native funding,
`W` native payout, `F` actual native transaction fee, and `i0,i1,o0,o1` private
slot values. Zero-valued slots carry no liability. Every positive output must
meet the immutable candidate note floor `Vmin`; every positive payout meets
`Pmin`. Define `Vmin >= F_exit_budget + Pmin`, where `F_exit_budget` covers a
single-real-input fallback in both continuing and terminal forms under a declared
fee-rate/mass envelope, including storage mass over the allowed reserve and
payout amounts. **These new numerical constants are not qualified yet.**
Do not inherit the old 0.6-tKAS note floor as a measured v6 bound.

| Mode | Private relation | Native reserve transition | Outputs in private state |
| --- | --- | --- | --- |
| `ADMIT` | `i0=i1=0`; `D=o0+o1+F`; at least one positive output | `R'=R+D-F > 0`, `W=0` | Append two commitments, including any zero slot |
| `SPEND` | At least one real input; `i0+i1=o0+o1+W+F` | `R'=R-W-F > 0`, `D=0` | Always append two commitments; zero, one or two outputs may be positive |
| `DRAIN` | At least one real input; `o0=o1=0`; `i0+i1=W+F`, `W>0` | `R'=R-W-F >= 0`, `D=0` | No new commitments; exact whole-input withdrawal |

`SPEND` with `W=0` must create at least one positive output; fee-only destruction
is not an operation. With `W>0`, two zero output slots permit an ordinary full
withdrawal without an explicit public change flag. A terminal withdrawal uses
`DRAIN`, since it needs no successor reserve or output commitments.

Examples are algebraic, **not fee estimates**. Two notes worth `a` and `b` can
pay a recipient `p` and return change `a+b-p-F`. A partial native withdrawal
`w` from a note worth `v` can return private change `v-w-F`, with a zero second
output. Each positive result must meet `Vmin`. A zero result is allowed padding;
a positive result below `Vmin` is rejected. The wallet must choose other inputs
or explicitly revise the requested amounts, never silently donate change.
Amounts below the exit-supported note floor are outside this candidate's
payment range. More than two receipts require additional merge operations.

Let `L` be the sum of all unspent positive notes. From valid genesis and valid
transitions, `R=L` is the intended accounting induction: admission adds `D-F`;
spending removes `W+F`. There is no pending-withdrawal state: the authorized
native payout and note consumption settle atomically. An unconfirmed proof does
not consume a note or eliminate its liability. This specializes backing and
conservation at explicit native deposit/withdrawal boundaries; it changes no
[security invariant](../../SECURITY-INVARIANTS.md).

**Terminal settlement is determined by actual `R'=0`, never by commitment minus
nullifier counts.** Padded entries have no fixed monetary meaning. Terminal
settlement must still satisfy ownership, current spentness and conservation;
the accounting induction, not a claimant's assertion, then implies `L'=0`.

## Notes, real inputs and padding

Retain the branch's SHA-256 note/owner commitments, HMAC-SHA256 positioned real
nullifier and sealed note delivery, under the new pool domain. The domain binds
the network identity, pool nonce and immutable protocol profile; the descriptor
pins its actual genesis, code, VK, parameter hashes and constants. Avoid a
circular domain depending on its own funding transaction ID or complete redeem
script. The domain profile covers relation/encoding identifiers, tree and
economic constants and the VK hash; it excludes the domain-bearing script and
final genesis outpoint, which the descriptor pins separately. New domain and
immutable VK binding prevent cross-pool and cross-version authorization.

For each of two private input slots the circuit constrains a Boolean real flag.
For a real input it proves:

1. The note opening and ownership secret match its commitment and owner.
2. `Vmin <= value <= MAX_SOMPI`; its private position is below the public anchor
   count and its depth-16 membership path reaches the common historical root.
3. Its public nullifier is the existing positioned derivation:
   `HMAC(spend_secret, real_nf_tag || domain || commitment || position_LE32)`.
   It is independent of input slot, anchor, operation, payout and fee.

Here `real_nf_tag` is the existing `KPI-positioned-nullifier-v1` plus NUL byte;
the new domain separates these notes from earlier pools.

Two real inputs must have different positions and different nullifiers. The
same note cannot enter twice by changing its slot. They may use different
ownership keys; the submitting wallet needs both witnesses. No other wallet's
approval is required when spending its own notes.

A padded input has zero value and no membership or spend authority. Its inactive
note/path/position fields are canonical zeros. In `SPEND` and `DRAIN`, its
nullifier is constrained inside the proof to
`HMAC(dummy_key, dummy_nf_tag || domain || dummy_seed || slot_u8)` with fresh
private 32-byte key/seed and a distinct fixed tag. Both public nullifiers must
be nonzero and unequal; **both are inserted into the current nullifier tree**.
The exact new tag is `KPI-dummy-nullifier-v1` followed by one NUL byte.

An unconstrained, caller-chosen dummy nullifier is forbidden: it could consume
someone else's disclosed pending real nullifier. The tagged derivation relies
on HMAC preimage/collision resistance and private randomness; this composition
needs independent review. Wallets must not reuse dummy key/seed combinations.
Do not publish real flags, dummy seeds or a list identifying padding. Admission
is a distinct public mode with two zero nullifier fields and no NF insertion.

Every `SPEND`/`ADMIT` output slot contains a note commitment and a 185-byte sealed
ciphertext. A zero-value output uses fresh note randomness, a throwaway receiving
key and the same encryption format as a real output, not the old all-zero dummy
encoding. The circuit derives both commitments, enforces their inequality and
nonzero encoding, and constrains each value to zero or the positive range.
Randomize input/output ordering in normal wallet construction; randomness is a
wallet assumption, not something this circuit proves.

As today, binding a ciphertext digest **does not prove correct encryption**.
Recipients decrypt and validate domain, owner, incoming key, canonical value,
note commitment, accepted position and current spentness before accepting a
positive claim. Zero notes are ignored. Malformed or misleading delivery is
rejected, not counted as received value. The sender verifies its own private
change the same way. Ciphertext recipient privacy and the new padding
composition remain unreviewed assumptions, not inherited Orchard guarantees.

## Private authorization and public settlement boundary

Candidate authorization serialization is below. Integers are little-endian;
hashes are raw 32-byte strings. The 36-byte script encoding includes its 2-byte
version and the existing 34-byte native P2PK script. Offsets are byte offsets.
These are proposed bytes for review, not an existing wire-format claim.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | Magic `KPICU06` followed by NUL |
| 8 | 32 | Pool domain |
| 40 | 4 | Historical commitment count |
| 44 | 32 | Historical commitment root |
| 76 | 64 | Two ordered nullifiers |
| 140 | 64 | Two ordered output commitments |
| 204 | 1 | Mode: `ADMIT=0`, `SPEND=1`, `DRAIN=2` |
| 205 | 8 | Native payout `W` |
| 213 | 8 | Exact native fee `F`, positive |
| 221 | 36 | Payout script, or zero when `W=0` |
| 257 | 8 | Admitted funding `D` |
| 265 | 36 | Admission funding txid and output index |
| 301 | 36 | Admission funding script |
| 337 | 8 | Bootstrap value, otherwise zero |
| 345 | 32 | SHA-256 of the ordered 370 ciphertext bytes |

Total authorization: **377 bytes**. The proof has two public field elements:
the two 16-byte halves of SHA-256 of all 377 bytes, each interpreted as an
unsigned little-endian 128-bit integer. No truncation or reduction aliases.
The circuit constrains that digest and every relevant semantic predicate;
native script independently reconstructs the same digest and compares the
native fields. Retain the verifier's canonical BN254 encoding: 128-byte proof,
328-byte VK for this two-public-input shape. New parameter bytes and circuit
cost are unknown; these lengths are format choices, not measured performance.

For `ADMIT`, anchor/count, nullifiers, payout/script and bootstrap are zero;
`D`, funding outpoint and funding script match the actual ordinary input. For
other modes all admission fields are zero. `DRAIN` has zero output commitment
fields and 370 zero ciphertext bytes; no commitments are appended. All inactive
fields are constrained, not ignored. Except at validated bootstrap, bootstrap
value is zero. Positive `W` requires the canonical supported native P2PK payout
encoding; `W=0` requires the entire script field to be zero.

The authorization intentionally excludes the **current** reserve outpoint,
current NF root, successor state and public update paths. The covenant checks
those against the consumed native UTXO. All real inputs use one historical
anchor authenticated in the current append-only history. Normal wallets choose
a recent eligible common anchor and generate a fresh proof; consensus must not
require the latest root or expire older roots, which would invalidate fallbacks.

## Native transaction, covenant and public payload

| Mode | Inputs | Native outputs |
| --- | --- | --- |
| `ADMIT` | 0: current reserve; 1: ordinary signed funding UTXO | 0: successor reserve `R+D-F` |
| `SPEND`, `W=0` | 0: current reserve | 0: successor reserve `R-F` |
| `SPEND`, `W>0` | 0: current reserve | 0: successor reserve `R-W-F`; 1: exact payout `W` |
| Continuing `DRAIN` | 0: current reserve | 0: successor reserve `R-W-F`; 1: exact payout `W` |
| Terminal `DRAIN` | 0: current reserve | 0: exact payout `W`; no reserve output |

Reject extra inputs, outputs, alternate reserve code/VK/domain, mismatched
amounts/scripts and noncanonical mode framing. There is no sponsor, operator
input or public change output. Admission consumes the whole ordinary UTXO;
separate preparation of that UTXO has observable ancestry and additional fees.
Use the existing version-1 native transaction framing, zero gas/locktime,
maximal input sequences and no covenant metadata. The proof is in reserve
input 0's witness with the exact redeem script. Native conservation, not a
host-supplied field, establishes `F=sum(inputs)-sum(outputs)`.

Admission input 1 uses native Schnorr authorization, the canonical 66-byte
signature script and exactly `SIGHASH_ALL` without `ANYONECANPAY`. Native
validation verifies the actual UTXO. The signature binds the payload and native
monetary intent; it does not sign signature scripts or v1 compute budgets.
Do not assume a nonexistent budget introspection check. Native execution and
relay validation must independently establish adequate metering and fees.
On reserve contention the depositor re-signs rebuilt native inputs; the private
admission proof may remain unchanged when its funding outpoint and intent do.

The continuing reserve carries the existing 105-byte state shape, new tag `6`:

`tag_u8 || C_u32 || N_u32 || CM_root[32] || NF_root[32] || history_root[32]`.

`C` counts all commitments, including zero-value notes; `N` counts all inserted
nullifiers, excluding the sentinel and including padding. Authenticate the
current state from the consumed redeem script and require the exact successor.
Retain canonical empty leaves and existing tree hash definitions from
[the compact tree](../../poc/shared-pool/src/compact/tree.rs), with the NF depth
changed to 17. A NF predecessor leaf is `(value[32], next_index_u32, next_value[32])`;
compare all 256 bits under the existing unsigned ordering, without field reduction.

Candidate payload: `KPICR06\0 || authorization || ciphertexts || next_state || witness`.
It has one canonical shape in all modes; unused witness slots are zero.

| Offset | Bytes | Content |
| ---: | ---: | --- |
| 0 | 8 | Payload magic |
| 8 | 377 | Authorization |
| 385 | 370 | Two delivery ciphertexts |
| 755 | 105 | Successor state; all zero for terminal `DRAIN` |
| 860 | 512 | Historical-anchor membership path |
| 1372 | 1160 | NF 0 insertion witness |
| 2532 | 1160 | NF 1 insertion witness |
| 3692 | 1024 | Two commitment append paths |
| 4716 | 512 | History append path |

Total proposed payload: **5,228 bytes**. Each NF insertion witness has a 4-byte
predecessor index, 68-byte predecessor leaf and two 544-byte paths: predecessor
authentication and empty-leaf append. First verify nonmembership and the strict
predecessor gap, rewrite the predecessor, then append under that updated root.
NF 1's entire witness is against the state after NF 0. Applying both witnesses
against the old root, overwriting a leaf, dropping a prior NF or accepting the
same NF twice is invalid. The second append position advances with the first.

`ADMIT` zeroes anchor/NF witnesses and preserves NF state. `SPEND`/`DRAIN`
authenticate the old private anchor and insert both NFs. `SPEND`/`ADMIT` append
two commitments sequentially and then exactly the resulting `(C+2, root)` to
history. `DRAIN` zeroes commitment/history append paths and preserves those
trees. Even terminal `DRAIN` verifies both current NF nonmembership/updates;
its zero next-state field does not bypass either input's single-spend check.

For a spend, the anchor count is positive, odd and no greater than current `C`.
Authenticate the existing history leaf `SHA256(0x03 || count_LE32 || anchor)`
at derived index `(count-1)/2`, not a caller-selected position. After two CM
appends, the new history leaf is appended at old index `(C+1)/2`. This binds
the root and its eligibility count together; existing entries are never replaced.

## Genesis and capacity must leave exits available

Retain a singleton genesis with `R>=Vmin`, not a consensus-invalid zero-value
reserve or a below-floor initial claim. The public descriptor pins the actual
funding outpoint, initial CM,
canonical singleton CM root, empty NF sentinel and singleton history. Clients
independently validate this genesis and every accepted successor before joining;
a creator's state label or arbitrary payment to a P2SH address is not admission.

The first transition proves exactly one real initial note at position zero,
value equal to actual `R`, and its ownership, with the other input padded.
The initial membership path must have the canonical empty-subtree siblings;
an arbitrary root containing undisclosed initial liabilities is not a singleton.
Its nonzero bootstrap field equals `R`; the covenant enforces the canonical
initial state. It may `SPEND` into ordinary notes or `DRAIN` back out. `ADMIT`
is unavailable before this verification. Later bootstrap fields are zero, with
no creator privilege. Preserve the initial opening until that note is spent.

Padding requires different capacity accounting. Proposed limits:

- CM and history depths remain 16. `C` starts at 1 and increases by 2, so
  `Cmax=65,535`; history length is `(C+1)/2`, at most 32,768.
- NF depth is 17, with one sentinel. Each `SPEND`/`DRAIN` inserts two NFs;
  admission inserts none. Every spend consumes at least one previously unspent
  positive note. Thus at most `C` spending operations can consume the notes
  created so far, and the total NF space needed to spend them is at most `2C`.
- If `t=N/2` spending operations have happened, at most `C-t` positive notes
  remain. One-note fallback exits need at most `2(C-t)` further slots. Including
  the sentinel, `1+N+2(C-t)=1+2C <= 131,071 < 2^17`. This is a design argument
  dependent on valid transitions, not a tested implementation claim.

Enforce canonical parity, `N<=2C`, exact insertions and tree bounds. Stop new
admissions and `SPEND` when two CM slots/history space are unavailable.
`DRAIN` remains legal, consumes no CM/history space and has reserved NF capacity
by the argument above. Normal operations must not evict old roots/nullifiers or
require rollover to exit. A full pool can force use of the more revealing exit
path; it cannot require an operator's signature. Capacity exhaustion remains a
payment-liveness and privacy risk, not an unlimited-scale claim.

## Independent exits, private fallbacks and recovery

For each received positive note, its owner can prepare a one-real-input `DRAIN`
proof with one padded input, exact fee and a fresh native payout script they
control. Keep this bundle private. It can use the note's first accepted anchor;
public paths can later authenticate that same anchor in a larger history.
The reference fallback uses the qualified `F_exit_budget`; the note floor must
leave at least `Pmin` after that fee in either native settlement form.

An unrelated accepted spend/deposit changes only the current reserve and public
state. If the note is unspent, both saved NFs remain unused, history is available
and its exact fee is adequate, the **same proof and authorization** must settle
after public rebuilding. Dummy-NF collision resistance and fresh wallet
randomness are explicit assumptions; a colliding NF is rejected, never bypassed.
Contention on the reserve requires rediscovery and public rebuilding. It does
not itself require another private proof. No ordering fairness is promised.

The real positioned NF is shared by every normal/fallback authorization for
that note. Whichever is accepted first invalidates the others, even if they use
different anchors, companions, modes or output choices. Two per-note fallbacks
also remain alternatives to one normal two-input spend. A rejected competing
transaction does not spend either note; a committed spend does. Newly created
private change is a new claim: retain its opening and prepare its own fallback,
not the spent input's obsolete proof.

Recovery needs the owner's spending, incoming-view and native payout key
material, including any payout derivation path/index not recoverable from public
data; an authenticated pool-descriptor pin; and the initial opening for an
unspent genesis claim. Saved fallback bundles permit exit without re-proving.
Without such a bundle, the owner can locally create a first proof using the
public proving parameters, authenticated history and their recovered note.
Neither case needs the sender's secrets or an operator export of future notes.

Public dependencies remain exact PK/VK and formats/software, retained accepted
commitments/NFs/history/ciphertexts, and an independently obtained correct chain
and UTXO view. The PK is needed for new proofs, not public rebuilding of an
already saved fallback. Roots cannot recover missing data. A particular server
may vanish; loss of every required public copy still blocks recovery. Follow accepted reserve
lineage across reorgs; roll back orphaned notes/state and never combine roots
from conflicting branches. Comprehensive reorg and retention policy remains open.

**Exact fees are retained.** Public rebuilding cannot reprice a saved proof.
Above its affordable fee envelope the owner must make a fresh authorization or
wait; a spent-down note may cease to be economically exitable at a sufficiently
high fee rate. No all-fee-market exit guarantee, fee sponsor or privileged rescue
is added. Policy must disclose this before accepting a note.

## Cost, review gates and stopping conditions

This proposal adds a second private membership/ownership check, padded-slot
constraints and two public NF insertions. It changes proving parameters and
covenant work. Proposed payload length is derivable above; **script mass,
compute budget, relayability, fee, proving time/RAM and key size are unmeasured**.
The existing v5 21,893,200 / 22,005,200 / 21,934,400-sompi transfer/admission/exit
fees at 100 sompi/mass are comparison baselines only, not v6 quotations.
Count admission, merges, partial-withdrawal change and eventual drain when
assessing cost. Two inputs need not double verifier cost, but neither constant
proof size nor current L1 primitives establish affordable total cost.

Before implementation, resolve review of dummy-NF derivation, output padding,
conservation/terminal induction, bootstrap and the capacity argument. A later
authorized offline implementation may establish native costs; before any funded
qualification, freeze the canonical profile, fee-rate envelope,
`Vmin/Pmin/F_exit_budget`, native limits and exact encodings against the pinned
SDK using those costs. The layout above is a reviewable candidate; a change must
update the RFC/ADR rather than silently change a format.

A separately authorized future mechanical qualification must cover two receipts
paying a third wallet with change; a partial withdrawal and re-spend of change;
all four independently funded wallets exiting; an unrelated saved proof unchanged
across these operations and a later deposit; both winner orders of normal versus
fallback; native backing; boundary amounts; duplicate/reordered inputs; wrong state/domain;
sequential NF updates; malformed delivery; and capacity exhaustion followed by
independent drainage. These are **acceptance criteria, not tests run or authorized
by this document**. Only after qualification and further authorization could a
complete TN10 rehearsal/trial establish execution of this particular layout.

Stop or redesign if arbitrary dummy NFs can invalidate other users' claims,
padding can create value or hide a skipped spend check, a terminal/capacity rule
can strand a valid funded claim within the declared assumptions, public rebasing
needs a privileged secret, or the layout cannot meet native limits. If costs
make supported ordinary payments uneconomic, compare batching/another settlement
architecture explicitly. If realistic public constraints still reconstruct
relationships, report that privacy failure rather than increasing synthetic
participant counts until a score improves. No production or strong-privacy
decision follows from writing this specification.
