# RFC-0003: Private-payment proof and native settlement contract

Status: **Open**, 2026-10-18. Owner-authorized specification work; no funding,
broadcast, mainnet, real funds or production construction is authorized here.

The later owner-authorized [implementation package](../adr/0018-private-payment-implementation-package.md)
permits P1 preparation and eventual qualified testnet execution against the
owner's node. It preserves the review/proof/native prerequisites below.
[RFC-0004](0004-private-payment-suite-and-encoding.md) supplies the concrete
candidate suite/intent bytes. The owner-selected separate-agent AI design
review route is recorded in [ADR-0019](../adr/0019-separate-agent-prototype-review.md).
It is not an external audit. This RFC remains Open and does not itself qualify
a funded private trial; offline readiness requires closure of the review findings.
This expands [RFC-0002](0002-shielded-payment.md), preserves I-1–I-16, and supplies
the proposed complete *semantic* relation for implementation review. It is not a
completed circuit, interoperable wire standard, cryptographic audit or proof of
permissionless exits. [ADR-0015](../adr/0015-private-payment-proof-boundary.md)
records the narrow research boundary. [Source facts and alternatives](../../research/private-payment-source-review-2026-10-18.md)
are separate from the recommendations below.

## 1. Decision sought and scope

Investigate **Orchard-derived notes/actions and local wallet proving**, followed
by a total ordinary wallet-proof verifier in the existing proved ordered
application transition. Use native KAS as the sole backing asset. The experiment
does not add a privacy token, account runtime, governance, archive network or
privileged withdrawal key. Existing public Based App settlement is the backend
to adapt, not evidence that the private integration already works.

The first relation has exactly **two action slots**, each with one input and one
output, using the selected Orchard dummy-note rules for unused slots. A real
note has positive u64 value; a zero-valued dummy creates no user entitlement.
Credit, transfer and exit share the relation but expose their operation kind.
Normal mode appends both output slots. A distinct public `exit_only` mode proves
both output values zero and appends neither, allowing full withdrawal even when
the commitment tree is full. This explicit adaptation needs P1 review; it is not
an unchanged Orchard transaction rule.
Merge/split requires at most two inputs/two outputs; larger transactions require
another reviewed profile. This arity is a proposed experimental limit, not a
throughput or privacy result. No claim hides deposit/exit timing or amount.

The proposed baseline studies Orchard's V2 note semantics and repaired
post-NU6.2 action constraints, including exact Pallas key/point validation,
nullifier/commitment derivation and depth-32 membership. Historical insecure
pre-NU6.2 circuit semantics are prohibited. V3 notes, post-NU6.3 flags and any
future changes need separate explicit review; current source HEAD is not a
license to switch algorithms. This proposal is **not** Zcash transaction
compatibility, an unchanged Orchard Halo2 circuit, or a post-quantum claim.

## 2. Trust and acceptance boundary

Assume the selected established primitives, proof system and pinned verifier
are sound; Kaspa consensus acceptance/ordering and the native scripts enforce
their documented rules; the user's own spending/incoming keys remain private.
A compromised hosted executor/prover/archive may withhold service but must not
authorize inflation, incorrect rejection, theft or a redirected exit.

Native payout is complete only after the exact permission consumption and native
recipient output are accepted on the chosen canonical lineage. A model event,
executor acknowledgement, transaction submission or proof alone is insufficient.
Canonical observation/confirmation policy is a named testnet configuration;
no finite depth is advertised as mathematical irreversibility. Contradictory or
unavailable chain evidence halts accounting rather than marking an exit paid.

Use separate responsibilities:

| Layer | Required verified decision |
| --- | --- |
| Wallet relation | Own the hidden inputs; derive exact commitments/nullifiers; prove ranges, balance, output encryption and intent authorization. |
| Transaction adapter | Decode accepted operation bytes, recompute intent and actual native identity, run the exact wallet verifier, produce a deterministic outcome. |
| Ordered transition | Authenticate the full accepted sequence, allowed roots and current spentness/deposit/claim state; update atomically. |
| Settlement/native scripts | Bind prior/successor state, reserve UTXOs and permission claims to exact native outputs; handle nonterminal and terminal reserve cases. |
| Recovering wallet | Authenticate complete lineage/data/artifacts, replay, decrypt/check locally, reconstruct witnesses and prove with its own keys. |

## 3. Descriptor, domains and canonical data

An immutable genesis descriptor `G` commits to native genesis/network, pool and
lane IDs, economic domain `D`, initial state, state/native script identities,
permitted proof suite IDs and exact encodings. The economic consumed-resource key
is `(D, nf)`. **Do not put verifier, statement, backup or archive versions into
the economic nullifier derivation or create parallel spent sets for versions.**
Every permitted route consults the same `N[D]`. A foreign descriptor/lane proof
cannot alter state. The network must be testnet for the authorized experiment.

All consensus byte encodings have one canonical form: unsigned integers in
fixed-width little endian; flags exactly 0/1; fixed arrays in slot order;
variable bytes prefixed by u32 length; no map ordering ambiguity, float, negative
integer, duplicate field, unused trailing byte or unknown enum. Raw native
transactions use the exact pinned native consensus encoding, not this envelope
encoding. Point/scalar/hash bytes use their pinned library's unique checked
encoding; noncanonical, identity-forbidden, wrong-curve or wrong-subgroup values
fail. These rules are requirements for the wire-format implementation; golden
binary vectors and final native script length bounds are still blockers.

The public intent `I` contains, in the declared field order:

```text
tag="KPI/private-payment/intent/v1", G_hash, D, network_genesis, pool_id, lane_id,
statement_id, proof_suite_id, wallet_program_or_vk_hash, operation_kind, append_mode,
expiry_order_bound, anchor, nf[2], cmx_new[2], ephemeral_key[2], ciphertext[2],
deposit_reference_or_absent, deposit_principal_or_zero,
exit_script_or_absent, exit_principal_or_zero,
fee_script_or_absent, private_fee_sompi_or_zero
```

`deposit_reference` is the actual native outpoint plus authenticated deposit
descriptor; scripts include script version and full script bytes. Absent and
zero have explicit distinct encodings. The ciphertext includes all decryption
metadata needed by the chosen note format; no omitted memo/tag dependency is
silently required. The transaction's native fee/rent funding is separately
authenticated and accounted, never inferred from the private fee field.

`intent_id = SHA256(canonical(I))`. The wallet journal is exactly the fixed tag,
`G_hash`, statement/verifier IDs, `intent_id` and `authorization_digest`; publishing additional witness
material is forbidden. Authorization binds **all of I**, including recipient
scripts, ciphertexts, public fee and expiry. A spender cannot sign only a root
or commitment subset. For real private inputs the full wallet proof establishes
knowledge of the actual spending-key material and its complete note ownership
derivation, while binding its journal to this intent; public commitment/viewing
knowledge is insufficient. This is distinct from merely checking the original
Orchard Action circuit, whose surrounding spending signatures perform another
responsibility. No unconstrained signing-key intermediate substitutes for that
knowledge. The exact key/authorization implementation remains a P1 review item.

For native-deposit credit/refund recovery, the proposed stable descriptor carries
an independent Ed25519 recovery public key. The corresponding authorization
for CREDIT signs the canonical tuple `("KPI/credit-recovery/v1", G_hash,
intent_id)`, thereby binding every CREDIT intent field. A refund request has its
own canonical public tuple `("KPI/refund-recovery/v1", G_hash, D,
deposit_reference, principal, destination_script, rent_refund_terms,
expiry_order_bound)` and signs exactly that tuple. Both use the recovery key
authenticated by the same native deposit descriptor/outpoint, not a key claimed
by the host or wallet. Verify with a pinned strict Ed25519 implementation inside
the proved computation. Recovery signatures are
outside the signed intent serialization, avoiding signature self-reference;
their canonical envelope is nevertheless included in actual native operation
identity. Require canonical scalar/point encodings and reject small-order keys
and alias encodings consistently. This key is a per-deposit recovery authority,
not an operator withdrawal key; private notes never publish this key as owner.

The exact public wallet authorization bytes are flag 1 + signature64 for CREDIT,
or exactly flag 0 for TRANSFER/EXIT. Unknown flags, absent required signatures,
irrelevant signatures and trailing bytes reject. The guest verifies CREDIT
using these same bytes and computes `authorization_digest = SHA256(raw ASCII
"KPI/private-payment/authorization/v1" || auth_bytes)`. The outer independently
derives that digest from the actual accepted operation and requires exact full
wallet-journal equality. A private VM input containing some other valid signature
cannot validate a different public envelope. The signature signs G_hash and
intent_id only; adding its envelope digest to the subsequent journal introduces
no signature/proof/native-ID cycle.

Expiry is valid iff absent, or the canonical accepted native lane transaction
ordinal in `K` is **less than or equal to** the optional u64 bound. Ordinals
start at zero and advance once per accepted native lane transaction, including
malformed/rejected operations. This initial profile permits one application
operation per transaction; a payload cannot invent extra ordinals. Authenticate
the cursor and check its u64 increment before effects; halt atomically before
overflow rather than wrap. Neither a host clock, executor-provided height,
private witness, checkpoint substitution nor cursor reset determines expiry.

### No proof/native-ID cycle

The wallet proves `intent_id`, excluding proof bytes and final native ID. A
native operation carries `I` and its proof/authorization. The adapter obtains
the actual transaction from authenticated accepted Kaspa data, recomputes the
exact native ID using the pinned native rules (including proof payload where
applicable), and binds that ID, intent and accepted position to the outer journal.
A host-supplied native-ID string is not authority. Claim IDs derive from this
accepted identity/position and claim ordinal, not a host alias or malleable
proof encoding. Replaying a credit/exit intent in another native transaction
still encounters the same consumed deposit/nullifier; it cannot mint a new claim.

## 4. Full wallet relation

The wallet guest is a **generic fixed-profile relation**: it enforces the exact
selected algorithms/versions/encodings and binds the supplied context in I and
its complete journal. It does not embed its own image or final G hash, accept a
host-provided policy, prove pool admission or authenticate native backing.
Before any effects, the proved outer transition authenticates the immutable
policy from its prior authorized state and compares **every** duplicated field:
`G_hash,D,network_genesis,pool_id,lane_id,statement_id,proof_suite_id,
wallet_program_or_vk_hash`. It verifies the receipt against the actual permitted
image and parameters, not a journal string. Only then may it select the
authorized shared spent set N[D]. Different supported versions cannot fork N[D].
An offline fixture policy is explicitly synthetic; actual built wallet IDs are
inserted after build. It authorizes no native reserve or deposit recognition.

Wallet public inputs are `I` and the canonical authorization bytes; their
admission to an authenticated pool is the above outer responsibility. Private witness comprises
the selected old notes, spending authorization material, complete membership
paths and positions, new notes/recipient addresses, encryption randomness and
any suite-required secret randomness. Public I/auth bytes remain public even
when supplied through the VM input stream. **Nothing in this private witness is sent
to the executor, outer prover, RPC or public journal.**

The proof must establish every row below; computing a value in an unconstrained
helper is not establishing it. Each reference to an Orchard operation means
the exact algorithm/version selected in the final manifest, not the Python
model's SHA/HMAC recipe.

| Predicate | Required relation |
| --- | --- |
| Domain and decoding | The fixed-profile guest checks all intent/auth/witness encodings and kind, binds every context field through the complete intent/journal, and does not infer pool admission from those strings. The proved outer transition performs all immutable-policy comparisons and actual-image verification stated above before effects. |
| Old note binding | For each slot, reconstruct recipient, u64 value, rho/seed and all dependent randomness; recompute the full note commitment and extracted tree leaf with the selected Orchard algorithms. No freely supplied commitment or dependent key intermediate is trusted. |
| Ownership | Recompute the spending/full-viewing/incoming-key relationships and diversified recipient binding. Prove satisfied spending authority for each real input and authorization of this intent. An incoming/full viewing key alone cannot satisfy it. Reject forbidden points/keys and underconstrained scalar bases. |
| Hidden membership | For each nonzero old note, recompute the depth-32 path from its derived leaf and hidden position to exactly `I.anchor`. No selected leaf, position, path or owner ID appears publicly. A zero dummy may skip membership only under the exact reviewed zero-note rules. |
| Nullifier | Derive `nf[i]` from that same old note, its commitment, rho/psi and rightful nullifier key. Do not let a sender select another marker. Dummy nullifiers follow the established dummy rules and are also subject to current uniqueness. |
| New note binding | Recompute each output commitment from the actual recipient/value/seed. Preserve the action relationship `rho_new[i] = nf[i]` and exact dependent seed derivations. Real notes are positive; zero dummy values contribute zero to the equation. |
| Delivery correctness | Execute the selected established note-encryption algorithm **inside the proved relation**, with the same new note, recipient address and derived ephemeral secret. Recompute ephemeral public key, KDF/AEAD data and every delivered byte; equal the public delivery bytes. A digest comparison without this computation is insufficient. |
| Integer ranges | Every principal/fee/note value is `0..2^64-1`. Accumulate the two-slot equation in checked u128 (or explicitly constrained carry limbs), never modulo a proof field. Every stored ledger total and native output also satisfies its own u64 bound. Reject overflowing sums before committing state. |
| Balance and kind | Enforce the kind-specific equation below, including every change output and authorized fee. Fields irrelevant to that kind must be absent/zero, not unconstrained. |
| Binding | Recompute `intent_id` from the proved public fields; the spending authorization covers that digest. Mutating a ciphertext, public amount, destination, kind, domain or expiry invalidates authorization/proof. |

Let `in = sum(v_old[2])`, `out = sum(v_new[2])`, `f` be the authorized
private fee, `p` the referenced deposit principal and `x` exit principal:

```text
CREDIT:   in = 0; p > 0; f = x = 0; out = p
TRANSFER: in = out + f; p = x = 0; in > 0
EXIT:     in = out + x + f; p = 0; x > 0
```

A credit proves control of the stable deposit recovery authority and binds its
native reference/principal; the outer transition separately proves the event's
actual existence, amount and still-pending status. An unauthenticated public
`p` is not an input value. Native network fees are funded outside this equation
unless a separately authorized, backed fee claim explicitly covers them.
In particular, CREDIT has no real input note: it must verify the deposit's own
recovery authorization over `intent_id`; dummy spending keys cannot authorize
crediting somebody else's pending deposit. Native descriptor recognition and
key-to-outpoint authentication are explicit P1/P4 implementation blockers.

`append_mode` is either `full` or `exit_only`. CREDIT/TRANSFER require `full`.
EXIT in `full` may create private change; EXIT in `exit_only` additionally proves
both new note values exactly zero and `in = x + f`. Its two dummy ciphertexts
and all key/commitment predicates are still verified and retained, but their
leaves are not inserted. Both slot nullifiers are inserted under normal current
spentness rules. The mode is bound by the intent/proof, never selected by the
executor. This permits repeated no-change exits of existing notes at capacity
without increasing the tree or bypassing conservation/authorization.

The exact fixed two-action zero-note/authorization semantics and key/address
derivation must survive independent cryptographic review. If translating them
to the chosen backend changes assumptions, stop and revise this RFC rather than
substituting a simpler unreviewed construction. Proving this larger relation in
a new zkVM/circuit does not inherit the deployed Orchard circuit's assurance.
The conservation boundary includes authenticated pending principal credited in
and newly created exit principal out: `in + p = out + x + f`, with the exact
kind restrictions above. CREDIT does not add reserve again; EXIT remains an
unpaid backed liability. ADR-0019 explicitly reviews this clarification of I-2
rather than silently applying its old closed-private equation to native boundaries.

## 5. Recipient acceptance and visibility

The recipient obtains a receiving address through an authenticated out-of-band
channel; neither this protocol nor a proof identifies the human behind an
address. Address substitution is an application failure that must be detectable
by the chosen authenticated exchange. Do not publish a per-user spending account.

A wallet counts a positive output as received only after: (1) authenticating its
accepted canonical record and complete history coverage; (2) local trial
decryption; (3) exact note/plaintext, ephemeral-key and commitment validation;
(4) checking the recipient belongs to its key hierarchy and the version is
spend-supported; (5) reconstructing a valid witness and consulting **current**
nullifiers. A history entry can be received-but-spent; it is not a spendable
balance. Zero dummies and malformed/unusable notes never count as payment.

Constrained encryption is required for successful payment semantics; a sender's
commitment plus unavailable/wrong-key ciphertext cannot count as a completed
payment. The receiver still validates independently. All accepted ciphertexts
are retained for local scanning; no private view key or selected-note request
is sent to a server. No sender handshake/counter is introduced in this profile.

Public: domain/verifier, anchors, nullifiers, new commitments, ciphertexts,
operation kind/shape and append mode, explicit private fee, deposits, exit destinations/amounts,
native fee/rent and ordering. Private: selected notes/paths, secret keys, hidden
values and cryptographic input-output linkage. Timing, size, low activity, fee
sponsors, entry/exit amounts and network metadata can still correlate users.
Fixed two-slot proofs reduce one shape leak; they do not demonstrate anonymity,
zero knowledge or constant-time wallet behavior. See [VISIBILITY](../../poc/shielded-design/VISIBILITY.md).

## 6. Persistent state and accepted ordering

Logical state `S` comprises commitment-tree frontier/count/root `C`, allowed
anchors `A`, global economic nullifiers `N[D]`, authenticated deposit states `P`,
unpaid/paid claims `Q`, reserve outpoints/principal `R`, native rent ledger `T`,
accepted-input cursor/activity digest `K`, and pinned descriptor/artifact IDs.
The implementation must use authenticated deterministic encodings for all roots
and collection entries; a commitment root alone is not the application state.
The aggregate state commitment binds **every component**, including paid markers,
reserve outpoints, sequence cursor and rent, with no host-owned hidden table.
At genesis, C is the canonical depth-32 empty Orchard tree with count zero and
A contains exactly its root:
`ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f`.
The count representation must include 2^32; note positions remain u32. Genesis
rollback restores that initial anchor along with the complete authenticated state.

For every accepted native operation, in authenticated lane order:

1. Prove prior state equals the current settlement-authorized state, verify full
   accepted-range inclusion/completeness and native operation/context.
2. Decode the exact operation. Run the pinned ordinary verifier as proved
   computation; enforce current state, expiry, allowed-anchor and all economic
   checks. Never consume a host-provided valid/invalid flag.
3. Before effects in `full` mode, require checked `pre_count + 2 <= 2^32` and
   nonwrapping append indices. Otherwise reject atomically. In `exit_only` mode
   verify the zero-output predicates and retain `pre_count` unchanged. Never
   admit a real output for which no valid depth-32 witness can exist.
4. On success commit all note/nullifier/deposit/claim/ledger changes atomically.
   Insert **all** slot nullifiers, including dummies; reject duplicates within
   the operation or earlier canonical operations/batches. Append both output
   commitments in slot order, including dummies, only in `full` mode.
5. On deterministic invalidity, preserve all economic state and record its
   canonical rejection outcome. Both success and rejection advance `K` through
   the actual accepted native identity. Continue later operations from that
   resulting state; the executor cannot omit or reorder accepted bad inputs.

At capacity, new credits/transfers and exits requiring change fail without
consuming their resources; pending deposits remain refundable. Existing notes
retain the `exit_only` route. Do not solve exhaustion with an admin sweep,
unreviewed tree rollover or an unverifiable note migration.

Allowed roots are the explicit genesis anchor and recorded canonical post-operation anchors; do not
invent an intermediate root between an operation's two appends. An old allowed
root proves membership, never freshness of spentness. Reorged roots are removed.
A caller may retry a correctly proved operation rejected solely for now-stale
state with a new intent when appropriate, but consumed claims stay consumed.

### R13: real-proof deterministic rejection

The ordinary verifier has a bounded canonical input language and returns a
proved validity result for *every admitted byte string*: malformed/truncated,
oversized, invalid points, wrong statement/VK and well-formed false proofs all
select no-op. Oversized native-accepted payloads must be rejected by safe parsing
without allocating attacker lengths. The supported language and native payload
limits are explicit profile parameters. Missing host data or proof artifacts is
**unavailable**, never evidence that an accepted proof was invalid.

RISC Zero recursive assumption verification alone does not prove a `false`
verdict for arbitrary bad proof bytes. Reuse the ordinary-verifier classifier
research, but replace its preimage/sum proxy with the full relation and produce
an independently verified **complete outer receipt**. CPU/GPU execution logs,
segment receipts and a host verifier cannot substitute for it.

## 7. Deposits, liabilities, refunds, fees and rent

The deposit descriptor must be recognizable by an outer stable format even
when an inner wallet proof/version is unsupported. It commits the actual native
pool script/outpoint/principal and recovery authority; arbitrary unsolicited
native transfers do not automatically create private credit. The exact native
descriptor/script remains an implementation blocker, not the old delegate
helper renamed. No user should fund it before end-to-end rehearsal.

Let `V` be private outstanding value, `P` pending deposit principal, `E` unpaid
exit principal, `U` unpaid deposit refund principal and `F` unpaid fee claims.
The principal invariant is `V + P + E + U + F <= R`; unexplained surplus cannot
be swept by an admin. The experimental ledger should reconcile equality for
declared fixtures and expose every excess as unexplained/explicitly classified.

| Transition | Preconditions and atomic principal effect |
| --- | --- |
| Accepted deposit | Prove native outpoint/script/value and canonical acceptance; deduplicate the outpoint; `R += p`, `P += p`, state `pending`. |
| Credit | Deposit `pending`, rightful stable recovery authority and full CREDIT proof; `P -= p`, `V += p`, state `credited`; append notes/nullifiers atomically. |
| Refund request | Deposit `pending`, rightful recovery authorization of descriptor/reference, exact amount/destination and current state; `P -= p`, `U += p`, state `refund_pending`; create one exact unpaid refund permission. |
| Private transfer | Full TRANSFER proof; `V -= f`, `F += f`; notes and spentness update, reserve unchanged. |
| Exit request | Full EXIT proof; `V -= x + f`, `E += x`, `F += f`; reserve unchanged; create exact unpaid claims. |
| Confirmed claim payout | Consume one authorized exit/refund/fee permission and prove exact native recipient principal; decrease the matching unpaid liability and `R` by that same principal; retain canonical paid consumption evidence. |

Credit/refund competition is decided by canonical current state, including across
batches/restores: exactly one consumes `pending`. Invalid inner credit leaves
the deposit recoverable. An owner signature alone cannot bypass credited state.
The refund request is not payment; unpaid refund principal remains backed.

Native submission fees, state rent, per-permission rent and sponsor assets have
separate integer ledgers. Never subtract a sponsor-paid native fee from user
principal, count treasury as reserve or charge both a private fee and the same
unannounced native fee. A private fee is a proof-authorized backed claim, with
an exact recipient and single payout. Rent refunds must pay only already-funded
locked rent; deposits and claims cannot multiply the same refundable rent.

## 8. Native payout, restart and final drain

A claim binds `(D, accepted_request_identity, ordinal, kind, principal,
recipient_script, rent_terms, verifier/state identity)`. The native permission
must commit to those exact fields and authorize no alternate script/value,
operator-only signature, replay route or arbitrary remainder withdrawal.

Payout verification matches consumed reserve/permission outpoints, actual output
indices and exact recipient scripts/principal, with explicit change, fee and
rent outputs. If claims are aggregated, each output is assigned once to a
deterministic checked sum; one native output cannot independently satisfy
multiple claims. An unrelated payment to the same address is not evidence.
The native UTXO spend and canonical paid record jointly prevent replay; restore
must authenticate both. Unknown submission status triggers chain inspection
before retry, never automatic resubmission under a reused trial identity.

A continuing payout proves the remaining reserve outpoint/value and state
successor. The **last payout** proves all private/pending/exit/refund/fee
liabilities are zero and consumes the final principal without requiring a
positive minimum successor reserve. Any unavoidable state/permission rent and
native fee are separately funded/refunded by their stated owner. Zero principal
must not force dust, an unauthorized sweep or an unspendable mandatory state
output. Test both a user claim last and a fee claim last, including no-fee mode.
The exact terminal native script branch still needs implementation and rehearsal.

After restore, all canonical already-paid claims remain consumed even when old
private proofs, permissions or membership anchors are replayed. A branch with
missing payout history cannot be declared complete. Reorg rollback removes only
orphaned payments/claims and rebuilds from canonical ancestry; previously
submitted transactions must be reconciled before deciding what remains payable.

## 9. Recovery, backups and version boundaries

An independent recovery bundle contains authenticated genesis/descriptor and
canonical checkpoint provenance; complete ordered operation bytes and
acceptance/settlement proofs (or a verified snapshot plus complete suffix);
all commitments/nullifiers/ciphertexts; deposit/claim/paid/native reserve and
rent lineage; permitted anchor history; exact verifiers, encodings, public
proving artifacts and compatible software. A checksum authenticates bytes,
not chain authority or completeness. A public artifact must be fetchable from
another source and checked against its pinned identity.

Each user retains its spending/incoming-view recovery material and required
pending-deposit note/receipt metadata. Specify the exact backed-up data versus
seed-derived data when the selected suite is implemented; do not inherit the
model's deterministic keys or promise seed-only restoration. Incoming-only
viewing cannot derive authoritative nullifiers for all own notes. Orchard full
viewing material can derive own-note nullifiers and current spentness when
complete canonical history is available; neither viewing role can authorize an
exit. Full outgoing recipient/payment history may need other retained data.
No chosen-note path/witness is uploaded to a replacement prover.

Recovery authenticates lineage first, rebuilds all economic state, scans locally
and checks current spentness, then proves a spend/exit. Missing ciphertexts,
old verifying/proving artifacts, keys, ancestry, funding or confirmation yield
explicit incomplete/unavailable states; never a false zero balance or paid exit.
Persist state/cursor atomically and reject stale concurrent writers. Reorg
replay starts at a verified common ancestor or authenticated genesis; old anchors
and orphaned effects cannot survive as canonical balances.

Initial experiment accepts exactly one reviewed note/suite version. Legacy
unknown versions fail closed without an admin recovery key. Before accepting
another version require a shared economic spent set or proven one-way migration
consuming old claims exactly once, retained legacy artifacts/fees and voluntary
recovery for dormant users. A verifier upgrade is not a new nullifier universe.

## 10. Adversarial acceptance programme

Each vector must name the enforcing layer and retained evidence. Offline model
controls are useful fixtures; only the required real proof/native evidence
below closes the corresponding requirement.

| Group | Required negative/boundary cases and result |
| --- | --- |
| A: authority/membership | Wrong spend key or view-only key; mixed note/path/position; wrong or orphan root; forbidden/aliased point; mutated derived key intermediate; historical insecure circuit/VK. At tree counts `2^32-2`, `2^32-1`, `2^32`, verify exact capacity/no-wrap rules, atomic failed credit, pending refund and valid existing-note `exit_only`; all invalid cases fail without state effects. |
| B: nullifiers | Caller-selected marker; duplicate within a proof; two valid proofs on one old root across operations/batches/restores; different version/route/domain replay. One economic spend only. Dummy markers cannot bypass duplicate checks. |
| C: values | 0, 1, `2^64-1`, overflow of each intermediate/native output, field-modulus wrap, negative/float/bool encodings, absent change, hidden extra output and fee overflow. Valid boundaries conserve exactly; malformed/overflowing states reject. |
| D: output delivery | Good commitment with wrong recipient ciphertext, wrong key/ephemeral data, corrupted/truncated plaintext, inconsistent rho/seed, unsupported note version and unavailable last delivery. Invalid encryption fails proof; recipient never counts unusable or incomplete delivery. |
| E: intent/order | Mutate each public field, script, ciphertext byte and fee; substitute proof/VK/program/native ID; omit/reorder/truncate accepted sequence; stale prior state/cursor; unsupported flags. Reject without admitting a fabricated accepted state. |
| F: R13 real classifier | Actual full-relation valid A -> well-formed cryptographically invalid B -> genuine valid B; additionally all parser/curve/subgroup/VK controls. Complete outer proof verifies exact accept/reject/accept journal and unchanged middle economic state. Repeat across batch and restore. |
| G: credit/refund | Both race orders across batches/restarts; wrong recovery authority, amount, destination/outpoint, duplicate credit/refund, invalid inner proof then valid credit/refund. Reserve remains backed and exactly one pending transition wins. |
| H: native payout | Duplicate/diverted/underpaid/overpaid claim, reused output, unrelated same-address payment, wrong permission, replay after restart, fee/rent double charge, orphan payment, unknown submission, final user/fee/no-fee drain. No second release; exact canonical principal/rent accounting. |
| I: disappearance/privacy | Remove producer/executor/relay/archive; drop history/ciphertext/artifact; independent user backup only; empty and late restore; private canary in network/log/journal. Recover through declared public alternatives or report unavailable; do not disclose witnesses. |
| J: migration | Wrong/old verifier, alternate statement domain, orphaned migration and two-route consumption. Initial unsupported versions reject; any later migration needs its own proof/evidence. |

Adversarial second-pass conclusion: the principal inflation routes are unauthenticated
deposit amounts, partial intent binding, modular sums, freely chosen nullifiers,
omitted failed operations, missing paid markers and reused native outputs. The
specified enforcement points above address each as an obligation. The largest
remaining trust gaps are the unimplemented full circuit/verifier, canonical
native private-state binding, archive/checkpoint authentication and exact payout
scripts. Dependency loss may halt proving/payment; it must not select invalidity
or release reserve. No passing local test closes cryptographic soundness.

## 11. Review blockers and falsifiable completion gates

| Gate | Required deliverable before calling it implemented |
| --- | --- |
| P1: primitive/suite review | Exact note/key/tree/encryption/authorization algorithms and versions, two-slot/dummy and `exit_only` adaptation, capacity policy, deposit Ed25519 recovery descriptor/key-to-outpoint linkage, circuit/VK/program/control IDs, parameter/licence provenance, encoding lengths and golden vectors. Independent cryptographic review covers their composition, not only source names. |
| P2: full wallet implementation | Real proofs for every positive path and adversarial A–E/G vectors; constrained encryption and checked sums; independent public-input verification; local witness-only proving and measured full-relation resource costs. A preimage/sum proxy fails this gate. |
| P3: R13 outer proof | Full relation inside the ordinary verifier; complete outer receipt and independent seal/image/journal verification for F; exact current-state/batch replay checks. GPU qualification for the old proxy alone fails this gate. |
| P4: native integration | Accepted real ordered testnet operation bytes, deposit/recovery descriptor, pinned private-state settlement/covenant/permission scripts, reserve/fee/rent/native mass qualification, terminal branch and confirmed full lifecycle. No mainnet or real funds. |
| P5: R16 shutdown | Three separately restored users using only their own backups plus independently retained/authenticated public data and replacement proving software; usual app services absent; actual full proofs and confirmed exact native payouts for every user; zero principal reserve/unpaid liabilities with explicit rent reconciliation and duplicate rejection after restore. |

R16 evidence retains accepted native IDs/lineage, operation/receipt/journal
hashes and verifier/artifact pins, public reserve/claim/rent reconciliation and
per-user success/failure summaries. Do not publish spending/viewing secrets or
private values merely to make the report reproducible. Synthetic fixtures may
be public but must be labelled synthetic. Different processes on one machine
are not independent operators or hosts.

The current task produces this reviewable specification and measures GPU
qualification separately. It **does not** complete P1–P5, authorize a funded
trial, prove strong privacy, or mark R13/R16 real gates passed. Proposed next
implementation order: review P1; implement and qualify P2; produce P3; rehearse
P4 with a fresh unfunded trial identity and test KAS only; then perform P5.
