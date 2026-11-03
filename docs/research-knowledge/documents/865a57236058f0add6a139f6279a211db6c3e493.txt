# RFC-0010: Independent deposits without replacing saved exit proofs

**Status:** Open — scoped, not implemented or tested.
**Date:** 2026-10-19.
**Branch:** `shared-pool-four-wallet`; inspected baseline `d67e174`.
**Scope decision:** [ADR-0022](../adr/0022-compact-two-note-deposits.md).

## Question and smallest useful result

Can four separately funded wallets join one compact native-KAS pool, preserve
exit authorizations prepared before later deposits, and withdraw every claim
without the original prover, another wallet or a privileged operator?

**H10:** after a verified initial bootstrap, three ordinary signed deposits can
each add exactly two backed notes without spending or changing any existing
claim. All eight resulting notes can then exit with the exact authorization and
proof saved immediately after their creation. Only public settlement data changes.

Passing would justify using actual independently funded deposits in the later
[Stage 2 privacy study](0009-compact-anchor-privacy.md). Failure selects a concrete
admission/accounting or proof-compatibility redesign. This is a prerequisite,
not completion of Stage 2 and not a test of real-world anonymity.

The current authorization circuit is already a two-output value-conservation
proof. Reuse that relation for externally funded admission rather than introduce
a separate deposit circuit. Change the native covenant and public state builder
in a **new immutable pool version**, provisionally v5. The deployed v4 pool code,
proofs and evidence remain intact. A v4 proof does not become a claim in a new
pool: the preservation requirement concerns v5 proofs created **before later v5
deposits**. No migration or in-place upgrade is proposed.

This document authorizes no implementation, experiment, funding, TN10 activity,
push or upstream publication. A later implementation/run needs user authorization.

## Grounding and assumptions

The [source review](../../research/compact-deposits-source-review-2026-10-19.md)
pins current Kaspa/KIP/upstream sources and compares Orchard, Aztec, RAILGUN,
Monero, MWEB and vProgs. Kaspa provides multiple native inputs, input/output and
payload introspection, ordinary Schnorr authorization and the existing proof
verifier. No additional consensus primitive has been identified as necessary.
That is a source-supported composition proposal, not native acceptance evidence.

Keep the native/SDK pin `01b532e8b553523216471682649693af92f0fd16` for comparison.
Reuse the exact v4 circuit/PK/VK, hash definitions, positioned nullifiers,
depth-16 trees, note/delivery encodings and fee/payout binding. Pin the intended
new pool's genesis, domain, full immutable code and existing VK in its public
descriptor. Single-party setup, unreviewed cryptography, a correct chain view,
available authenticated public history and sufficient fixed fees remain
assumptions. Do not reinterpret any [security invariant](../../SECURITY-INVARIANTS.md).

## Native transaction and private statement

The following is the proposed deposit shape; normal transfer/exit branches retain
their separate real-membership and current-spentness checks.

| Field | Required deposit value |
| --- | --- |
| Input 0 | Current reserve UTXO, value `R`; proof and the new immutable redeem script |
| Input 1 | Depositor's ordinary noncoinbase P2PK UTXO, actual value `D`; valid native Schnorr signature |
| Output 0 | Only output: successor reserve of exactly `R + D - fD`, same code/domain/VK and exact next state |
| Native fee | Exactly `fD`, deducted entirely from new private credit |
| Transaction framing | Version 1, native subnetwork, zero gas/locktime, maximal input sequences, no covenant metadata |
| Extra inputs/outputs | Rejected; no deposit change, public payout, sponsor or operator input |

Consume the whole funding UTXO. A wallet needing a different deposit amount can
prepare an ordinary UTXO separately; count its fees and visible ancestry. All
values are integer sompi; check ranges, subtraction and the aggregate input bound
before arithmetic. `R + D` must not exceed `MAX_SOMPI = 2,900,000,000,000,000,000`.

Input 1 must have the ordinary 36-byte encoded P2PK script and the canonical
66-byte signature script: `0x41 || Schnorr_signature[64] || 0x01`.
`0x01` is exactly `SIGHASH_ALL`, without `ANYONECANPAY`. Native validation must
verify it against the actual funding UTXO. This signature binds input outpoints,
outputs, its own amount/script and the nonempty payload. It does **not** sign
scriptSig bytes or v1 compute budgets. The covenant can enforce canonical script
shapes; native metering enforces the declared execution budget, while the builder
and relay checks select sufficient budgets/fees. Do not assume the covenant can
pin a compute-budget field without an introspection opcode. Budget mutation may
invalidate execution or relayability, but must not change credit or payout. This
is not a signature over every byte.

The unchanged 265-byte private authorization uses:

| Authorization field | Deposit interpretation |
| --- | --- |
| `domain` | This new pool's pinned domain |
| `mode`, `count` | Transfer relation `1`; virtual input count `1` |
| `bootstrap` | Actual input-1 value `D > 0` |
| `anchor`, `nullifier` | Virtual private input's root and positioned nullifier; **not** pool membership or spentness |
| `outputs[2]` | The two new private note commitments |
| `payout`, `spk` | Zero and 36 zero bytes |
| `fee`, `cipher_hash` | `fD` and SHA-256 of the two 185-byte delivery ciphertexts |

The existing circuit proves ownership of its private input, value/range bounds,
two distinct positive output notes and `D = v0 + v1 + fD`. The nonzero
`bootstrap` field equates the private input value to `D`. With `count=1`, the
constrained private position is zero. A standard wallet constructs a virtual
singleton tree; its root need not be authenticated as real pool history because
the native funding input, not an existing pool claim, supplies the value.

Do **not** insert that virtual input commitment, root or nullifier into any pool
tree. Do not suppress real membership/spentness checks in the ordinary spend
branch. The deposit proof is an admission statement, not permission to consume a
real note without its nullifier. Native branch selection and actual backing
checks are part of the security argument; the circuit alone does not make this
composition safe.

No separate virtual-commitment field, second proof or deposit-context hash is
proposed. The proof binds `D`, credit, fee and ciphertext digest; the covenant
compares `D` with the actual input; the funding signature binds the intended
transaction and payload. The native funding key need not equal the virtual
note's private spending key. Before signing, the depositing wallet must verify
its intended commitments, values, recipients and decryptable delivery: the
existing circuit binds the ciphertext hash but does not prove correct encryption.

Each output note must be at least 60,000,000 sompi, so:

`D >= 120,000,000 + fD`.

This higher minimum and two future full exits are the cost of avoiding a new
private relation/setup. Two notes are not two independent participants.

## Covenant, state and framing changes

Keep the 105-byte state layout, with a new application tag `5`:

`tag[1] || cm_count[4] || nf_count[4] || cm_root[32] || nf_root[32] || history_root[32]`.

After validated bootstrap, require `nf_count >= 1`, `cm_count >= 3` and an open
reserve. A deposit changes `(C, N)` to `(C+2, N)`. Authenticate two empty append
positions, insert the two commitments, and append the exact resulting root/count
to history. `nf_count` and `nf_root` must remain byte-identical. Preserve every
earlier commitment and history entry. Odd counts retain the existing history
index `(count-1)/2`; the new history leaf is at `(C+1)/2`.

Proposed deposit payload: `KPICD01\0` followed by the unchanged authorization,
370 ciphertext bytes, next state and fixed witness. Total remains 3,892 bytes:

| Byte offset | Length | Content |
| --- | --- | --- |
| 0 | 8 | Deposit magic |
| 8 | 265 | Existing `KPICU01\0` authorization |
| 273 | 370 | Two ciphertexts |
| 643 | 105 | Next v5 state |
| 748 | 1,608 | Canonical zero padding: unused membership/nullifier-spend witness slots |
| 2,356 | 1,024 | Two commitment append paths |
| 3,380 | 512 | History append path |

The existing normal-operation envelope `KPICR01\0` keeps one reserve input.
After bootstrap it requires authorization `bootstrap=0` and authenticates the
real historical anchor and current nullifier insertion. Deposit framing requires
two inputs, `mode=1`, `count=1`, positive `bootstrap`, and its distinct transition
checks. Reject cross-mode framing and malformed sizes rather than guess a mode.

The private proof stays 128 bytes and the VK 328 bytes. The new redeem-script
length, compute budget, native mass and required fees are **unmeasured**. Existing
v4 code hardcodes one input and spend transitions; it is not a usable deposit
builder. Add a distinct public deposit builder/replay path in the proposed
version; do not route admission through the existing nullifier-inserting helper.

## Genesis and proof preservation

Retain the current first-depositor model. Alice funds a canonical singleton
reserve, then proves an ordinary private self-split whose initial note value
equals that reserve. Only afterward can Bob, Carol and Dave deposit. Alice has
no continuing privilege. A zero-value reserve is rejected by native consensus;
an empty-genesis or public subsidy mechanism is outside this scope.

Before joining, each wallet independently checks its pinned public descriptor,
initial commitment, canonical singleton commitment root, empty nullifier tree,
singleton history, actual funding and every accepted transition. The existing
native bootstrap authenticates value/NF/history but does not reconstruct the
initial CM root from a supplied singleton CM. A creator-chosen script claiming
`nf_count >= 1` is not proof of valid genesis. No operator assertion substitutes
for descriptor validation and accepted-lineage replay.

Append-only commitment/history trees preserve the old exit anchor. Unchanged
nullifier state during deposits preserves current unspentness. For an unspent
note, retain **identical authorization, proof, fee and payout**; rebuild only the
transaction's current reserve outpoint and public authentication/update paths.
Normal exits still insert the note's nullifier and reject a second spend.

A conflicting reserve spend invalidates the deposit's native funding signature,
which names that reserve outpoint. Its owner can rebuild public data and re-sign
without another private admission proof if credit/fee/outputs are unchanged.
Do not promise unchanged deposit transaction signatures or contention fairness.

Replaying the same spent funding input must fail. Reusing an admission proof with
a different, newly signed input of the same value creates separately backed
positions and is not inflation; positioned nullifiers keep those claims distinct.
Treat this as a positive accounting control, while ordinary wallets generate
fresh commitments/ciphertexts to avoid the obvious public repetition link.

## Bounded future experiment

The primary fixture uses four separate funding keys/UTXOs and four 10-tKAS
contributions, each `1,000,000,000` sompi. Record actual public funding ancestry;
different keys do not prove unrelated humans or unrelated upstream funds. A
shared-funding privacy control belongs to the later population study.

1. Alice creates her reserve and self-splits into two own notes. She immediately
   saves both exit authorizations/proofs at commitment count 3, then stops her
   prover. The seed note is already spent.
2. Bob, Carol and Dave each deposit once. Each receives two notes, checks them
   through its own ciphertext-scanning path, saves both exit proofs immediately
   at counts 5, 7 and 9 respectively, and stops its prover before the next wallet
   joins. No controller exports plaintext notes to the wallet.
3. Stop original experiment services. Give each isolated exit client only its
   two private bundles and authenticated public descriptor/VK/history/current
   state. No wallet secrets, PK, other-wallet files or privileged signer are
   needed to settle these already-prepared exits. Drain Dave, Carol, Bob, then
   Alice, both notes per wallet. Alice's early proofs must survive three later
   deposits and everyone else's exits. Other wallets need not cooperate with an
   exit; every client must be able to take the terminal role.

Use a fixed 400,000,000-sompi first note and a second note of
`600,000,000 - creation_fee` for each contribution, subject to the measured fee
and note floors. This deliberate split is an accounting fixture, not privacy
traffic. Fix each note's exit fee before creating its proof, sufficient for both
continuing and terminal settlement under the declared fee rate.

The main path is **13 native transactions**: one ordinary funding, one bootstrap
transfer, three deposits and eight full exits. It needs **12 genuine private
proofs**: bootstrap, three admissions and eight exits. Exclude and separately
count any ordinary funding-input preparation. Reconcile nine actual created
commitment positions, nine spent claims at completion, zero liabilities and no
remaining reserve.

Replay exits in exclusive offline states using the same prepared bundles:
`D,C,B,A`, `A,B,C,D`, `A,C,D,B` and `A,B,D,C` (two notes per wallet).
These four orders exercise each wallet's terminal role; only the primary order
defines the 13-transaction path. They require no replacement private proofs.
A separate small regression must transfer a deposited note privately, then let
its recipients drain all resulting claims. Do not expand the main fixture into
a traffic simulator, partial-exit feature, batch deposit or live race test.

## Controls and completion criteria

All are future requirements; no new test result is recorded here.

| Obligation | Required evidence/control |
| --- | --- |
| Backing and ranges (I-1/I-2/I-7) | Exact sums after every accepted transaction; reject one-sompi overcredit, wrong successor value/fee and underfunded admission. Check note/deposit minimum below/at/above boundaries, MAX/aggregate overflow and native payout/dust limits. Existing users never pay a new deposit's fee. |
| Funding authorization (I-3/I-6) | Reject missing/wrong-key signature, weak hash type, substituted funding outpoint/amount/SPK and post-signature payload/output changes. Signature-script and budget handling account for fields excluded from SIGHASH_ALL. |
| State/proof binding (I-4/I-5/I-6) | Native checks reject wrong domain/VK/code, malformed proof/framing, cross-mode authorization, premature deposit, wrong append/history paths and any deposit change to NF count/root. Joining-wallet descriptor/replay checks reject forged genesis and truncated lineage; native script does not fetch ancestry. At capacity reject admission while valid exits remain possible. |
| No second spend (I-4) | Reject funding-input replay. After an exit, reject another authorization for that economic note against the current successor, not only against an already-spent UTXO. Test both winner orders. Separately accept legitimate repeated admission proof with fresh signed backing and independently spendable positions. |
| Delivery (I-14) | Each wallet checks its own accepted ciphertext/commitments and rejects malformed or mismatched receipt before recognizing spendable balance. No test-controller plaintext shortcut. |
| Proof survival and exits (I-8/I-10) | Hash/byte comparison of each of eight saved authorizations/proofs; four isolated clients, no PK/prover/operator help; both exit orders and each wallet's terminal role; exact payouts and complete drain. Ordinary transfer regression remains valid. |
| Data failure (I-9/I-10) | Replacement authenticated public source suffices; wrong/stale source is detected against the independent chain view. Loss of all required public data safely halts and is reported as failed availability, not successful recovery. |
| Reproducibility (I-11) | Record source/native/descriptor/VK identities, accepted transaction bytes, mass/budgets, fees, proof/rebuild time, client input inventories and stop/isolation evidence. Keep private backups/openings/unused authorizations outside Git. |

Before any future live run, require native Full validation, default relay-policy
checks, SDK/JSON transport round trips and complete offline drainage. A later
authorized TN10 test must first rehearse the complete path including terminal
payout, then use a fresh trial identity. Source inspection is not relay evidence;
offline validation is not live confirmation. Timers/resource caps are harness
observations, not reasons to weaken safety or strand a funded trial.

## Cost gate and stopping conditions

No fees have been measured for the new covenant. At the historical comparison
rate of 100 sompi/mass, v4 measured 21,688,400 sompi per transfer and 21,729,600
per exit. These are references, **not v5 estimates**: added code may change every
operation's mass. Measure continuing and terminal exits and all deposit inputs
before freezing authorizations. The fixed circuit floor requires:

`largest configured exit fee + 10,000,000 <= 60,000,000 sompi`.

If it fails, stop and redesign; increasing a wallet-only minimum does not fix
the protocol's ability to create stranded notes. Preserve fixed-fee proof
limitations if network fee requirements later rise; do not silently reprice an
old authorization or promise unconditional exit liveness.

With a common sufficient fixed exit fee `fE`, the main path costs:

`f_genesis + f_bootstrap + 3*f_deposit + 8*fE`.

The eight payouts must total
`4,000,000,000 - f_bootstrap - 3*f_deposit - 8*fE` sompi. Ordinary genesis funding
and optional input-preparation fees are external to those four contributions
and reconciled separately. Two notes mean two full exits per depositor; report
this cost before selecting the design for a wallet. Current warm proof/cold-load
timings do not substitute for measuring the proposed path. This scoping step
spends no test KAS.

Stop or redesign if admission can dilute old backing, erase spentness, accept
an unverifiable lineage, require new private exit proofs after a deposit, require
operator secrets, strand any claim, fail the fee-floor inequality, or need a
changed private relation/setup or L1 consensus rule. A different circuit remains
an alternative requiring an explicit new decision, not an unnoticed scope change.
Preserve failures and existing variants.

Stop adding mechanics once this bounded prerequisite works. If public amounts,
funding ancestry and anchors still force the tested relationships, report that
before building a larger privacy simulator. Four keys/eight notes alone supply
no practical-anonymity result. Chain-only observation includes native amounts,
scripts/outpoints, order/timing, commitments, ciphertexts, anchors, nullifiers,
proofs and public witness paths; public test labels and private truth are excluded
from the observer. RPC requests, IPs and peer observations are a separate threat
model. Keep Stage 2's existing population thresholds unchanged.

## Outcome

Scoped only. The source review found no missing current-L1 primitive for this
candidate. Covenant composition, fees, four-wallet independence and unchanged
proof settlement remain untested. [ADR-0022](../adr/0022-compact-two-note-deposits.md)
records the bounded design choice and alternatives; it does not accept a protocol.
