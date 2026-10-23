# Exit fee and owner independence: architecture options

**Recommendation:** after an explicit scope decision, test a **new future-format
hash/HMAC/Schnorr authorization primitive**, with separate private ownership and
revealed nullifier credentials, against current-state exclusion and full native
mass. This is the only one of the three routes below that could remove the
fresh-Groth16 fee assumption when an owner starts alone before an exit request
has been accepted. It is a hypothesis, not a selected format or a working exit.

Source baseline: `8d7d719f18ae5975e651a4a114f8cecceb3e8b7c`. This note changes
no source, target, invariant or immutable instance. It proposes no wallet,
owner CLI, public-ledger replayer, DRAIN proving, PK restoration, funding or
broadcast. The previously rejected S7 owner/replay workflow stays parked.

## The discriminator

Start with one valid, unspent, accepted private claim. Its owner has their own
backup and authentic public data. Stop preferred services **before any exit
request or withdrawal authorization is accepted**. Can the owner now construct
an authorized, self-funded exit alone? Ordinary network inclusion and public
data availability remain explicit assumptions; indefinite censorship is not
promised away. A permissionless terminal claim available only after earlier
authorization does not answer this starting case.
[R7/R8](../../../docs/rfc/0012-useful-privacy-requirements.md),
[I1–I11/I14/I16](../../../SECURITY-INVARIANTS.md).

| Route | State/authentication diagram | Owner starts alone before request acceptance? | Fee meaning |
| --- | --- | --- | --- |
| Accepted batch authorization → native claim | `private note → owner-authorized accepted batch consumes original NF → backed ticket/root → current single-use native claim → payout` | **Not established by the cheap terminal path.** The owner first needs accepted authorization, with its proof, data and fees; a stopped service cannot be assumed to provide it. | Amortizes earlier settlement and may remove a fresh proof from the terminal transaction. Count both stages and all per-user shares. |
| Future revealing fallback with shared NF | `accepted future note → reveal note-local NF credential + committed-key signature → check current original NF → insert that NF and pay` alongside `private proof(owner secret + NF credential) → same NF set` | **Potentially**, without a new proof or new collector acceptance, if the future format, private relation, immutable native branch and available-data obligations are actually satisfied. | Removes the particular fresh-G16 tariff. Whole-transaction mass, actual fees and complete-lifecycle costs still need evidence. |
| Present fresh-proof singleton | `accepted v6/S7 note → owner proof + current NF witnesses → native G16 check → NF insertion + payout` | Cryptographic authorization need not require an operator, but this instance's full independent workflow/data/resource evidence is missing; the economic small-claim condition fails at rate500. | Direct verifier floor is147,500 mass:73.75M sompi at500 before overhead, above a60M claim. Faster proving does not remove it. |

The current prior-only21.09772557% amount-guessing floor versus the unchanged20%
cap is a separate workload information limit. Cheaper exits cannot qualify that
workload. Emergency disclosure may be studied under the requirements, but its
effects on historical privacy targets remain in scope.
[Prior review](../../privacy-target-consistency-2026-10-22.md),
[fee frontier](../fee-frontier/README.md).

## 1. Accepted withdrawal authorization, then a cheap claim

Candidate shared state adds authenticated pending claims and their spent state
to the existing private-CM/current-NF state. An accepted owner-authorized batch
must consume each original private NF and create a stable entitlement containing
instance, claim ID, recipient, principal and fee authority. Merkle membership
alone cannot create that entitlement or authenticate an unaccepted request.

For one whole-note claim of value V:

```text
authorization: private liability V → pending claim q = V − f_auth
              reserve R → R − f_auth; original private NF consumed
terminal:     pending q → owner payout P = q − f_claim
              reserve → reserve − q; stable claim ID consumed
```

Until terminal payment, q remains a backed liability. The accounting gap cannot
improve merely by renaming a private note as pending. A separate terminal claim
ID is legitimate here because acceptance already consumed the originating NF;
it must remain stable across accepted roots, reordering and extensions. Claims
check **current** spent state and the actual reserve predecessor, including
reorg removal of their authorizing history.

A batch could instead create an actual native P2PK output. Then the pool has
already paid that principal; a later key-authorized spend is an ordinary native
spend, not a second reserve exit. Count its fee without counting its principal
twice. If anyone may trigger a claim without a signature, the payout must be
fully prebound. Variable claim fees need explicit owner authorization or a
predefined conservative policy; an arbitrary submitter must not burn principal
by changing fees. Sponsor-paid fees are someone else's cost, not self-funding.

The [Aztec Outbox](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L95-L156)
is an established authorization-then-membership/nullification pattern: only its
rollup inserts roots, and consumption checks the bound recipient/chain and an
unused message identity. This does not supply the missing earlier acceptance
for a lone KAS note. Current S7 J336/state has no pending-claim root or liability
accounting; it cannot be reinterpreted as one.
[Source seam](IMPLEMENTATION-SEAM.md).

Data needed after acceptance includes the accepted entitlement, membership
path/reconstructible leaves, current spent-claim state, authentic current native
predecessor and the owner's fee-signing key if applicable. No prover need remain
online for a properly designed terminal claim, but unavailable witnesses can
still halt it. Before acceptance, the owner also needs whatever authorization
proving/public parameters the selected settlement requires. Batch filling,
another user's cooperation and an unpaid future collector are not R7 guarantees.

Issuing standing tickets with every private output is a different design. A
public ticket reveals information; a hidden ticket that competes with later
private spending needs the exact same exclusion/authority problem as route2.
It is not evidence supplied by an already settled Outbox example.

## 2. Future revealing fallback: credential separation is essential

Current notes commit `(owner, incoming, value, rho)`. Ownership hashes the
reusable wallet spending secret and incoming key; positioned NFs are an HMAC
under that same secret. Native payout keys derive separately. A sender can
construct the note opening from public receive data, so the opening is not
spend authority. Revealing the existing wallet secret is not a note-local
escape. [Wallet/note](../../../poc/shared-pool/src/protocol.rs),
[NF](../../../poc/shared-pool/src/compact/mod.rs),
[actual v6 constraints](../../../poc/shared-pool/src/two_input/circuit.rs).

The following **candidate relation**, not a wire specification, uses only
existing SHA256/HMAC/Schnorr primitives:

```text
O = owner_hash(domain, private_owner_secret s, incoming)
K = SHA256(note-local NF credential k)
CM_future = hash(new tags/domain, O, incoming, u64LE(V), rho, K, exit_pubkey)
NF_future = HMAC(k, new positioned-NF tag || domain || CM_future || u32LE(position))

private branch: prove membership, knowledge of s satisfying O, knowledge of k
                satisfying K, exact NF_future, and value conservation
reveal branch: show opening + k; verify K/CM/membership and exact NF_future;
               require SIG_HASH_ALL under committed exit_pubkey;
               check/insert NF_future against current authenticated NF state
```

The private owner secret s and native signing secret stay private. Revealing k
must not satisfy the private ownership condition. The signature binds the real
transaction's predecessor, payout, fee-bearing outputs and payload; a new
signature under an uncommitted key proves nothing about this note. Enforce the
exact allowed hash type, canonical key/script/amount encodings and immutable
successor policy. The existing v1 signature excludes compute budget, so native
metering/full-mass checks remain mandatory.
[Pinned native sighash](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs#L248-L279).

**Reject the single-credential variant.** If revealed k alone proves private
ownership, an observer learns k and the opening from a pending reveal, builds
a private SPEND to attacker outputs and races the same NF. Only one transaction
wins, but the winner can be theft. A native signature required only by the
reveal branch does not guard the competing private branch. Neither faster
inclusion nor shared-NF uniqueness repairs this authorization error.

The recipient/descriptor contract is still unresolved and must precede a
useful format claim:

- The sender may use public commitments O/K and the public native key to form
  an output, but must not learn k. The recipient must independently derive or
  validate k and the native key from its own pre-payment backup/descriptor;
  accepting a sender-selected NF secret can make subsequent spending visible.
- Decryption/commitment consistency is insufficient. Acceptance must verify
  both spend paths are usable with the recipient's own retained keys and that
  the received K/native key match its descriptor. A malformed output must be
  deterministically rejected before crediting spendable value (R2/I14).
- Calling a credential “one-time” does not enforce note isolation. Reusing K
  across distinct CMs/positions can let one reveal expose other NFs. Keeping s
  private prevents the simple theft race, but does not remove that privacy
  linkage. Test malicious sender/descriptor reuse and duplicate-record cases;
  do not silently delete the existing multiplicity/position problem.
- The private and revealing relations must use byte-identical CM/NF/domain/
  position rules. A separate emergency-spent map is insufficient. CM inclusion
  proves existence, not current unspentness. Define single-real/dummy NF arity,
  counters, capacity and terminal-state behavior explicitly; current v6's two
  NF slots/even count cannot silently become one insertion.

For a whole-note exit with no external input, require `V = P + f`, reserve
`R′ = R − V`, and private liability `L′ = L − V`, with authenticated current
state, valid ranges and exact owner payout. A terminal case has no reserve only
when no liability remains. Fee choice must be owner-authorized; public k must
not let another actor redirect payout, increase a fee or corrupt the successor.
If the input state changes, refresh public witnesses and sign the new body;
an old current-state witness is not reusable authorization.

This route changes note fields, private constraints, VK/domain/version and the
immutable native policy. Existing notes/covenants do not acquire it. Migration
from an older note remains an authorized, costed transition, not a privileged
rescue or erasure of economically stranded liabilities. A proof-free signature/
hash checker does not establish that the future private circuit enforces this
relation.

[StarkEx's revealing escape](https://github.com/starkware-libs/starkex-contracts/blob/f3b250690c5d927a6e398e9c1735d9193a643034/scalable-dex/contracts/src/starkex/components/Escapes.sol#L10-L21)
shows authenticated-state disclosure with owner-bound recovery, but uses a
frozen vault system and per-vault exclusion, not concurrent positioned private
NFs. [Privacy Pools ragequit](https://github.com/0xbow-io/privacy-pools-core/blob/d494b63e79f33bb2b0c8ece6cdacdca465c3b884/packages/contracts/src/contracts/PrivacyPool.sol#L119-L135)
shares the normal nullifier consumption pattern, but still verifies a Groth16
proof and authorizes the original depositor. Neither is a drop-in transferred-
note fallback; reuse their obligations, not an unsupported cost conclusion.

Disclosure includes the note opening, value/position, linked CM/NF and emergency
public key. It can expose prior/future relationships through reused fields or
participant knowledge. R6 keeps the effect on historical ordinary targets in
scope. An owner-chosen revealing emergency path is not an automatic privacy
waiver or a qualified ordinary-payment policy.
[Requirements](../../../docs/rfc/0012-useful-privacy-requirements.md).
Disclosure is monotone: a rejected or later orphaned reveal may already have
published k and the opening. Rolling back reserve/NF state cannot undo that
knowledge. Subsequent private spending and descriptor reuse must be assessed
with the old public disclosure retained; the separate private-owner guard must
remain effective even when the revealed NF becomes unspent after a reorg.

## 3. Present fresh-proof singleton: keep the negative control

The existing owner/private NF relation does not need a new authorization
primitive. It does need authentic public state, correct keys/software and a
valid proof at the exact authorized fee. A suitable saved authorization might
avoid generating a new proof; otherwise public proving data and a prover are
needed. Native acceptance still pays the verifier charge in either case. Those
availability/resource properties are not established by the parked S7 workflow.

Its verifier alone costs73.75M at rate500. A60M note retaining the10M payout
floor has at most50M for fees. Per-user admission plus a fresh direct exit also
has a29.5M reference-rate proof-only floor, exceeding the20M lifecycle budget
for a10KAS principal under that unamortized route. These are conditional
current-route bounds, not universal privacy impossibility results. A sponsor,
owner top-up or another claimant changes the accounting/availability premise.
[Exact frontier](../fee-frontier/README.md).

## Minimal falsifiable next engineering step

**Select only a standalone, public future-format authorization/exclusion/native-
mass experiment after an ADR and relation review.** It must not import old
wallets, private material, PK/proving, owner restoration or public-ledger replay.
Use deliberately public test credentials and declared synthetic CM/current-NF
contexts, with no funding or accepted-backing claim. It is not a pool lifecycle.

1. Freeze the two-secret-plus-native-key relation above, canonical bytes,
   recipient descriptor assumptions and a small independent reference relation.
   Retain the single-credential theft trace as a mandatory failing design.
2. Test an actual pinned native hash/HMAC/Schnorr checker against supplied
   current context, exact payout/fee/successor and shared-NF updates. Require
   deterministic failures for wrong k/K/key/domain/position,
   modified payout/fee, weak sighash, stale NF/path/outpoint, prior private
   spend, duplicate reveal, malformed widths/counters and capacity. A reference
   private-side relation separately rejects a wrong private owner secret and
   public-k-only ownership. That equality check is not a genuine private proof;
   label it. The native reveal checker neither receives nor verifies s.
3. Separate the minimal primitive cost from a complete native body with all
   required witnesses, signature, outputs and current-state checks. Record full
   compute/storage/transient/mining mass and actual fees at100/200/500. No G16
   tariff may be assumed for a G16-free branch, and no absent check may be
   omitted to obtain an appealing fee.

Predeclare these economic discriminators:

| Question | Necessary screen; not sufficient qualification |
| --- | --- |
| Can a60M claim self-fund at500 and retain10M payout? | `f ≤ 50M` and full mining mass `≤ 100,000`, with no external fee input/subsidy. |
| Can a10KAS lifecycle fit2% atreference100 with an unamortized v6 ADMIT? | After its147,500 verifier-mass floor, only52,500 mass remains for **all** payment, terminal, funding and other attributable costs. A100,000-mass terminal claim would fix the first screen while still failing this one. |
| Can the owner act after pre-request shutdown? | No batch, new proof, service response or private controller export is required for the revealing checker; authentic current public data and retained owner credentials are explicit inputs. This bounded checker still does not establish a complete wallet recovery/inclusion workflow. |
| Does revealing k retain authority/privacy boundaries? | k alone cannot satisfy private ownership; no reusable owner/native secret is revealed; descriptor reuse and the resulting disclosure remain explicit adversarial cases. |

If authority/exclusion fails, stop before interpreting mass. If full mass misses
the100,000 singleton screen, this candidate does not solve the named small-claim
problem. Passing it advances only a resource/authorization gate; full-lifecycle
economics, the future private circuit, durable public data, independent owners,
contention/reorg handling and unchanged privacy targets remain open. Route1
remains useful for already accepted entitlements, but cannot substitute for the
pre-request shutdown case. No implementation is selected by this note.

## ADR-ready candidate C: public conformance and complete-body cost screen

This contract narrows the proposed next step. It selects no deployable note
format and authorizes no experiment by itself.

**Statement.** A supplied, synthetic reserve input authenticates a new-version
state with current CM/history/NF roots and counts. A disclosed future-format
note commits to `O`, `incoming`, integer `V`, `rho`, `K = SHA256(k)` and one
canonical 32-byte Schnorr public key. Fix new domain-separated CM/NF tags and
all byte widths before implementation. `O` retains the existing undisclosed
owner-hash relation under s. The private reference requires both s and k;
the native reveal receives k and the opening, never s.

The native policy must enforce all of the following atomically:

1. Recompute K, CM and `NF = HMAC-SHA256(k, tag || D || CM || u32LE(position))`.
   Prove the position is in the declared commitment prefix. A historical anchor
   must be authenticated by the input state's history root/count; an arbitrary
   supplied CM root is insufficient. Include both current and historical
   synthetic contexts in the frozen cases.
2. Authenticate the predecessor/empty-append witnesses against the **current**
   indexed NF root, apply strict numeric little-endian ordering and insert this
   exact NF once. Define a new-version single-insertion counter/capacity rule;
   retain the sentinel and pointer invariants. No old even-m compatibility is
   implied. CM/history roots and counts remain unchanged during this exit.
3. Require the committed native key's signature over the actual transaction,
   with the exact `SIG_HASH_ALL` byte. Allow one reserve input, no sponsor/top-up,
   and only the declared owner payout plus continuing reserve output. Check
   `0 < V <= R <= MAX_SOMPI`, `0 < P`, `V = P + f`, actual native fee f and
   `R' = R - V`. The successor binds the updated NF state and identical immutable
   policy/profile. For the minimal experiment choose `R > V`; a zero-reserve
   terminal case remains unsupported until liability exhaustion is established.
4. Reject malformed encodings, wrong opening/k/K/key/domain/position, weak
   sighash, payout/fee/successor substitution, wrong current outpoint, occupied
   NF, duplicate insertion, stale paths and count/capacity overflow. Frozen
   competing-private-spend fixtures mark the identical NF consumed through an
   explicit private-relation oracle; they are not real private transactions.

**Source reuse.** Existing note/owner and HMAC relations are in
[`protocol.rs`](../../../poc/shared-pool/src/protocol.rs),
[`compact/mod.rs`](../../../poc/shared-pool/src/compact/mod.rs) and
[`two_input/circuit.rs`](../../../poc/shared-pool/src/two_input/circuit.rs).
CM/history folding and current indexed-NF insertion reuse the semantics of
[`two_input/tree.rs`](../../../poc/shared-pool/src/two_input/tree.rs) and the
independently checked state-assertion corpus, not its old note/profile bytes.
Pinned native `01b532e8b553523216471682649693af92f0fd16` supplies
[`OpXor`, `OpCat`, `OpSHA256`, `OpCheckSig` and transaction introspection](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs).
Compose standard HMAC from its SHA256 block/pad definition; freeze an independent
library vector for the exact 32-byte key/message layout. No new hash, signature
scheme or proof system is introduced by the probe.

**Decisive output.** After all authority/state controls pass, an actual official
Full validator run and consensus mass computation can determine whether this
complete synthetic body has mining mass at most 100,000. Include its real
redeem/scriptSig/payload/signature, every witness, every output and compute/
storage/transient dimensions. At rate 500, select and verify a fee meeting the
actual mass quote while leaving at least 10M sompi from the 60M claim. A bare
opcode benchmark cannot answer this question.

The future union/private branch's exact body is not yet known. Freeze a
conservative total-redeem size envelope and include corresponding padding in
the measured body, or state that the result qualifies only the standalone
policy. Any later union exceeding that envelope invalidates the extrapolation.
Passing the 100,000 screen is also insufficient for the separate 52,500 residual
lifecycle screen above.

**Unresolved after a passing probe:** the real future private circuit and its
new VK/setup; output construction/recipient descriptors hiding k from the
sender; durable backup/one-time-key reuse and record multiplicity; data
availability/current-witness reconstruction; authentic initial backing and
history; contention/reorg/inclusion; migration/version isolation; and emergency
disclosure versus unchanged ordinary privacy targets. Public test credentials
and supplied roots establish none of those properties. No old S7 owner workflow,
adoption, genuine owner DRAIN or end-to-end exit claim follows.
