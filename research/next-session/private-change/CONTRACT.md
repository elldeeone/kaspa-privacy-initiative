# Private change and repeated owner spending: common contract

Accepted under ADR-0055 against `a8392f11`, 2026-10-23 UTC. This contract selects
the wallet API, random-u64 change indices, private slots and public sizing barrier.
Setup and live actions still require their concrete fresh-trial software and
body selections. No prior source, frozen evidence or trial is changed.

## Scope and unchanged authority

Extend the owner wallet through new packages to demonstrate requested partial
cashout, recovery of real private change, a private payment from that change,
another backup-only recovery and independent complete drainage. One real input
plus one dummy is the wallet scope; the circuit retains its two-input relation.

Keep Note168, Receipt216, Invoice208, ciphertext264, State112, Auth528,
public-update3344, payload4400 and the native program relation unchanged. Retain
the existing `AUTH528_PRIVATE_CASHOUT/v1` program label: private change is an
existing action of that program. Use a fresh trial identity/domain, seeds,
development setup/VK and public parameter selection. A changed compiled domain
changes the relation constants; matching dimensions alone cannot authorize an
old PK. Do not load or alter any prior trial's parameters or frozen packets.

Within one selected domain/VK, the same newly authenticated public parameters
serve ordinary private payment, partial cashout, continuing full cashout and
terminal cashout. Preserve owner-local proving, `parameters-ready` before backup
bytes, strict witness-FD schema and public-output allowlists from ADR-0053, with
ordinary selected executable releases and trusted-host assumptions of ADR-0054.

## Owner API and accounting

New strict request schema: `kpx3-private-change-owner-request/v1`.
Reuse the existing owner's public identity/software/manifest/fetch/backup/output
fields; reject duplicate or unknown fields. Operations are:

| Operation | Additional input | Required result |
| --- | --- | --- |
| `recover` | None | Recognize current private claims and historical owned native payouts from original seed backup plus complete fresh public replay. |
| `prepare-partial-cashout` | `payout_sompi` | Exact requested native payout and one positive self-change receipt plus one sealed dummy. |
| `prepare-private-payment` | `payment_sompi`, `recipient_invoice_path` | P0 payment to the authenticated public Invoice208; positive self-change or exact zero change. |
| `prepare-full-cashout` | None | Existing full-claim continuing or terminal cashout. |

Preparing additionally uses the existing local public-PK/prover/native-helper
paths and fee rate. Requested amounts are JSON integers, excluding booleans,
negative values, floats and strings. Normalize legacy external amount encodings
once at their boundary; all internal calculations use integer sompi. No caller
supplies a private-note map, CM position, membership path, operator witness,
saved action recipe or precomputed exit.

Initially choose the largest recognized `owner_action_available` claim, with
lowest position as tie-break. Include otherwise owned duplicate-invoice claims;
never select from `normal_credit_sompi` alone. There is no two-input aggregation
or general coin-selection search in this milestone. A refusal of the selected
claim does not establish that every possible owned-note combination is unable
to fund the request.

Let `V` be that real input, `R` the current reserve, `f` the actual selected fee,
`P` the native payout, `T` the private recipient payment and `C` self-change:

```text
partial: V = P + f + C; P = requested payout >= 10,000,000; C >= 60,000,000
payment: V = T + f + C; P = 0; T = requested payment >= 60,000,000;
         C = 0 or C >= 60,000,000
full:    V = P + f; C = 0; P >= 10,000,000
all:     R' = R - P - f; f > 0; R' = 0 or R' >= 60,000,000
```

All values obey the existing maximum `2,870,000,000,000,000,000` sompi and the
input/output/range constraints. Root selected support for exact `C=0` payments
through the explicit public sizing path below; a private transfer has no
mandatory retained balance. The main repeated-payment workload deliberately
has positive change. Never silently donate subfloor change or decrease `P`/`T`.

No timer, retained working balance, population threshold, operator approval or
other owner's cooperation is an exit condition. Full private exit remains an
explicit operation. An unavailable proof/data dependency safely halts; there
is no automatic REVEAL. The separate existing owner-authorized revealing
fallback is not weakened or made privileged.

## Fresh self-change and receipt recovery

Keep the V2 receiver derivation unchanged. For each newly prepared positive
self-change, draw eight fresh bytes from the OS CSPRNG and interpret them as a
uniform little-endian u64 invoice index. Derive its Invoice208 with the owner's
existing `Receiver.invoice(index)`.

Reject any candidate index already present in **all recognized historical own
receipts**, including spent receipts. Also reject a repeated receive tuple
`(owner, incoming, key_commitment, native_pk)` against those receipts and the
selected input/recipient descriptor. Resample on collision; do not use
`max(index)+1`, a fixed fixture index, a restored issuance counter, reserved
global namespace or a new child-seed primitive. The domain-stable delivery key
is deliberately outside this tuple: V2 requires it to decrypt the embedded index.

Hold the selected index, receive fields, note rho and private input/output
permutations fixed for one prepare action's fee-quote iterations. A new prepare
or retry, including after a fresh backup restore, draws fresh change material,
dummy input material and permutations. Once a candidate is selected for proof,
preserve its exact note/cipher/Auth/body bytes; never rebuild it after proving.

The backup predates every change. Restoration decrypts each retained public
ciphertext using V2's stable delivery secret, reads its encrypted u64 index,
rederives the descriptor and checks exact note/CM/current positioned NF. It
needs no index lookahead, saved operator map, note list or action recipe. Use
`receiver.keys(claim.receipt.index)` when spending recovered change; no index0
shortcut is allowed.

Freshness is probabilistic over a 64-bit namespace, not a uniqueness proof or
256-bit privacy claim. Checking known history cannot exclude unknown unpaid
invoices or orphan-only disclosures lost from the available history. A fresh
OS draw avoids deterministic reuse after rollback but cannot eliminate random
collision or lost RNG assumptions. Existing duplicate handling is unchanged:
mark all recognized reused-index claims privacy-contaminated; retain owner
authority and backing for every valid unspent accepted position. A later
duplicate cannot revoke or freeze earlier owned value.

## Private slots, fee quotes and recipient boundary

Independently OS-shuffle the real/dummy input order and the two continuing
private output roles once per prepare action. No fixed change slot, public
change flag or receive-index field is added. The real NF remains the original
positioned NF. Compute the dummy HMAC with its **actual chosen slot**, then
perform both authenticated NF updates in Auth NF order. Append CM/path/cipher
in the chosen Auth CM order. A recipient-plus-change payment has two genuine
positive receipts; a real output plus padding uses genuine sealed-box padding.

Every changed fee changes positive change value and therefore its Note, CM,
append roots, state and Auth. Rebuild all affected fields before quoting again.
Use a fresh established SalsaBox seal whenever plaintext changes; do not reuse
an ephemeral/nonce across changed plaintext. Keep only the final selected
candidate for the witness/proof/body comparison. The actual official mass/storage
quote and complete context determine the fee. P0 requires destination36 zero
and no native payout output.

For private payment, sizing must precede legal private-material construction:

The authenticated local prover may already be waiting on an **empty** witness
pipe after `parameters-ready`, preserving PK authentication before backup read.
Sizing never writes that pipe or starts proof generation and needs no second
parameter load.

1. Construct a **public diagnostic sizing action** with zero proof, canonical
   opaque dummy-output CMs/sealed padding, both exact current NF updates and
   public `P=0`, `R'=R-f`, fee, state/counts and context. It is continuing with
   two CM appends. It intentionally has no valid payment/private-conservation
   witness; create no private-action witness and send none to the helper/prover.
   The selected native helper must reach its expected failed-G16 quote seam.
   Keep sizing and actual candidates distinct in the API: a sizing candidate
   has no private-witness serialization method or field.
2. Use the provisional actual native fee to compute `C=V-T-f`. Reject negative
   or positive subfloor change. Build the **actual** recipient receipt plus
   positive self-change or legal zero-value dummy. Validate every private range,
   ownership, original NF, output CM and exact value equation locally before
   creating the final action witness or writing its FD.
3. Re-quote the exact actual public material/body. If the required fee changes,
   discard that candidate, repeat sizing as needed, rebuild/revalidate all
   fee-dependent actual fields and re-quote. Never infer acceptance or a fee
   identity from matching wire widths alone. An impossible fixed request safely
   fails without adjusting requested amount or turning residual value into fees.
4. Select only the final **actual-material** quoteID and bytes. Send only that
   witness to the authenticated local prover. Substitute only its genuine proof;
   require native Full/all engines and exact normalized actual-quote/body/context
   identity. A sizing Auth/state/body/quoteID can never satisfy this gate.

All unselected sizing/quote diagnostics, NF/Auth/candidate digests and bytes
remain private and unbroadcast. They
are not accepted transitions, authorizations to release KAS or evidence of
private conservation. No seed, note opening, s/k or witness enters the keyless
public native helper. Full and partial cashout retain their legal-candidate
quote path; partial always leaves positive change.

`recipient_invoice_path` denotes exactly 208 binary bytes supplied as public
recipient data through an authenticated recipient channel. Check current domain,
fixed width/magic, exact reencoding and nonzero receive/delivery fields. Frozen
`Invoice.parse` alone does not validate domain, curve validity, possession or
freshness; the existing crypto bridge supplies no public-point-validation API.
Do not invent one or claim these stronger checks. Authentic receiver derivation
and valid recipient key/encryption behavior remain explicit assumptions. In the
workload the recipient derives its invoice from its own original backup.
The sender witness never contains recipient s/k/seed. The recipient decrypts,
rederives, checks accepted CM and current NF before credit. Self-change is fully
locally rederived/decrypted and compared to its intended receipt before use.

## Current state, retries and disclosure retention

Every cold prepare starts with original backup plus a fresh complete independent
fetch/replay for the pinned founding identity. Before submission, recheck the
actual current outpoint/state/reserve and every consumed context. An occupied
original NF, changed head, wrong root/domain, missing receipt or incomplete
history halts. A genuinely valid alternative Auth under a new head is not a
replay-negative control. Never edit an old proof to rebind it.

The root alone submits once under durable canonical-transaction submission
markers. Ambiguous submission is resolved from fresh network evidence, not
rebroadcast. A failed live trial uses a fresh trial identity; no used identity
is retried with weaker gates. No owner action automatically broadcasts.

After a reorg rebuild the accepted public state: removed receipts are not
spendable and reverted NFs no longer describe current consumption. Prior
publications and disclosed receive fields remain privacy observations. Retain
available orphan/mempool records separately; never relabel them accepted or
erase contamination because canonical replay no longer includes them. Seed-only
recovery cannot reconstruct missing orphan ciphertexts or prove that no invoice
was previously issued. This milestone tests stale/competing current-state refusal
and current-head rebuilding, not arbitrary-reorg recovery or finality.

## Smallest decisive workload and limits

Follow the [six-body workload](lifecycle/WORKLOAD-PROPOSAL.md): one 10-KAS Bob
payment; requested 400M native cashout with positive change; restore from the same
old backup; 300M private payment to Charlie plus second positive Bob change;
restore again; Bob full continuing cashout; Charlie terminal cashout. Both
post-payment positive branches must independently recover and spend. End CM9,
NF11, R0 with all source change, native payouts and fees reconciled.

Local complete rehearsal requires five distinct genuine proofs under one fresh
setup and six actual-body Full validations with exact prior-output links.
Add one distinct genuine **local-only C0 private-payment fork control** under
the same VK: one real input, one recipient output plus dummy, public sizing
followed by exact actual re-quote and native Full. Its proof must not be a replay
of a main-route statement. This sixth local proof is an alternative supplied
context fork, never another live action or simultaneous accepted spend. The
main trace remains five proofs/six bodies; the extra control needs its own Full
result and is not relabelled part of terminal drainage.
After founding/P0 publication, stop the operator prover. Bob's three subsequent
actions and Charlie's terminal action each use a fresh owner process, original
backup and fresh public capture, producing four new local proofs. Cold mounts
exclude operator profiles, other owners, rehearsal exits, private recipes and
all previous attempt outputs. Public exports omit owner/CM/index associations,
private witness bytes/hash/path and backup/seed material.

Use component boundary controls for exact floors, invalid amount encodings,
fee-dependent receipts, both slot permutations, collision/reuse/duplicate
handling, wrong domain/recipient descriptor, spent originals and stale heads.
Use existing reviewed native/proof rejection suites as reference without
rerunning their old matrices or relabelling them new coverage. Add only decisive
new action/recovery and original-proof/body mutation controls. No observer score
is rerun or privacy threshold changed.

This is a functional research workload. Its single-owner intermediate reserve
exposes the remaining total; public payouts, fees, drainage, invoice-directory
links, counterparty records and network metadata remain. Positive change removes
the universal whole-claim-wallet equation `V=P+f`; it does not establish input
amount/owner ambiguity in this trace. Every added action fee is charged. The
two-recipient baseline shares three verifications: 1.5 checks and a 22,125,000-
sompi floor per 10-KAS recipient, already above the 20,000,000 complete-lifecycle
target at rate 100. It is not a universal floor for every ingress design. The
new five-check route has a 73,750,000-sompi verification-only total floor before
other costs. This larger trace neither qualifies that fee target nor financial
privacy, setup honesty, durable data/
parameter availability, independent consensus or production security.

Sources and rejected alternatives are recorded in [SOURCE-NOTES](design/SOURCE-NOTES.md).

## Identity and finite transport reuse

Reuse the unchanged fresh-identity constructor, identity schema
`kpx3-tn10-private-trial/v1`, `PRIVATE_TN10_TEST_KAS_ONLY` classification and
`KPX3/TN10/PRIVATE-RECOVERY/v1\0` domain tag with a NEW OS-random nonce. The legacy
label identifies the unchanged Auth528 protocol, not reuse of a used trial. A
new public reuse-selection record binds ADR-0055/this contract, fresh identity
and unchanged ADR0053/0054 source/template authority. Keep all old bytes.

The new trial transport may fork only the finite stage dispatch: `founding`,
`initial-payment`, `partial-cashout`, `change-payment`, `full-cashout`, and
`terminal-cashout`. Preserve exact whole-body/context/SDK checks, fresh UTXO
checks, strict TN10 identity and durable exclusive stage plus tx-ID markers.
All stages submit at most once. Native helper and generic network/replay may
remain byte-for-byte unchanged; no native program or cryptographic relation
change is authorized by this wallet decision.
