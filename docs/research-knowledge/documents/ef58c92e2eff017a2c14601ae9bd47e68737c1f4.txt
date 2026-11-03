# Owner-local wallet and authorization boundary

Source/API preparation for the new unfunded ADR0063 prototype. The normative
financial statements, scalar/point formats and body encoding come from
`research/next-session/owner-private-prototype/CONTRACT.md` and the sibling
relation, verification and construction packages. No relation is selected by
this wallet document. It does not read or migrate any old wallet backup.

## Reuse and minimal private authority

Reuse the exact existing `future-recipient/v2/recipient.py` source at SHA256
`93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2`:
Note168, Receipt216, Invoice208, domain-separated SHA commitments, positioned
HMAC nullifiers, owner-local HMAC derivation, sealed-box creation and receiver
decryption/rederivation. The existing RustCrypto/libsecp adapter is public code;
its selected crypto executable identity is
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`.
Secret requests use child stdin inside one owner namespace, never host argv.
Its source errors are constant categories and do not echo requests or keys.

All fixtures use fresh owner-local seeds and notes under new D
`32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d`.
The note's native public key remains encrypted/private. There is no separate
BIP340 or Binding signature. Each input note retains its original opening,
authority, original physical position and original positioned NF across retries.
Position is depth16: no ignored upper bits may create an alternate NF.

Input value commitments use a fresh owner-local scalar for every construction
attempt. They are proved against the input note's hidden value/membership.
Output creators choose fresh output scalars. No previous output-CV scalar is
needed to spend an incoming note, so Receipt216 and CF264 need no new field/KDF.
The recipient checks decryption, its invoice, Note/CM/value, and the genuine
Output proof for that CM/CV/CFH. Encryption correctness is not proved by CFH.

## Private processes and data flow

Each of three owner workers has only its own fresh private directory mounted.
It can read the common authenticated public session/profile/initial state,
private participant-bound peer invoices, current selected body, public proving parameters and fixed
crypto/proof programs. It cannot see the other owners' private directories or
the old original wallet directories. Child Output/Spend provers run inside this
same owner boundary with the minimal selected witness over stdin; no root seed,
foreign witness or complete private owner plan is sent to a proof coordinator.

Output creation happens entirely inside that worker: construct its two notes,
CFs, commitments, value openings and genuine Output proofs. Their complete
520-byte rows and individual beta are never exported to the coordinator.
Private proof logs, creation times, rows, row hashes and owner-output mappings
stay in the owning directory. There is no public per-output READY receipt.

The worker writes the construction package's frozen `codec.owner_input()`
encoding directly to its own opaque MPC-input directory:

```text
Input-P{party}-0: exactly35 zero-padded76-digit decimal lines, mode0400,2695bytes
row0: 17 little-endian31-byte limbs
row1: 17 little-endian31-byte limbs
beta: (r_in - r_out0 - r_out1) modulo selected BabyJubjub q
```

Each complete row is `CM32|CV64|CF264|CFH32|OutputProof128`; its last seven
packing bytes are zero. The owner selects no modulus by reducing arbitrary
wire bytes. The stock MPC party opens only its own file inside its private
container and normalizes the fixed-width input only in owner memory before
piping to the engine. The coordinator never opens or hashes an input file and receives
only the final common mixed six-row pool plus aggregate Delta after all three
stock malicious engines agree. Opaque input-directory selectors are private
controller handles, not public artifacts.

The worker may emit only a neutral readiness result: fixed operation status,
public session/profile identity and counts. It emits no output row, CM/CF/proof
hash, individual beta/point, private path, per-proof timing or creator metadata.
Input NF/CVin skeletons and post-mix Spend proofs may identify an input owner;
they never identify an output subset. The shared effects digest is identical
for all owners and covers the entire mixed pool.

## Checks before financial authorization

The post-mix owner operation independently parses the common exact native
projection/body through the selected public verification codec; it does not
reimplement the sibling's byte layout with JSON hashing. It checks:

1. The exact new domain/session/roster/profile and prior point/state; canonical
   integer amounts, zero payout, reserve decrease and approved fee policy.
2. All six complete tuples and genuine Output proofs; every own required
   payment/change tuple appears exactly once without modification. It checks
   its exact created CV openings and all receipts it can decrypt against the
   expected local invoice, note commitment and proof.
3. The current original NFs and the authenticated NF/CM transition; its own
   original input remains authorized/current and its advertised fresh CVin
   matches that note's bounded value and locally retained scalar.
4. The direct global group balance equation, fixed counts, all canonical
   points/scalars and the same complete effects digest computed locally.

Only after those checks does it irreversibly close the attempt's disclosure
path and generate its genuine Spend200 proof. Effects include all six complete
Output tuples and their Output proof bytes. Spend-proof bytes are excluded, so
valid same-statement witness malleability is allowed; there is no literal
wire-byte seal claim. No per-owner output digest, CF subset or beta accompanies
the Spend export. No caller boolean certifies a proof or accepted state.

## Abort, retry and truth separation

There is no owner-secret/map reveal API, including blame, reconnect, loss,
retry or error handling. After any exported financial authorization, a valid
old body may still settle. Preserve that body and reconcile current accepted
state/NFs before a retry or independent action; unknown remains INCOMPLETE.
Nothing claims that a timeout revokes an existing proof. Fresh retry material
means a new session/MPC identity, fresh input scalar, output randomness,
complete rows and private contribution, while preserving original note
authority/NF and financial setup.

An exclusive owner-local file lock serializes every operation. Before financial
authorization, a new session archives its old fixed-width input by private
rename into the prior generic attempt directory. After the durable disclosure
barrier, all prepare/authorize requests halt before reading old maps or assets.
This prototype supplies no accepted-state reconciliation or post-auth retry API.

Per-owner hidden truth stays in its private directory for a separate truth
oracle. Neither coordinator nor attacker receives it. The oracle can inspect
the owning records only after the attacker result is sealed. No public file
names, fixtures, manifests or logs publish actual owner-to-output tuple maps.

Before host public reads/hashes/copies, collect metadata-only exclusions for
all eight old original backup inodes and complete owner directories. New owner
private material receives the same own/foreign path and alias protection through
three whole party parents, each containing its own owner and MPC children.
Private engine certificate symlinks are inspected only with lstat and never
followed; all secret writes remain regular files beneath those private parents.
Each designated peer leaf is fixed240bytes: participant_id32 followed by its
Invoice208. The owner checks the private participant binding against the public
roster before creating a payment, so reordered peer handles cannot redirect it.
Never open, copy or hash an old backup. A trusted same-host controller/daemon
and pinned software remain explicit premises; namespace isolation is not a
claim against malicious host administration.

The first useful result is one genuine three-owner/six-output body accepted by
the new unfunded predicate, with retained malformed/omitted/duplicate/wrong-
context/party-loss/late-disclosure negatives. It is not a privacy score, native
funding rehearsal or production-security approval. Root's contract/source
review precedes implementation execution and scheduled proving/setup jobs.
