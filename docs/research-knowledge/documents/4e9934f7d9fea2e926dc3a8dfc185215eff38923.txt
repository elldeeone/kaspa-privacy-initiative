# Original-only payment and recovery integration

`private_lifecycle.py` runs four operations in separate one-owner, network-off
namespaces: private invoice, private payment input preparation, scan, and direct
AuthExit preparation. It reopens one strict new-profile Original leaf per owner.
The controller never opens, hashes or decodes those Originals, owner notes,
invoices, witnesses, MPC input files, candidate Exits or private logs.

This source is **not yet an executed private lifecycle**. Its history entry
accepts only `UNFUNDED_SUPPLIED_CONTEXT`. A caller's `accepted` field or changed
scope is rejected. The genuine aggregate/R0/native proofs, accepted whole-CASE
acquisition and strict new GEN3 admission remain separate requirements. No
funding, submission or network operation is available in this controller.

## Workload and private outputs

The prospective pool is exactly
`d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf`,
matching the actual aggregate setup. It is allocated before GEN3; the supplied
fixture outpoint is not accepted funding. Domain/ProfileID/service are checked
against the selected descriptor and every supplied current head.

The fixed benchmark remains three20-KAS initial notes; round one sends5KAS
forward; round two sends2KAS backward. Owner1 spends recovered round-one
change; owners0/2 spend recovered round-one received notes. This leaves nine
claims for independent exits, with the unchanged21-KAS useful denominator.
The corresponding invoice indexes1/2 and3/4 are an encrypted, owner-local
benchmark schedule. No public output role or creator partition is exported.
No fee saving or calibrated native fee is inferred from this source.

Each owner verifies complete Output proofs, decrypts from its Original alone,
rederives the descriptor/CM/NF and positioned path, then rerandomizes its input
CV. It needs no sender's historical CV blinding. Payment creates two actual
Output proofs, a real restricted-intent signature, the stock normalized
signature witness and the actual2,635,409-value owner input through the admitted
Rust CLI. All tuples, signatures and input values stay in that owner's excluded
directory for direct intake by the locked MPC job. Public receipts contain only
fixed types/counts and do not contain tuple hashes, individual Delta, NF, fee,
intent hash or owner-to-output mapping.

Invoices travel through one read-only recipient-worker-created leaf mounted at
`/invoice/INVOICE208.bin`. That explicit trusted namespace routing is the
authenticated confidential channel in this local experiment. Sealed-box
encryption alone does not authenticate a counterparty. This assumption must
remain in the frozen observer/deployment model.

Direct Exit reconstructs the actual current native projection, approves its
exact destination/fee, and creates and independently verifies a genuine
AuthExit proof using the existing genuine parameters. It mounts no MPC shares,
service history or other owner. The candidate remains private until a later
explicitly selected release. Each Exit needs a fresh current accepted head;
nine candidates from one stale head would not be nine usable withdrawals.
Scan and Exit verify Output history with the admitted binary/VK manifest alone;
neither needs the Output proving key or the owner-auxiliary generator. Payment
alone mounts those construction dependencies. Invoice needs only the selected
key-derivation/crypto/authority implementation.

## Complete public history

`wallet_history.py` replays
`kpb-private-batch-public-history/v1`: exact chain/pool/profile/domain/service,
three original Output520 rows, ordered payment/Exit projections, retained Exit
proofs and final state/reserve/outpoint. It reconstructs the complete CM/NF
trees and checks every path, current head, actual native projection and integer
reserve/fee equation. Each owner independently derives `CV(20KAS,0)` from its
restored original receipt and compares it with all three genuine initial
Output CVs. These checks bind initial liabilities; they do not establish that
the reserve was funded or a CASE accepted.

The supplied-context replay deliberately does **not** verify aggregate/R0/Exit
history proofs or current chain acceptance. It cannot be used as a substitute
for the concrete accepted-chain adapter. Preserving complete ordered raw
transitions allows that adapter to bind the actual whole CASE rather than
upgrading a rows-only or Boolean history report.

## Invocation and checks

An operation needs a fresh label, the exact bootstrap trial receipt/hash and
three explicit integer fees. Payment/scan/Exit additionally need an exact public
history/hash and immutable native tail/hash; payment needs the exact private
invoice operation's public result/hash. `--help` lists the finite interface.
The parent experiment must freeze observer inputs, owner truth, predictions,
thresholds and stop rules before running actual private payment preparation.
Payment now also requires the exact public privacy binding file/hash. Its
method digest must match the frozen method and its trial UUID must match the
actual Originals. The owner writes salted private truth and only a public
commitment sidecar; the controller never opens or hashes truth or salt.
Actual invoice-route filenames, roles and execution timings are retained for
the declared dispatcher view, including failed attempts. Terminal scan status
binds the exact selected public-history hash. See [the privacy API](privacy_API.md).

Eleven focused public controls pass: complete state replay; refusal of accepted
flags/scope upgrades; wrong identities/noncanonical encodings; initial reserve
and CV changes; missing/reordered/replayed history; changed current state,
native policy, NF/CM witnesses and fee; mandatory Output-verifier refusal;
original-index R2 selection; metadata-only private-leaf admission and alias
refusal; strict public receipt fields; and operation-specific dependency
admission. These are structural and boundary
tests with explicit model proof bytes, not cryptographic or native evidence.

## Adversarial second pass

- Inflation and reserve release: owner preparation enforces exact integer
  input=payment+change+fee; complete relation and native checks remain mandatory.
  The supplied replay cannot establish accepted backing.
- Double spends, stale state and replay: consumed NFs are reconstructed in order,
  every current context/path is exact, and an already-spent selected claim
  refuses. A reorg requires a newly verified head and fresh authorization.
- Privacy: no creator-to-tuple preparation receipt or individual-Delta export
  exists. Private files remain in one-owner namespaces. The authenticated local
  invoice-routing and honest runtime/source assumptions are explicit; this is
  not an independently administered deployment or an anonymity result.
- Dependency loss: absent proof tools, history, parameters or source pins refuse
  before authorization/proof output. No admin or unverified-history fallback
  exists. Independent Exit still needs its public recovery data/software.
- Remaining qualification: actual private worker runs, frozen-view measurement,
  all-nine sequential Exit/native payouts, accepted-chain wallet integration,
  external recovery data and independent second-pass execution review.
