# ADR-0066 independent adversarial review

Date: 2026-10-25 UTC. Status: STATIC REVIEW COMPLETE; execution qualification
pending. No production, privacy-pass or testnet-readiness verdict.

Scope: the new local one-input/two-output domain only. Public source was read
through the root's guarded public-read helper. No protected owner backups,
plans, logs, event streams, truth files or their hashes were read. No active
deanonymization reproduction, funds, broadcasts or old financial-file changes
were performed by this reviewer.

## Contract assessment

ADR-0066 and the selected `poc/local-private-payment/SPEC.json` state a coherent
candidate contract: fresh D and all three component parameter sets; one Spend
and two positive Outputs; exact native reserve fee conservation; independent
full-note Exit152; accepted-head binding; recipient/change authorization; and
original-seed public-history recovery. This does not select stronger privacy or
lower fees in advance. No additional review ceremony is required by this review.

RFC-0029's proposal/no-selection wording predates the accepted ADR. Its status
and decision references should be synchronized with ADR-0066. This is a
documentation consistency item, not an implementation blocker.

## Source observations so far

- Relation: fresh D and Spend/Output/Exit tags are circuit-constrained. Note,
  original-NF, key, Merkle and CV algorithms are retained. Values and blindings
  are bounded, public statements are hashed in-circuit, and G16 proof/key
  decoders require canonical encodings, subgroup validity and nonidentity.
- Public transition: Python and Rust independently check exact arity, reserved
  zero bytes, domain, outpoint, positive fee, reserve arithmetic, distinct
  nonzero/nonempty CMs, encrypted-field hashes, append paths and indexed-NF
  insertion. Public structural helpers explicitly decline proof/currentness
  claims. Accepted occupied-prefix provenance remains an external obligation.
- Native policy: the mixed branch checks actual one-input transaction context,
  current state/outpoint/reserve, exact fee, zero payout and same immutable
  successor policy. It reconstructs the projection-bound outer journal. The
  separate full-note exit branch directly invokes the selected Exit G16 VK and
  binds actual payout amount/destination, fee and NF insertion. Terminal zero
  reserve removes the continuing output. Source inspection is not VM acceptance.
- Tor ingress: the adapter selects SOCKS5h, remote DNS, a fresh random isolation
  password, strict default TLS validation, no redirects and no direct retry.
  It accepts public whole-history calls rather than owner/index filters. Its
  keyword filter explicitly does not prove arbitrary strings contain no secrets;
  the wallet must enforce that public boundary. Daemon SOCKS-auth isolation and
  actual wallet use remain integration obligations.
- SDK bridge: the added single-session loopback bridge forwards official SDK
  text/Borsh frames unchanged through the same explicit SOCKS5h/TLS boundary.
  It stops listening after the first local connection and never retries an
  upstream connection. The caller must select that exact loopback SDK URL,
  prevent SDK resolver/direct fallback, verify the actual testnet network and
  permit public RPCs only. Path selection is not Borsh method/network validation;
  a transport completion is not transaction acceptance.

- Wallet/recovery: `prepare` constructs recipient ciphertext locally and never
  imports an externally serialized draft. Immediately before Spend proving,
  consent reconstructs exact invoice/payment value, own change descriptor and
  decryption, each complete output once, owned input, accepted head, paths,
  integer value sum, CV openings and Delta. Receipt indices and output roles stay
  private; received/change recovery scans every accepted output and obtains the
  index from its encrypted receipt. Claims are keyed by position; a historical
  repeated CM at another position has a distinct position-bound NF. Wrong seeds
  cannot report an empty successful scan, even after terminal exits. Direct exit
  derives payout authority reproducibly from seed plus public history, with no
  outer prover or private attempt journal.
- Worker boundary: typed private payment/exit requests do not deserialize
  `Draft`/`CreatedOutput`; all three manifests are checked before seed use, and
  required whole proving keys are checked before witness input. Public exports
  contain completed public projection/proofs and bounded status, not invoice,
  receipt, note position, output role, owner label or private payment amount.
  Transparent initial admission amount and funding SPK are explicit exceptions.
  The documented finite mount/source closure must be enforced by the controller.

No confirmed source-level financial authorization/inflation defect has been
identified in these reviewed portions. Corrected-fee mixed payment and direct
Exit have now passed actual supplied-context native execution. Actual testnet
payouts remain required acceptance evidence.

## Component evidence reviewed

The public relation `SOURCE-01.json` reports 42 distinct passing test functions,
genuine new Spend/Output/Exit proofs and rejection under old same-role VKs. The
strengthened `CLI-BEFORE-STDIN-02.json` reports six old/malformed-manifest refusals
with complete valid public statements and empty open stdin, so statement parse
failure cannot mask the parameter-before-witness check. The added codec tests
independently vary each proof/VK identity component and exact length.

This reviewer separately read all three selected public VK328 files and pinned
parameter manifests through the guard. Their VK hashes match the selected
component profile role-for-role and all manifests bind the new D. These are
genuine component implementation checks and selection agreement; they do not
establish composed outer/native execution or accepted backing. Setup remains a
local OS-RNG trusted setup without an independent ceremony.

The known-public-seed wallet fixture reports three payments, received/change
spending after seed restoration, five direct exits and terminal reserve zero,
with 16 negative controls. Its report explicitly marks outer proof, Native Full
and testnet confirmation false. Its fixed 100,000-sompi fee was subsequently
found below the selected native budget's minimum fee. Retain it as component/
supplied-context lifecycle evidence only. Native qualification requires a fresh
fixture whose exact actual normalized mass/fee is established before its Spend
effects digest; changing the fee after signing would invalidate authorization.

This reviewer independently ran the selected genuine host verifier against that
immutable public projection. `HOST-NEGATIVES-01.json` records 23/23 expected
outcomes: baseline accepted and 22 changed-effect, cross-role-proof, malformed
proof/CV/scalar, subgroup, path, state, domain, fee, reserved-byte and length
cases refused. CF mutation recomputed CFH, and matching body/prefix outpoint and
nonzero action/policy mutations reached proof binding. No private input or GPU
proving was used. This is component/host evidence only.

The fee correction's selected worker path now requires a pinned fee policy and
the owner's exact approved current quote before creating output notes. It
reconstructs/requotes the actual projection again before Spend/Exit proving.
Fixture02 reports three payments, five exits, terminal zero and 137,864,900 sompi
in fees, with all quotes exactly 100 times actual native mass. Its outer,
Native-Full and testnet flags remain false. This new component fixture addresses
the old quotation composition gap without modifying fixture01.

`NATIVE-EXIT-NEGATIVES-01.json` separately records 15/15 independent native
outcomes in a public-only closed namespace using the pinned actual engine.
The valid corrected-fee direct Exit passed Full and all input scripts; fourteen
normalized proof/witness, domain/state/policy/VK, input/output, payout/fee/
destination/outpoint and insufficient-budget mutations failed both. Native
admission-policy flags are recorded separately. This is actual supplied-context
native execution, not accepted chain state, payment outer execution or payout
confirmation.

The later `NATIVE-MIXED-NEGATIVES-01.json` records 13/13 independent native
outcomes against the genuine final outer/native-proof CASE. Baseline passed
Full and all input scripts. Twelve normalized corrupt/zero outer-proof,
component-proof, effects, matching outpoint/fee/reserve, image/tail, extra
input/output and insufficient-budget cases failed both Full and scripts.
Mass/fee quotations and native admission-policy flags are retained separately.
This closes the supplied-context mixed native binding check; it establishes no
accepted chain or confirmed payout result.

## Bootstrap and native wrapper review

New GN3 admissions bind three genuine Output proofs to public CV(20 KAS,0),
exactly 60 KAS reserve, a fresh trial/domain/profile and the selected immutable
native tail. Each signer privately reopens its own receipt and derives its own
funding key, checks the complete case, all three outputs, normalized native mass,
exact fee allocation and SDK roundtrip before SIGHASH_ALL. The combine path
requires all three signatures and actual Native Full/all-input acceptance.
These transparent admission roles are separate from private payment output roles.

The Native Full wrapper stages only selected public files, checks exact image/
component/Exit VK, case/projection/journal and budget, attaches only the mixed
proof's zero witness slot, and requires real Full plus every input-script result
and fee agreement from the selected engine. Direct Exit does not invoke the
outer prover. The engine must remain independently tied to its pinned source;
the financial-profile string alone is a label rather than proof authority.

The latest recovery genesis schema includes public `deposit_sompi`, checks each
initial CV against CV(deposit,0), and requires reserve=deposit*output_count.
This matches the new chain replay. A mismatch reported from the earlier source
snapshot was withdrawn after refreshing both sides; no defect remains there.

An approved independent child reviewed the new chain acquisition, verification,
preflight, submission and confirmation paths. See `CHAIN-HISTORY-REVIEW-01.md`
and its retained source snapshots. No financial blocker was found. The author
fixed an ID-only confirmation evidence gap: confirmation now requires the pinned
expected complete CASE and compares actual accepted witness/budget/contexts
before native replay. The SDK checks the explicit bridge URL before/after
connection and rejects a configured resolver. These are static source controls;
the child performed no broadcast or private reads.

## Static privacy model

The ledger observer sees a stable NF and the pair of complete output tuples,
reserve movement, fee, timing and transparent exits. The two outputs are visibly
grouped; permutation removes a protocol payment/change label but does not prove
either output is hidden from a counterparty that knows its own receipt. The old
six-output benchmark and failed 2% fee result remain unchanged.

An endpoint sees each submitted public NF and transaction, its timing, and the
Tor exit connection. An authenticated or otherwise identifiable request links
that submitter to its NF. Tor is a transport assumption, not proof against a
global traffic observer. Invoice disclosure can link a stable delivery key to a
party. A compromised owner host or witness-holding prover knows note openings.

Removing compulsory live-owner cohorts removes that coordination dependency;
it does not hide shared-head contention or guarantee retry unlinkability. A
stale authorization must fail. A later attempt must rebuild against accepted
history without permanent private-note locks or delayed independent exits.

## Remaining evidence to review

1. Public-fixture execution of invoice/change substitution refusal before Spend,
   original-seed received/change spending, wrong seed/backup and supplied stale/
   reorg histories. The source implementation alone is not this evidence.
2. Fresh selected Spend/Output/Exit parameters; genuine G16, outer receipt/native
   proof and Native Full checks including bad proof, policy, witness and budget
   controls; actual terminal payout/zero reserve remains a separate testnet gate.

`history.load` accepts an externally authenticated genesis digest and exact
current native checkpoint. It validates complete component proofs, policy,
transitions and balance, but does not itself select or authenticate a Kaspa
canonical chain. Supplied histories/checkpoints remain supplied-context evidence;
the runtime must independently establish actual native accepted history.

All statements above are bounded static observations. Passing implementation
tests cannot establish cryptographic correctness, production safety, external
retention or actual off-host recovery.
