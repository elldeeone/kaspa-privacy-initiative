# Native terminal permission claim: probe plan

Status: source-first plan under ADR0039/RFC0019; no runtime evidence yet. Base
`8d7d719f18ae5975e651a4a114f8cecceb3e8b7c`. Only public synthetic supplied UTXOs,
no GPU/proofs, funding, broadcast or old S7 owner/replay/DRAIN workflow.

## Decisive source facts and selected scope

Reuse vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e` directly. Its public
`vprogs-zk-backend-risc0-api` crate with `default-features=false` exports the
permission/delegate emitter and tree hashes without enabling host/guest/CUDA
or the proving SDK. Its ABI still depends on native hashes/SMT/seq-commit; do
not describe the graph as dependency-free or build the upstream proving suite.

The normal accumulator clamps one leaf to depth1. Use exactly one60,000,000
sompi entitlement, full deduction, count1→0, and no remaining entitlement or
continuation output. Do not substitute an invented depth0 profile. The second
Merkle walk's result is discarded in this final branch. The missing binding
between separate old/new path witnesses remains a correctness blocker for
continuing roots; this probe neither repairs nor exercises that unsafe path.

Official payout/change semantics forbid fees from claim principal:

- Payout≥deduct; final payout≥deduct+permission-input rent.
- Delegate change equals recognized delegate inputs minus deduct.
- A continuing permission's rent would pass through exactly.

Therefore all permission/delegate input value is required in protocol outputs.
A positive miner fee needs another nondelegate input. This is a retained negative
answer for a fully self-funded60M claim, not a reason to weaken payout checks.
The source-positive has a separately signed external fee input; never count it,
or the50M permission rent refund, as claim-funded fee capacity.

## Exact reuse and native boundary

Pinned upstream source:

- `zk/backend/risc0/api/src/permission_script.rs`: public emitters94–108,
  final payout/rent408–450, delegate accounting515–604, builder678–712.
- `api/src/permission_tree.rs:48–92` and
  `core/merkle-tree/src/streaming_builder.rs:60–70`: ordinary tree/hash/depth.
- `api/src/permission_tags.rs`: Leaf0,Branch1,Empty2 domains.
- `zk/abi/src/delegate_script.rs`: exact53-byte delegate script.
- `test-suite/tests/permission_spend.rs:155–179`: private witness helper to
  adapt visibly; no emitter rewrite. Its existing tests execute input0 only,
  use zero fee, and do not establish Full/value/policy/signature validation.

Upstream lock selects rusty-kaspa `9fdbaf1b1886fb5742783d2da73c36239bd6f272`;
our reusable Full checker selects `01b532e8b553523216471682649693af92f0fd16`.
Record both and use only byte bridges: official Vec<u8> scripts and32-byte
hash/public-key arrays become the selected native engine's types. Do not pass
Rust types across revisions or silently patch upstream. Verify opcode values,
SPK encoding and covenant delegate behavior against both source pins. Any
incompatibility is a blocker or separately reviewed adapter, not a weaker test.

Reuse the direct native isolation→`TxValidationFlags::Full` construction and
mass functions from `poc/public-state-consensus-check/src/main.rs`, plus the
native `sign_input(...,SIG_HASH_ALL)` API. Create an isolated
`poc/native-terminal-claim-cost` binary; import no shared-pool/S7/prover code.
Actual emitted permission/delegate bytes must be the official API results.
Check one-leaf accumulator P2SH hash equals the generated redeem hash. An
independent stdlib SHA256 oracle can recount the public leaf/root/domains.

## Public transaction and honest accounting

Use publicly declared test-only deterministic keys for a spendable recipient
P2PK and fee-payer P2PK. They control no live wallet. Source inputs are:

| Input/value | Accounting role |
|---|---|
|Permission UTXO50M, generated P2SH, declared covenant ID|Separate protocol rent; not60M claim principal|
|Delegate UTXO60M, official delegate-entry P2SH|Backing for the60M accepted liability|
|Optional P2PK exact fee F|External capital, signed with actual SIGHASH_ALL|

The terminal payout is110M to the committed recipient SPK:60M entitlement plus
50M returned rent. There is no continuation or delegate change when all backing
is deducted. All outputs and all three input programs must pass Full validation.
This assumes a legitimately accepted/balanced permission context and available
witness; it does not authenticate its ancestry or exit an unconsumed private note.

For rates100/200/500 sompi per normalized mining-mass gram, calculate actual
noncontextual and contextual masses using the native calculator, set the exact
storage commitment, finalize/sign the complete transaction and recheck masses.
Derive F from the complete final body; account for a possible amount/storage
fixed point explicitly. Retain positive actual fees as input sum minus output
sum. Separate compute, transient, normalized noncontextual, storage and mining
mass, native limits, encoded bytes, sigops/budgets/units, and rate scenarios.
Consensus Full, source-adapted standardness, relay-floor quotes and hypothetical
mining-fee scenarios must have separate labels; there is no mempool or inclusion.

The target remains60M principal→at least10M principal payout with all fee paid
from that same60M. An external-F source-positive cannot satisfy it. Retain the
no-external-input attempt with full60M deduction but payout60M−F plus50M rent:
for each rate it must fail the original payout condition. Also retain the honest
zero-fee source case and explain that native consensus acceptance, if any, is not
positive-fee relay/economic readiness. Do not redefine a10M partial claim as a
completed60M exit; its residual50M liability would still exist.

## Controls selected before execution

Every semantic mutation retains sufficient value balance and, where relevant,
re-signs the external fee input so a covenant rejection is not merely a bad fee
signature. Retain exact stage/error/units; resource errors are not rejections.

1. Positive: exact final claim with genuine fee signature at each quoted rate;
   no permission-holder signature is required by this public anyone-can-trigger
   branch, whose authorization is payout-to-committed-SPK, not possession proof.
2. Payout destination substitution; payout one sompi below final entitlement+rent;
   no-external-input claim-funded-fee attempt; rent diversion to another output.
3. Wrong current root or sibling; malformed leaf amount/count; wrong domain;
   wrong delegate covenant/funding SPK; unintended covenant continuation.
4. Fee signature invalid/wrong key, and post-sign output mutation. Re-sign only
   the other semantic controls; these signature controls intentionally remain bad.
5. Duplicate permission input must fail native isolation. A consumed-outpoint
   supplied-view lookup must be labeled a context/missing-entry test, because the
   standalone public Full API accepts populated entries and has no global spent
   set. Never re-inject an old entry and call acceptance/rejection a replay proof.
   If used, source-adapt only the native UtxoView lookup; no general ledger replayer.

No hostile continuing-root fixture. Retirement1→0/no successor is the exact
current-root transition tested; arbitrary continuing-root safety is unqualified.

## Freeze, resources, evidence and stop rules

First freeze this plan, exact source/dependency/config identities and positive/
negative case schema before runtime. Source-build reuse is authorized under
ADR0039 after that freeze: private target/cache outside Git, up to6CPU/10GiB RAM,
zero swap, no GPU or downloaded toolchain. Use available caches; a missing
locked dependency is an operational issue to report, not bypass via stubs.

An independent second pass must review funding/signatures/payout/current-root/
cross-domain accounting before execution, and independently recount results
before publication. Preserve every input/body/script, source adaptation, exact
mass/fee result and reason-specific failure. Generated binaries/caches stay local
with hashes. Public artifacts remain synthetic and source-pinned. Passing this
terminal probe cannot close earlier private authorization, continuation safety,
DA/service-loss/reorg guarantees, full user lifecycle fees or financial privacy.
