# Proposed whole compact-policy emitter

Status: for ADR0056/RFC review, before implementation. New profile/package only;
do not fork or modify the active private-change trial, its native/helper,
circuits, parameters, funded state or frozen evidence. The successful component
batch is not a financial-policy implementation.

The next falsifiable result is an actual complete emitted program, exact wires
and ordinary native2.1 public-check execution reaching a typed Groth16 rejection
last. No circuit, setup, PK, private seed, signing, funding or RPC is needed.

## Fixed authorization, shared public checks

Retain State112, one current pool input and the existing Auth528 offsets for D,
outpoint, old State112, R, f, NF0/NF1, ciphertext hash, new State112, R', P and
SPK36. Use a new magic/domain/profile. Existing proof/private signatures cannot
authorize the new relation.

| Auth offset | Width | New meaning |
| --- | --- | --- |
|268|32|CM-array SHA256 digest; canonical zero in the inactive terminal case|
|300|1|slot mode:0 terminal,2 compact private action,32 wide payer action|
|301|3|canonical zero|
|304|4|aligned CM start, unsigned LE32; zero in terminal mode|
|308|24|canonical zero|
|332|32|SHA256 of exactly the mode's ciphertext bytes; terminal uses SHA256(528zeros)|

All other Auth offsets remain unchanged. In particular new State112 starts364,
R' starts476, P starts484 and full SPK36 starts492. SHA256(Auth528) still splits
into the same two LE128 public field elements. Both role VKs therefore have
two public inputs and compressed size328; native tariff stays147,500 mass.

The common private frame is:

`Auth528 | NF witness2320 | CM list32N | ciphertext264N | CM boundary path32(16−log2N)`.

NF witness offsets are fixed528 and1688 in every private mode. This permits one
shared pair of authenticated native NF insertions. Compact continuing payload
is3,920 bytes; wide32 payload12,672 bytes. Terminal payload is2,848 bytes:
`Auth528 | NF witness2320` only. An absent inactive section means canonical
zeros, never missing or unverifiable active data.

The wire is deliberately different from the current profile; no current parser,
descriptor, native helper, proof or setup is silently promoted to compatibility.

## Native obligations retained

Preserve current version/subnetwork/gas/locktime/sequence, exact input count,
actual current P2SH/state/outpoint/reserve, amount ranges, fee/conservation,
capacity, output counts/SPKs, authorizing-input/covenant metadata, ciphertext
binding and exact immutable successor checks. Preserve the entire proofless
ADMIT and explicit owner REVEAL implementations, with self-size/offset bindings
updated for the new complete program. Their bytes remain charged to every
private spend. REVEAL is never an automatic private fallback.

All native NF predecessor authentication, sentinel rules, nonzero/distinct NFs,
absence interval checks, sequential inserts, count and capacity checks remain.
Only their fixed witness offsets change. No native NF check moves into an
unimplemented circuit or disappears.

Mode2 and32 authenticate one empty aligned CM subtree and derive the replacement
root from every ordered CM in the list. Native checks compute the CM-array
digest and ciphertext digest and compare them to Auth. Metadata must satisfy
`start=ceil(old_n/N)*N`, `new_n=start+N<=65535`. All arithmetic is bounded before
use; old_n<=65535 means the rounding intermediates fit ordinary signed native
integers. The old-state equivalence check binds old_n to actual current state.
Mode32 requires P=0. Existing P0-at-least-one-positive-output and all real/dummy
note/value/ownership obligations must remain explicit future proof constraints.

Skipped positions are canonical empty by authenticated prior-state induction.
The native subtree module rejects an occupied target block, not an arbitrary
occupied skipped gap in a fabricated prior state. Genesis and every transition
must establish/preserve the empty suffix; replay derives sparse positions from
authenticated range metadata, without an operator map.

For the selected terminal-only omission, require R'=0 and P>0, canonical-zero
CM-array digest/metadata, the constant ciphertext hash, exact CM-root/n carry,
both NF inserts and m'=m+2. The fresh circuit must enforce every output Note168
field zero, including rho, and no positive hidden output. Removing unused
payload sections does not remove those constraints.

Zero-output full cashout with R'>0 is an **open capacity/recovery decision**. It
needs new native/circuit mode gating, count/liability review and an explicit
full-versus-change observability decision. It is not assumed here to save fees.
The bounded one32-recipient lifecycle stays below CM count126 even with31
continuing two-slot cashouts; this does not qualify a sustained pool at capacity.

## Dual VK dispatch and future constraints

Emit one shared Groth16 call and deterministic VK selection: mode32 selects the
wide payer VK; modes2/0 select the compact exit/private-action VK. Exact mode,
frame, domain, old/current roots and payout binding precede it. Keep the two
full canonical VK literals in the common program; no owner witness pooling,
public-input omission or unpriced routing transaction is allowed.

Future compact and wide circuits must independently bind the exact Auth mode,
CM-array digest, ordered output commitments, output-note constraints and value
conservation. They preserve current input s/k ownership, original nullifiers,
current root membership, real/dummy gates and independent payout-key inequality.
Wide output totals require explicit u128/checked host sums and a proof-bound
aggregate <=R<=MAX; never allow u64 overflow or rely on field wraparound.
Distinctness and inactive-slot rules need explicit constraint coverage, not a
claim that native hashing proves private note correctness. Ciphertext-delivery
validity remains a visible assumption unless separately proven.

Wide proving uses only that payer's own input witnesses and recipient public
invoices. Each exit uses only its owner's backup and public current history,
public compact parameters and local prover. New descriptor/parameter-manifest
versions must bind both key roles to the program/domain and select compact
parameters before any receiver seed read. No wide PK is required merely to
verify public history or construct a compact exit.

## Smallest implementation after the ADR

1. Create a new source-only emitter package, for example
   `poc/compact-private-policy`, with the exact baseline-source SHA recorded.
   Emit the full ADMIT/REVEAL/private union and solve its canonical self-length.
   Keep all copies/branches in the actual byte and unit accounting.
2. Prepare public synthetic State112/tree/NF updates and exact bodies for
   mode2 P0, mode32 P0, continuing mode2 payout and terminal mode0 payout.
   No real note, seed, key or private witness is an input. Domain/fixtures and
   outputs are conspicuously DO_NOT_FUND; no broadcast interface is provided.
3. Use two distinct valid public reference VK328s, one from the closed CAF
   public parameters (SHA256
   `a82c94918d93008160ea9af4b709b05ce41ed5fe6e4b85d66d0fb310b02d94f5`)
   and one from the closed old recovery descriptor (SHA256
   `5e7177177485bb58d9f4f475092fa8212fe83b29bed10806b6f550b37c84cfe2`).
   These are inactive placeholders, not parameters
   for the new relation. Validate their exact public identities and arity;
   never open a PK. Supply zeroProof128 and inactive zeroSignature65.
4. Run the complete public bodies through pinned SDK ID reconstruction and
   the existing generic native2.1 validator. Public positives must pass
   isolation and every native public check, consume the valid-key verifier
   tariff and fail **last** at the typed Groth16 precompile. They are not
   accepting transactions. Changed mode/frame/list hash/cipher hash/start/
   count/occupied CM block/stale NF/wrong current root/payout/successor controls
   must reject before Groth16. Resource/mass/ID failures do not count as the
   intended rejection.
5. Report actual complete redeem/payload lengths, native units, declared-budget
   compute, transient/normalized mining and actual integer contextual storage
   for every shape. Feed the actual emitted branch to the supported-opcode
   source meter; unknown opcodes or unbounded copies fail analysis. Reconcile
   one real32-recipient demand batch including entry/change, all independent
   exits and terminal fee overpayment. Do not create artificial recipients.

Source/meter/emitter conformance and independent review precede one bounded
network-off4CPU/4GiB batch. Ordinary pinned0500 executables/read-only mounts and
clean child environments follow ADR0054. Host user-service-manager connection
variables must remain available to the launcher; they are not inherited by the
namespace. Preserve the component's failed launch and sole successful batch.

## Stop rules and next work

The current source envelope's23,766-byte common-program and15,041,203-unit
figures remain conditional on the future emitter fitting every retained check,
both explicit64-byte glue allowances, fixed stack/SPK widths and no additional
whole-buffer copy. The source screen is not an emitted all-policy bound.
Main budget1600 remains unchanged; no1550/1500 saving is selected from this
screen or the measured component path.

If the actual whole program or conservative all-valid-path bound breaks the
fee envelope, report that failure and stop before cryptographic work. If it
fits, the next decision is a new compact/wide circuit profile, constraint
coverage tests, matched parameters and genuine-proof/native rehearsal. Neither
that setup nor a funded trial is part of this emitter milestone.

Even a fitting32-payment source envelope does not qualify single-payment or
separate-time demand, privacy, cold hardware/latency, parameter availability,
capacity recovery, independent consensus, production safety or the unchanged
global2% requirement. The original failed privacy/economic results remain facts.
