# ADR-0018: Private-payment implementation package and testnet preflight

Status: Accepted for owner-authorized research execution, 2026-10-18.
No mainnet or real funds. The owner authorizes the local RTX 3070 and testnet
node `10.0.3.26`; test-KAS funding/broadcast is within the eventual native trial
scope, after its actual cryptographic/native prerequisites are satisfied.

## Decision

Execute RFC-0003 P1–P5 in dependency order. Begin with an exact, reviewable P1
suite/encoding package, established-library interoperability vectors and
read-only node qualification. Do not mistake the complete proxy classifier
receipt for the full private payment relation or fabricate independent review.
An isolated VM compatibility probe may execute/prove established primitive APIs
on runtime-supplied, already-public test-vector data. Its distinct journal and
program identity authorize no credit/spend/exit and cannot pass P2/P3. This
measures whether the selected dependencies/toolchain work before a new wallet
relation is implemented; it is not a substitute for composition review.

The candidate uses Orchard 0.16.0 at
`616a669df8c9a59c33d47064d3ce04b25d026b2e`, V2 note/encryption semantics,
depth-32 Sinsemilla membership, full spending-key knowledge and the repaired
post-NU6.2 relation obligations. Disable Halo2/circuit/default features for the
primitive API/vector qualification; a later wallet zkVM must prove every
RFC-0003 predicate. Reusing primitive definitions is not reusing an audited
Orchard Halo2 circuit. Study exact public APIs and official vectors first.

The initial deliverables may encode proposed public intents, check established
upstream vectors and measure API/toolchain compatibility. They may not accept
user liabilities, release KAS or claim a complete wallet circuit. Pin actual
wallet/verifier artifact IDs when built; an unknown ID is an explicit blocked
deployment field, not a zero value or an accepted verifier. Independent
cryptographic composition review remains a real P1 prerequisite before
substantial implementation of the new wallet relation. Subsequent code/proof
qualification is additional evidence, not a substitute for that review.

## Required controls before implementation

- Compare note/key/nullifier/encryption/empty-tree outputs against independently
  published upstream vectors. Reject malformed scalar/point/address encodings,
  mutated delivery bytes, wrong recipient keys and unsupported versions.
- Specify exact two-slot intent bytes, domains and authorizations; independently
  derive golden bytes/hashes. Reject truncation, trailing bytes, unknown enum/
  flags, absent/present aliases, range errors and unauthorized kind fields.
- Keep integer sompi and checked u128 sums; cover zero, one, u64 maximum,
  overflows, private change, full-tree exits and credit authority with no real
  input. Never replace the note relation with the earlier preimage proxy.
- Retain testnet server/network/sync/UTXO-index and required RPC capability
  evidence. A synchronized node or normal transaction acceptance alone does not
  qualify Toccata ordering/covenants/native proof verification.
- Create a fresh unfunded native trial identity in one command once its concrete
  path exists. Calculate funding from actual transaction/fee/rent shapes; do not
  request an arbitrary wallet top-up before those prerequisites.

## Trust and scope

No new token, privileged withdrawal key, cryptographic primitive or altered
economic invariant. Wallet secrets remain local. Published test vectors contain
only explicitly public upstream/synthetic keys, never a funded wallet key.
Native node observations are RPC evidence from one owner-operated node; they
are not independent consensus proofs, operators or human cryptographic review.
Reorg, pruning or missing proof artifacts must stop acceptance, not bypass it.

Keep RFC-0003 open, distinguish P1 preparation/review from P2 implementation,
and record actual remaining requirements. Fresh source pins/rights and the
review package must be available before any request for an external review.

## Alternatives and reconsideration

Native-library checks alone would not establish compatibility with the proving
VM. Expanding the earlier small wallet proxy would not measure the selected
Orchard primitives. Importing Orchard's Halo2 bundle unchanged would bring
different value/signature/verification assumptions and still require native-KAS
composition review. The selected public primitive probe answers a narrow
compatibility/cost question without implementing an unreviewed payment relation.

Reconsider the candidate after independent composition findings or actual
full-relation resource/native-binding measurements. The established primitive
API pins are not a permanent architecture choice. The
[review handoff](../../poc/private-payment/REVIEW-PACKAGE.md) and
[measured results](../../poc/private-payment/RESULTS.md) record the current scope.

The subsequent P1 preparation adds only existing-library recovery-signature
qualification and candidate witness/journal/native-binding detail in RFC-0004.
It does not implement the new wallet relation or accept a native registration
contract. Keep the original Orchard receipt/locks/archive unchanged; retain
the [recovery-auth supplement](../../poc/private-payment/RECOVERY-AUTH-RESULTS.md)
as separate evidence. No author self-review or second library substitutes for
the unavailable independent composition review.

Subsequent owner instruction selects the separate-agent AI review route in
[ADR-0019](0019-separate-agent-prototype-review.md). That explicit research
decision governs offline implementation readiness after findings closure;
it must not be described as independent human review, a complete native P1
qualification or permission to accept unverifiable backing/payout state.
