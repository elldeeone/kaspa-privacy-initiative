# Private global blinding sum: concrete reuse decision

2026-10-24 UTC. Source research against continuation baseline
`b7b41ab066807d7859499b3491a663ab110fedf9`; no protocol implementation,
dependency build, financial proof, wallet backup access or network payment ran.
This is a decision input for RFC-0026, not an ADR selecting a KAS relation.
The closed ADR0061 packet and full-tuple design/review remain unchanged.

**Recommendation:** use an existing malicious arithmetic MPC engine as the
next exact-field API experiment, and retain ValueShuffle as the construction
reference. MP-SPDZ MASCOT is the concrete candidate identified by the
[independent source investigation](INDEPENDENT-SOURCES.md). It exposes a way to
test the actual Jubjub-field sum without first writing a new masking or blame
implementation. It is a research dependency, not a proposed permanent server
or an endorsement of the complete financial composition.

An additional archived implementation does expose scalar SumDC functions:
Stegos. That narrows the earlier search result: **CSPP and dcrd lack the needed
API; the entire existing ecosystem does not.** Stegos is a useful source
comparison, but is not a drop-in Jubjub implementation or a qualified retry
state machine. Its curve, domains and integration differ materially.

## What the sum must compute

For owner i, let `beta_i = sum(rcv_inputs_i) - sum(rcv_outputs_i)` in Jubjub's
scalar field. Reveal only `Delta = sum(beta_i)` for one exact roster, complete
output tuple set and financial context. Never publish each `beta_i`, its
verification point `beta_i*R`, or an unlabeled list of either: the already
executed subset certificate can try all such values against all input/output
candidates. A generic threshold signature with public original-owner share
verification keys does not remove this leakage.

The exact prime is:

```text
q = 6554484396890773809930967563523245729705921265872317281365359162392183254199
  = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
```

This is the scalar modulus in pinned
[Jubjub source](https://github.com/zkcrypto/jubjub/blob/127236bafe690053743a9156d2ff03a93631709c/src/fr.rs#L74-L98).
It is not the BLS12-381 base field, the 127-bit DiceMix slot field, the
Ristretto scalar field, integer XOR, or arithmetic modulo a convenient power
of two. Boundary decoding must be canonical 32-byte little-endian with value
strictly below q; secret sum arithmetic reduces modulo q. A general MPC
runtime's permission to reduce field inputs is not a canonical wire decoder.

## Existing scalar SumDC: Stegos, with explicit limits

Official repository metadata returned `archived=true`; the selected default
branch commit is `c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3`, committed
2020-06-23. This is historical source, not maintained deployment evidence.
Seven exact raw-file identities, lengths, Git blobs and SHA256 hashes are
retained in [PRIMARY-SOURCES-01.json](PRIMARY-SOURCES-01.json).

The actual
[scalar API](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/crypto/src/dicemix/mod.rs#L759-L799)
has `dc_encode_scalar(x, participants, my_id, share_cloaks)` and
`dc_scalar_open(participants, elts, p_excl, k_excl)`. The former adds signed
pairwise pads; the latter sums contributions and can remove excluded-party
pads. The
[key derivation](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/crypto/src/dicemix/mod.rs#L594-L630)
hashes the session ECDH point, ordered participant identities and session hash.
The
[pad function](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/crypto/src/dicemix/mod.rs#L306-L332)
hashes that shared key with a seed and selects a sign by participant order.
Those are actual reusable source seams, not names inferred from a paper.

Three limits prevent direct selection:

1. Its [`scc::Fr`](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/crypto/src/scc/mod.rs#L91-L95)
   wraps `curve25519_dalek::scalar::Scalar`; its group is Ristretto. A scalar
   serialized there and then reduced into Jubjub does not preserve masked
   cancellation or the required binding equation. Replacing the field is an
   adaptation requiring its own review, not an encoding conversion.
2. `scalar_open_seed()` is the constant `sum`. The code explicitly assumes
   only one scalar sum per shared-cloak context. Reusing the same pads for two
   scalars exposes their difference. The
   [reconstruction API](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/crypto/src/dicemix/mod.rs#L719-L725)
   accepts two sum tables and subtracts pads with that same seed from both.
   This is an API-use constraint to resolve, not an executed attack or a claim
   about a deployed Stegos transaction. A KAS adapter must not inherit the
   single-sum assumption silently or reuse masks across retries/contexts.
3. `dc_reconstruct` receives disclosed session keys and a caller-supplied
   `ValidatorFn`. Its
   [example validator](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/crypto/src/dicemix/mod.rs#L1410-L1430)
   returns true after comments describing future financial checks. This does
   not establish complete financial validation, a safe disclosure barrier,
   agreement under an equivocating assembler, or reviewed post-authorization
   retry behavior. The selected
   [transaction-pool module](https://github.com/stegos/stegos/blob/c1d4d6119fe2776e9548069f173eb9fbd1d5b6c3/txpool/src/lib.rs)
   forms and announces groups; that file alone does not prove completion of
   the missing composition.

The source therefore makes the route more concrete, while supporting reuse of
the protocol ideas rather than importing the old stack wholesale. Its default
crypto build also selects FLINT and historical dependencies; no build or
installation was attempted here.

## Why a stock MPC experiment is useful

ValueShuffle already combines anonymous output carriage, a private aggregate
blinding adjustment, commitments coupling those two transcripts, checking and
final authorization. Its construction is the primary reference for the
cross-protocol contract; it does not supply a maintained Jubjub library call.
[ValueShuffle, pp.10–12](https://fc17.ifca.ai/bitcoin/papers/bitcoin17-final6.pdf).

The independent investigation identifies an existing exact-prime arithmetic
engine as a way to test the missing primitive interface without implementing a
new pairwise masking scheme. This settles a narrower engineering question:
can each isolated process contribute one field element and obtain only a
checked aggregate, which the existing real-curve binding verifier accepts?

It does not settle anonymous output carriage. It also does not establish that
an owner's input really is its note-blinding difference: a malicious MPC input
is still an arbitrary field element. The financial consumer must verify the
commitment-derived global relation, every relevant note/range/spend proof,
nullifier/state/reserve binding and every owner's authorization. The MPC
engine's arithmetic checks cannot substitute for those financial checks.

## Required context and abort contract

Before any final authorization, all honest owners must agree on the same
session ID, roster, protocol/software/field identity, input commitments and
nullifiers, complete output tuples and their canonical order, global fee,
state/domain/native payout effects and validity limits. The native adapter
must define an exact financial-effect digest without a proof/signature
self-reference cycle. The tuple mix, sum and final authorization must join to
that context; authenticating only a generic confirmation flag is insufficient.

This is an integration obligation, not a newly selected digest or signature
design. In particular:

- A dropout may abort. Never recover liveness by publishing an honest owner's
  individual beta or output mapping. Keep the existing one-owner exit route.
- A retry uses fresh session material, masks and discarded output tuples. No
  subset-sum query may reuse the same honest contribution under changing
  rosters: two approved aggregate queries can reveal an individual by
  differencing, independently of the MPC protocol's internal security.
- After releasing any financial authorization for a body, its tuple secrets
  must never enter a later blame disclosure. The existing full-tuple review's
  same-run and cross-run concerns remain unresolved until the actual chosen
  state machine is tested. A fresh run name alone cannot erase an old signed
  body or an old input/output map.
- A malicious participant may learn an aggregate and then withhold its final
  signature. Fairness and guaranteed output delivery are not assumed. That
  event must reduce liveness without releasing unauthorized native KAS.

Adaptive scheduling/dropout is distinct from adaptive corruption of honest
processes and recovery of their memory. No inspected source here supplies a
verified adaptive-corruption claim for the proposed composition. Secure
erasure must not be assumed merely because a process exits. At least two
eligible honest participants are needed for nontrivial individual-input
ambiguity once the observer knows the aggregate and colluders' inputs.

## Proposed smallest decisive gate, not executed

A later ADR and exact source review should freeze this gate before a build:

1. Select the exact existing MPC commit, arithmetic backend, prime q, source
   closure and local dependency plan. Keep separate process namespaces and
   owner inputs; no central plaintext beta list, logs, note secrets, current
   financial PK or wallet backups. Use only public synthetic scalars and reuse
   the actual-curve binding-verifier API exercised in ADR0061. The first run
   is functional calibration, not heldout privacy data.
2. Run three owner processes with the stock secret-input/field-add/checked-open
   APIs. Fixed inputs `(q-1, q-2, 6)` must return `3`; `(0, 0, 0)` and
   `(q-1, 1, 0)` must return `0`; `(5, 11, 17)` must return `33`.
   Test canonical wire rejection at q. Independently feed the resulting Delta to the existing
   actual Jubjub commitment-derived RedJubjub Binding verifier. Correct sum
   must verify; changed sum, body digest and fee must reject. Retain the
   earlier explicit mock-Groth16 limitation.
3. Predeclare dropout points before input, after masked input and before final
   checked open, plus malformed transcript, wrong prime/software/context and
   mismatched roster cases. They must abort or reject without an exported
   financial authorization or honest individual contribution. Changing roster
   requires a new session, not a surviving subset opening of the old inputs.
4. Keep the assembler-plus-colluders' actual transcript, timing, identities and
   permitted own inputs in scope. A public synthetic run cannot empirically
   prove transcript privacy; absence of an individual beta argument is not an
   anonymity score. Assert only API/arithmetic/abort behavior actually tested.
5. Stop on unsupported exact prime, unchecked output, unexpected plaintext
   logging, hidden central input collection, unreviewed context glue or a need
   to alter the cryptographic engine. Retain that result. No original amount
   prior, ancestry failure, sample, qualification threshold or hidden-truth
   distribution may be changed to make this gate pass.

This gate can retire the exact-field executable-API uncertainty. Strong native
KAS privacy still requires the full tuple protocol, reviewed financial
relations, authorization/retry composition and the unchanged privacy observer
test. Independent recovery availability is a separate lifecycle requirement.

The independent memo's five-party test is an alternative research proposal.
The smaller **three-party functional gate** above and its
[distribution/API recipe](BUILD-RECIPE.md) are the recommended next root
decision. Neither proposal has been executed or selected by this note.
