# P1 MASCOT view: exact privacy and leakage assumptions

**Status:** source review, 2026-10-29. This is not a cryptographic proof, an
audit, or an empirical privacy result. The capture source remains
`CONFIGURED0`: a production-shaped authority/factory path now exists in source,
but no configured selected driver invokes it, launch is unauthorized, and no
actual receipt is enabled. Schema v9 source controls cover seventeen typed
lanes, including staged P1-local authenticated G1/G2 state and scalar-callsite
bindings; a configured full
registered execution and actual producer receipt are
still absent.

## Answer

Do **not** treat the captured fields as individually independent of the honest
owners' mapping.

There is a narrower defensible statement. Under the original MASCOT theorem's
corruption model, and only after assuming that the exact OT, preprocessing,
input, output, and implementation chain realizes the theorem's hybrids, the
**joint cryptographic value view of a statically corrupted computing party** is
simulatable from:

- the corrupted computing party's input and auxiliary information;
- the public program, field, dimensions, schedule, and declared outputs;
- values intentionally opened to all computing parties; and
- the adversary's ideal-world delivery/abort power.

Therefore, two honest-owner mappings that induce the same items above should
give computationally/statistically indistinguishable *joint stock-MASCOT
views*. This is not literal statistical independence, not a field-by-field
claim, and not a statement about physical timing, byte counts, retries, or
custom protocol extensions.

That theorem statement and the frozen empirical observer have different
scope. Per [ADR-0088](../docs/adr/0088-passive-pinned-p1-empirical-observer-scope.md),
the gate measures the complete admitted view of the exact pinned,
instrumented, protocol-following P1 process plus C1's declared wallet view.
It is not an image of an arbitrary malicious binary or physical host. Active
P1 deviation, internal random tape, physical-host/network-stack state, and
covert channels remain unqualified and block every general or production
privacy claim.

The current application cannot make even that narrow statement without
qualifications. Three boundaries must remain explicit:

1. The active owner path now implements the complete five-value DDNNT input
   supply, replacing the historical three-value MP-SPDZ external-client
   shortcut. DDNNT supplies the right client-delivery theorem, but applying it
   still depends on exact implementation correspondence, fresh one-use MASCOT
   preprocessing, authenticated role-bound channels, and the unresolved OT
   composition below.
2. The raw auxiliary Groth16 `B1` opening is gone. `C` is built with the two
   secret scalar/G1 products in Ozdemir--Boneh Appendix E. Each product maps a
   fresh scalar Beaver triple into the Smart--Talibi Alaoui scalar/group
   protocol and opens only one masked Fr difference and one masked G1
   difference. This is an established protocol design, but the exact custom
   C++ group/MAC implementation and its composition with this MASCOT binary
   have not been independently proved or admitted as a frozen source
   assumption.
3. The pinned base OT is Chou--Orlandi SimplestOT. The revised original paper
   expressly withdraws its proceeding-version UC claim; it describes an OT
   extension as only *informally* providing the needed timely-decryption step.
   I found no original paper or pinned-source proof that closes this exact
   SimplestOT -> SoftSpoken -> MP-SPDZ MASCOT composition.

These boundaries must be represented as conditional assumptions or
`UNQUALIFIED`, never silently removed from a privacy leakage ledger. Physical
timing, sizes, ordering, retries, failure phase, and host/network effects remain
empirical even if every value-protocol assumption is accepted.

A smaller prospective replacement is for each owner to split its field vector
additively among P0/P1/P2 and for each computing party to input its received
share through stock MP-SPDZ `Input<Share<Fr>>`. This removes the exported
triple and owner-side `a*b=c` branch. It is **not yet a proved external-client
input protocol**: MASCOT authenticates the share value a corrupt P1 chooses,
not the value the owner sent to P1. P1 can add a chosen delta and observe the
later validity result. The design is acceptable only after a selected relation
is shown to bind every reconstructed owner value so that every nonzero delta
has an input-independent negligible chance of acceptance. The current full
EdDSA relation is a candidate, not an admitted program. Until that admission,
the selected complete five-value DDNNT path remains the smallest
theorem-backed external-owner construction found in the inspected primary
sources.

## Exact code path inspected

The dependency manifest pins MP-SPDZ commit
[`113c4e47dd94bca9ecab029d2f0abe649bea5c52`][mpspdz-commit] (release 0.4.4),
SimplestOT_C `7ef7666909e493a18c99efe56f97cc4d13723005`, and libOTe
`fe6b2ff82a976a5332b3a2efe325831588b1324a`. Its selected configuration is
MASCOT, malicious SoftSpoken (`USE_KOS=0`, `USE_LIBOTE2=1`), BN254 Fr,
`AVX_OT=0`, assertions enabled, and no `INSECURE` or `NDEBUG`. The only listed
MP-SPDZ patch strengthens the server-side client-certificate requirement; it
does not change arithmetic or OT. See the local
[`DEPENDENCIES.json`](../poc/local-private-payment/mpc-prover/DEPENDENCIES.json).

The local field path is genuinely the stock MP-SPDZ `Share<Fr>` path:

- `Share<T>` stores an additive share and MAC share and selects SPDZ online
  multiplication, MASCOT live preprocessing, and MP-SPDZ MAC checking
  ([pinned `Share.h`][share-h]).
- `MascotContext` initializes `ProtocolSetup<Share<Fr>>`, obtains the local MAC
  key share, creates `ProtocolSet`, and requires exactly three encrypted parties
  with the expected BN254 field and secure runtime flags. The captured P1
  constructor records that one local MAC-key share after setup extraction and
  before protocol-set construction
  ([local source](../poc/local-private-payment/mpc-prover/auth_field.cpp)).
- `random_auth()` calls live preprocessing; `multiply_batch()` calls the stock
  protocol's prepare/exchange/finalize sequence; `open_public_checked()` checks
  pending openings both before and after `POpen`
  ([local source](../poc/local-private-payment/mpc-prover/auth_field.cpp#L132)).
- MP-SPDZ's `ProtocolSet::check()` runs the multiplication protocol check and
  output MAC check ([pinned `ProtocolSet.h`][protocol-set]). The live random
  path ultimately sums one input tuple from every computing party
  ([pinned `Data_Files.h`][data-files-h],
  [`Data_Files.hpp`][data-files-hpp]).
- The pin has amplification and correlation checks enabled, and
  `N_AMPLIFY=3` ([`MascotParams.cpp`][mascot-params],
  [`NPartyTripleGenerator.h`][n-amplify]). The MASCOT paper's Corollary 1 gives
  `k/2` statistical security for its `tau=3` construction under the paper's
  field hypotheses. This review does not turn that symbolic result into a
  complete concrete failure probability for this executable.

The capture code observes substantially more than public outputs:

- `P1CapturingPlayer` is role-bound to encrypted party 1 of 3 and records the
  application `octetStream`/`PlayerBuffer` bytes sent to or received from each
  peer, before/after the delegated transport call
  ([source](../poc/local-private-payment/mpc-prover/p1_capturing_player.cpp#L118)).
  These are corrupt-party application plaintexts, not TLS wire ciphertexts.
- Typed seams serialize the local MAC-key share; local scalar shares and MAC
  shares; random shares and MAC shares; field outputs; DDNNT owner frames; the
  exact two masked Fr and two masked G1 differences; and final `A,C`/`B2`
  openings. Schema v9 additionally serializes P1's local authenticated G1/G2
  share-then-MAC state at canonical `BASE`, `MIXED`, `PRODUCTS`, and `FINAL`
  stages
  ([source](../poc/local-private-payment/mpc-prover/p1_capture_seams.cpp)).
  They do not independently record MP-SPDZ's internal PRNG seeds, base-OT
  coins, or every preprocessing intermediate; those remain represented only
  through the resulting local values and peer application messages that happen
  to cross an instrumented seam.
- Every record adds semantic, direction, peer, fork identifier, monotonic
  timestamp, sequence/message/chunk numbers, payload length and digest. The
  completeness record adds per-lane and total counts/bytes and first/last time
  ([source](../poc/local-private-payment/mpc-prover/p1_capture_stream.cpp#L305)).
- `source_status()` reports schema
  `kpb-p1-streaming-capture-source-only/v9`, `configured=false`, no
  registered-driver or producer integration, no launch authority, and no
  actual receipt
  ([source](../poc/local-private-payment/mpc-prover/p1_capture_stream.cpp#L896)).
  A production-shaped `RegisteredP1Context::begin()` source path can consume a
  one-shot authority and construct `P1CapturingPlayer`, typed seams, and the
  captured context before setup
  ([source](../poc/local-private-payment/mpc-prover/financial/registered_p1_context.cpp)).
  No configured selected driver invokes that factory. Source reachability is
  therefore not evidence of an actual captured registered run. Focused v9
  stream, Player/authority, producer, and model controls exercise the closed
  grammar, staging, callsites, and fail-closed boundaries. Those are
  source-control results, not a frozen build/producer/model receipt or privacy
  evidence.

## What the original theorems cover

### MASCOT

The MASCOT paper proves UC security against a **malicious, static adversary**:
corruptions occur before the protocol begins, and as many as `n-1` computing
parties may be corrupt (Section 2, p. 7). One corrupt P1 among three computing
parties is inside that threshold; adaptive, mobile, or post-execution host
corruption is not.

Its authenticated-share functionality stores values, permits linear
combinations, opens a value to the adversary, and permits adversarial abort
(Figure 4). Theorem 2 realizes that functionality in COPE, commitment, and
randomness hybrids. Theorem 3/Corollary 1 covers triple generation in ROT and
authenticated-share hybrids; Theorem 4 combines triples and input tuples into
preprocessing. Theorem 5 realizes the arithmetic black box against a static,
active `n-1` adversary in the preprocessing hybrid ([MASCOT, Sections
2--6][mascot-paper]).

The online simulator sends random values for honest input masks and Beaver
multiplication openings. The paper says the two worlds are identically
distributed up to output because each triple is used only once; the ideal
functionality gives the output to the adversary first and lets it deliver or
abort (pp. 20--21).

That establishes a **joint-view simulation statement**. It does not establish
that a local share, its MAC, a preprocessing value, and each transcript message
are mutually independent. They are deliberately correlated. Nor does it
automatically prove a C++ implementation, serialization, network stack, or
custom application protocol correct.

### SoftSpoken and base OT

SoftSpoken analyzes its protocols in Simplified UC. Its ideal functionalities
notify the adversary of ideal input/output events and let it delay or block
delivery; protocol messages are assumed to use authenticated channels
(Section 2.3). Theorem 5.1 gives malicious security for the final OT extension
in its stated malicious-VOLE-pre hybrid, with trivial `{X}` selective-abort
leakage, conditional on its TCR hash and almost-uniform-hash assumptions and
concrete advantage term. Its implementation section instantiates additional
PRG/collision-resistance and ideal-cipher-style assumptions
([SoftSpokenOT][softspoken-paper]). This is computational, assumption-dependent
security, not information-theoretic independence.

The pinned MP-SPDZ source selects ref10 SimplestOT and links the Chou--Orlandi
paper directly ([`BaseOT.cpp`][base-ot]). However, Section 1.1 of the revised
Chou--Orlandi paper says its earlier UC claim was incorrect and removed. It
identifies extraction/timing problems and says combination with an OT extension
*informally* works as a timely-decryption proof ([SimplestOT][simplestot-paper]).
The pinned SimplestOT_C README separately calls the code academic and disclaims
correctness/security guarantees ([source][simplestot-readme]).

Consequently, invoking MASCOT UC security for this exact binary requires an
explicit **base-ROT/composition assumption** unless a separate applicable
composition proof is supplied. The SoftSpoken theorem alone does not erase the
gap.

### Groth16

The original Groth16 construction's public proof has exactly three group
elements and is zero knowledge for the witness under its setup and cryptographic
assumptions ([Groth16][groth16]). In this implementation those public elements
are `A`, `B2`, and `C`. There is now no raw `B1` opening.

Ozdemir--Boneh Appendix E writes the collaborative prover's third point as

```text
C = s*A + r*B1_base + L + H,
B1_base = beta1 + sum_i assignment_i * B1_query_i.
```

`B1_base` deliberately excludes `s*delta1`: `s*A` already contributes the
single `r*s*delta1` term. Appendix E.1 therefore requires exactly two secret
scalar/curve products, `s*A` and `r*B1_base`, and opens only the three final
proof points ([Appendix E][ozdemir-boneh]). The local toy and financial paths
use that algebra
([toy source](../poc/local-private-payment/mpc-prover/auth_groth16.cpp),
[financial source](../poc/local-private-payment/mpc-prover/financial/financial_prover.cpp)).

Each scalar/curve product consumes its own fresh stock MASCOT field triple
`(a,b,c=a*b)`. The local code maps it to `(a*G,b,c*G)`, opens only
`D=Q-a*G` and `e=x-b`, and returns

```text
c*G + e*(a*G) + b*D + e*D = x*Q.
```

This is Smart--Talibi Alaoui's `Multiply-G-S` protocol with the paper's `a`
and `b` labels exchanged. The paper maps an SPDZ field triple into a
scalar/group triple, opens one uniformly masked field difference and one
uniformly masked group difference, and proves the online elliptic-curve
functionality secure with abort in the SPDZ-offline hybrid for a prime-order
group ([Figure 9 and Theorem 2][smart-alaoui]).

That source correspondence removes the old concrete raw-`B1` disclosure. It
does **not** make the group lane stock MASCOT or prove this binary. Applying the
paper requires two independent one-use triples, correct BN254 prime-order
group admission, correct group-share/MAC representation, complete scalar and
group MAC checks, authenticated broadcast, and a correct composition with the
exact MASCOT/OT stack. The peer transcript necessarily contains masked values
before their MAC checks finish; the implementation does not return or use a
successful opening until the corresponding checks pass. Exact timing, bytes,
failure phase, and any undecoded group traffic remain unqualified or empirical.

## Per-field leakage ledger

Use the classification labels below. A `CONDITIONAL-*` label is not “zero
leakage”; it means the entire recognized joint value view is handled only by
the named theorem and assumptions.

| Captured item | Exact meaning in this source | Safe frozen classification | Boundary |
|---|---|---|---|
| P1 MAC-key share | P1's one local `alpha_i`, recorded once after field setup and before protocol-set construction | `CONDITIONAL-SIM`, as corrupt-party state | A corrupted P1 legitimately knows `alpha_i`; it is not a public value or an independent random field. Security requires at least one honest party's unknown key share, fresh lifecycle-correct setup, and no cross-failure key reuse. |
| P1 scalar share + MAC share | Local components of `Share<Fr>` from stock field operations, including DDNNT `s,r,w,v,u`, derived owner inputs, and the two scalar/group triples | `CONDITIONAL-SIM`, jointly | Only for recognized stock-MASCOT/DDNNT values, complete checks, fresh/single-use preprocessing, and the full OT/composition assumptions. Never claim the two fields or separate operations are individually independent. |
| Scalar callsite binding | Semantic 17's exact `v1/kind/site/count/zero4` record immediately before each corresponding share/MAC pair; sites `1..22`, randomness `{1,7,20,21}` | `DIRECT-CORRESPONDENCE / NONLITERAL-UNMODELED` | It proves finite source attribution and arity only when the complete bitmap/order checks pass. It does not make the following share/MAC payload harmless; each site still requires its stock/DDNNT/mixed-group/final-proof assumption chain. |
| Model, query-store, and scalar-manifest identities | HELLO's exact three 32-byte preimage/manifest bindings | `DIRECT-CORRESPONDENCE` | These bind which sealed model/query transport and scalar callsite manifest the run claims. Query correctness, MSM temporary reconstruction, witness privacy, and payload implications remain separate constraints or assumptions. |
| `random_auth()` share + MAC | Sum-of-input-tuples live random value used for Groth16 `r,s` | `CONDITIONAL-SIM`, jointly | Requires at least one honest computing party, correct/fresh RNG and input tuples, no state compromise/reuse, and the stock preprocessing proof chain. The custom group use of the scalar remains separate. |
| Peer-transport payload bytes | Mixed lane: MASCOT/OT/setup messages, MAC checks, public agreement, custom group traffic, and implementation framing | Split by decoded call site | Recognized abstract stock-MASCOT message *contents* may be `CONDITIONAL-SIM`. Custom or undecoded payloads are `UNQUALIFIED`. TLS only protects outsiders; P1 is the corrupt endpoint. |
| Beaver `epsilon,rho` openings | Stock multiplication masks embedded in peer traffic | `CONDITIONAL-SIM`, jointly | MASCOT simulator covers them only with a fresh triple used once. Their physical encoding/length/time is not covered. |
| Declared field outputs | Validity bit, effects digest limbs, and released projection bytes at enumerated call sites | `EXPLICIT-LEAKAGE` | The ideal arithmetic functionality permits declared output. The ledger must name the call site and meaning; the generic `FieldOpening` label is insufficient. Unknown/new opening sites default to `UNQUALIFIED`. |
| 10,685-byte public projection and final proof `A,B2,C` | Intended public result | `EXPLICIT-LEAKAGE` | Equality across mapping-swap trials must be frozen or differences are allowed public leakage. Groth16 witness privacy is separately conditional on setup, randomness, assumptions, and correct implementation. |
| Two masked Fr and two masked G1 differences | For `s*A` and `r*B1_base`, exact pairs `e=x-b` and `D=Q-aG` | `CONDITIONAL-SMART-ALAOUI`, jointly; not presently admitted | Figure 9/Theorem 2 covers this shape in the SPDZ-offline hybrid when each product consumes an independent fresh triple and all checks complete. The exact C++ correspondence/composition is still an assumption. Peer messages expose the masked values before checks; typed lanes are emitted only after checks. |
| Final group-opening lanes | Exactly G1 `A,C` and G2 `B2`; no raw `B1` | `EXPLICIT-LEAKAGE` | With capture attached, the checked opener requires the one-shot authority mintable only by the selected durable financial assignment, plus an exact-state private permit. Exact arity/callsite controls remain mandatory; any new or differently positioned opening defaults to `UNQUALIFIED`. |
| Named P1-local group share/MAC state | Direct share-then-MAC encodings: G1 `BASE[A,B1_base,L,H]`, `MIXED[U0,V0,D0,U1,V1,D1]`, `PRODUCTS[sA,rB1_base]`, `FINAL[A,C]`; G2 `BASE/FINAL[B2]` | `DIRECTLY-CAPTURED / NONLITERAL-UNMODELED` | Schema v9 enforces exact stages, counts, order, repeated `A/B2` byte equality, query-store/model manifest identity, and scalar site/kind/count bindings. It does not prove `D=Q-U`, Beaver/product equations, `C=products+L+H`, or query/MSM correspondence. Worker partials, expression/checker temporaries, allocator copies, internal random tape, and physical-host state remain uncaptured/unqualified. |
| DDNNT preprocessing frame | P1's local value shares only, in exact per-field `s,r,w,v,u` order; no MAC lane is sent to the owner | `CONDITIONAL-DDNNT`, jointly | Requires fresh independent tuples per field, both owner equations, exact canonical framing, authenticated role-bound channels, complete server checks before export, and the MASCOT assumptions. Exact size/owner/order/timing remain observed metadata. |
| DDNNT offset frame `d=x-s` | Same canonical `d` received from an owner and byte-agreed by all servers before `[x]=[s]+d` | `CONDITIONAL-DDNNT`, jointly | Uniform-mask reasoning requires fresh hidden `s`; malformed/different/replayed offsets poison the attempt. C1's own values and frames are explicit corrupt auxiliary input. |
| Historical owner frame `x+a` | Removed shortcut: owner reconstructed `(a,b,c)`, checked `ab=c`, and returned `x+a` | `REMOVED / UNQUALIFIED-3VALUE-CLIENT-INPUT` | Retain as a negative control and reject its contract/width. It is not a present-tense leakage lane and must not be accepted as an alias for DDNNT. |
| Proposed owner additive share `x_i` | Owner sends one fresh share to each Pi; each Pi supplies its received vector as that computing party's stock input; authenticated outputs are summed | `NOT-CURRENT / CONDITIONAL-CANDIDATE` | P1's honest-owner share is uniform and stock input covers the transcript for the value P1 actually chooses. It does not authenticate the owner's intended share. A selected full-record binding relation and a separate chosen-delta argument are required; metadata remains empirical. |
| Success/abort bit | Whether the abstract operation completed | `EXPLICIT-LEAKAGE` | MASCOT/SoftSpoken ideal worlds allow abort/delivery control. The exact cause, phase, exception, time, partial transcript, and retry count are not thereby safe. |
| Timestamp, duration, size, message/chunk count, ordering, peer, fork topology, connection/retry schedule | Physical/implementation metadata | `EMPIRICAL-METADATA` | Not covered by the cited value-view theorems. It may be treated as public shape only after proving it is a deterministic function of frozen public inputs; otherwise retain and test it. |
| TLS records, packetization, kernel scheduling, cache/page faults, process logs, CPU/GPU behavior, RNG failure, memory disclosure | Not captured by this stream | `OUT-OF-SCOPE/UNQUALIFIED` | No absence-of-leakage claim is permitted. The wrapper sees application buffers, not the network/host view. |

## The removed three-value owner-input gap was concrete

The superseded path sent every server's **local additive shares** of a MASCOT
triple `(a,b,c)` to the external owner; the owner summed all three, checked
`a*b=c`, and broadcast `x+a` back. This differed from MASCOT Protocol 5, in
which the input owner samples a random `r`, authenticates it through the ideal
authenticated-share functionality, and later broadcasts `x-r`. The current
source instead uses the complete DDNNT path described below and rejects the old
contract and `3*N` shape.

There is a simple selective-failure reason not to promote the adapter on OTP
intuition alone. A corrupt P1 can alter its exported triple components by
`(delta_a,delta_b,delta_c)`. The owner's check becomes

```text
a*delta_b + b*delta_a + delta_a*delta_b = delta_c.
```

For example, setting `delta_a=0`, nonzero `delta_b=t`, and
`delta_c=t*g` makes the owner continue exactly when `a=g`. On that rare pass,
P1 knows the mask and sees `x+a`; on failure it learns the failed guess through
the abort/partial transcript. One fresh BN254-field guess has negligible
success probability, but that observation is not a proof: retry count, fresh
triple enforcement, correlated choices, and all failure surfaces would have
needed a separate active-security analysis. This was sufficient to keep the
adapter and downstream views conditioned on it
`UNQUALIFIED-3VALUE-CLIENT-INPUT`. The selected DDNNT replacement removes this
specific check-and-continue oracle; retaining the counterexample explains why
the old identity must continue to fail closed.

The removed flow was not an accidental invention: it closely followed MP-SPDZ's
upstream `sint.receive_from_client()` and `Client::send_private_inputs()` path.
Those sources send the three local shares of a multiplication triple, have the
client check `a*b=c`, and return `x+a`; the compiler documentation attributes
the path to DDNNT15 ([pinned compiler source][mpspdz-client-input],
[pinned client source][mpspdz-external-client]). Source reuse does not itself
establish the privacy theorem, particularly because the primary DDNNT protocol
is stronger than this shortcut.

## Smaller conditional candidate: owner split plus stock MASCOT input

Let an honest owner sample independent uniform vectors `x0,x1` in Fr and set
`x2=x-x0-x1`. It sends only `xi` to Pi over the already authenticated,
role-bound TLS channel. Any one share, including P1's share, is perfectly
uniform independently of `x`; shares must be independently refreshed for
every owner, field, and attempt. This statement applies only to the canonical
share-vector body. The owner endpoint/identity, role, frame length, arrival
time, ordering, retries, TLS behavior, and host effects remain explicit or
empirical leakage.

The exact pinned stock API is exposed as `MascotContext::protocols().input`.
`Input<T>::add_mine()` consumes an input tuple for the local computing party,
broadcasts `input-r`, and adjusts the authenticated share; `add_other(p)`
consumes the matching tuple; `exchange()` transports the masked values; and
`finalize(p)` returns the authenticated result
([`Input.h`][mpspdz-input-h], [`Input.hpp`][mpspdz-input-hpp]). MP-SPDZ's own
processor uses exactly reset, add, exchange, finalize in that order
([`input_personal`][mpspdz-input-personal]). A local vector helper would use one
identical public schedule on all three processes:

```text
input.reset_all(player)
for p in P0,P1,P2:
    for every fixed-position field k:
        if local_party == p: input.add_mine(received_share[k])
        else:                input.add_other(p)
input.exchange()
for every k:
    authenticated_x[k] = sum(input.finalize(p) for p in P0,P1,P2)
complete the stock checks before validation/output
```

This is a clean reuse seam for the **computing-party inputs**. It removes the
server-to-owner triple export, the three-value client check, and `x+a`.
The concrete old attack `delta_b=t, delta_c=t*g`, whose owner-side triple check
continues exactly when the hidden mask equals `g`, has no corresponding branch
in this flow because the owner never receives or validates a server-chosen
triple. But the replacement does not by itself realize an honest external
owner's ideal input. In MASCOT's ideal semantics P1 is a corrupt input party
and may choose its input. If P1 replaces its TLS-received share `x1` with
`x1+delta`, stock input correctly
authenticates `x1+delta`, and the reconstructed record becomes `x+delta`.
Opening one final validity bit then gives P1 the predicate
`relation(x+delta)`. MASCOT simulation permits that result because the delta is
part of the corrupt computing party's input; it does not prove equality to the
external owner's intended share.

A later relation can close that application-level gap only under a stronger,
explicit condition: every field supplied by the owner must be either covered
by one canonical signed message or deterministically and bindingly derived
from it inside the selected relation. Every nonzero change to message,
signature, private witness, or derived auxiliary column must either be
semantically identical under a proved injective encoding or imply a signature
forgery, hash/commitment break, or other named negligible event. Merely checking
some signed public edges is insufficient: a changed unsigned witness or
auxiliary value can otherwise turn the validity bit into a secret-dependent
selective-failure oracle.

The repository contains a serious candidate for this condition, but not a
selected one. `JoinedSourceCircuit` appends every row of three complete
signature matrices and links 66 native core edges per owner
([source](../poc/local-private-payment/private-batch-relation/src/joined_source.rs#L29)).
The owner-local tool checks every imported signature row before ordering the
native edges, auxiliary values, and signature witness
([source](../poc/local-private-payment/private-batch-relation/src/bin/owner_aux.rs#L321)).
The retained candidate records 10,065 signature rows per owner, matrix SHA-256
`b573a68b...17d11`, and mapping SHA-256 `dfff3a6a...90712`
([evidence](../poc/local-private-payment/private-batch-relation/evidence/2026-10-28-full-financial-source/direct-source-equivalence.json)).
That evidence expressly disclaims a setup/proof claim, and the actual-head
selection says the matrix is ephemeral and not installed as immutable public
input
([selection](../poc/local-private-payment/mpc-prover/financial/REGISTERED-ACTUAL-HEAD-SELECTION.json#L89),
[blocker](../poc/local-private-payment/mpc-prover/financial/REGISTERED-ACTUAL-HEAD-SELECTION.json#L193)).
Therefore this design remains `NOT-CURRENT / CONDITIONAL-CANDIDATE`, not a
reason to reclassify present captures.

P1 colluding with external owner C1 does not change the computing-party
threshold: C1's record, all C1-generated shares, and its adaptive choices are
corrupt auxiliary input. For honest owners, P1 still receives only one uniform
share. The comparison must nevertheless hold C1's strategy fixed. A malicious
C1 may send inconsistent shares, producing one arbitrary corrupt-owner input;
missing/malformed frames may cause denial of service. Fixed owner order, frame
shape, and failure surface are required so C1 cannot use its own early failure
to probe which honest owner or phase follows it.

Retries are security-relevant. Never reuse an additive share, signature,
intent nonce, attempt identity, MASCOT context, input tuple, or partially
consumed state after any failure. A retry must be a new attempt with fresh
owner sharing and an attempt-bound signed message. Otherwise equal local shares
link attempts, and repeated chosen deltas give P1 an adaptive validity oracle
over the same private record even though each individual stock-input transcript
is simulatable. After successful stock input, owners and honest servers must
erase the temporary additive-share vectors and transport buffers and must not
log, persist, swap, or include them in crash dumps. This is lifecycle
hardening, not part of the static MASCOT theorem; later compromise of an honest
server that retained its share is outside the stated corruption model.

Do not admit or implement this replacement until all of the following pass:

1. **Immutable program selection:** install and hash-bind the exact full
   matrix, mapping, source/model, setup/verifying key, owner-file layout, and
   input count. Candidate or ephemeral paths must fail closed.
2. **Column coverage:** for every owner input column, prove that it is signed
   canonically or uniquely/bindingly derived in the selected relation. Mutate
   each field class, every one of the 66 linked edges, signature limbs, and
   representative derived/private columns; require the one final validity
   result to fail. Document the cryptographic assumption for any non-unique
   witness claim; mutation tests alone are not a proof.
3. **Encoding and domain:** enforce canonical Fr decoding, byte/bit ranges,
   Booleanity, curve/subgroup and signature-scalar rules, plus binding to the
   selected context, owner role where required, attempt/cohort, layout/model,
   and intent nonce. Cross-owner, cross-attempt, reordered, and aliased inputs
   must fail.
4. **Stock-input integration:** in a real three-party test, use the exact common
   reset/add/exchange/finalize schedule, sum all three authenticated inputs, run
   all pending checks, and open only an approved result. The authenticated sum
   must equal the owner's vector for boundary values and randomized vectors.
5. **Active P1:** replace, zero, increment, randomize, replay, and swap P1's
   share for every field class. All non-equivalent changes must reach one
   indistinguishable invalid result, never a row/stage diagnostic; the original
   share must pass. Repeat with P1+C1 and fixed corrupt-owner inputs.
6. **Ingress/freshness:** require one fixed-length canonical frame per
   owner/server/attempt; reject truncation, trailing bytes, wrong role,
   duplicate/replayed attempts, and the old three-value format. Property-test
   `x0+x1+x2=x`, and verify production randomness uses unbiased CSPRNG field
   sampling. Any failure consumes and poisons the attempt. A lifecycle test
   must establish that plaintext share buffers are destroyed after import and
   are absent from receipts, logs, reusable owner files, and restart state;
   compiler-level zeroization and host crash/swap behavior remain a separately
   reviewed implementation assumption.
7. **Frozen privacy test:** update the capture ledger so the P1 owner frame is a
   corrupt-party input share, keep stock input transcript values conditional,
   and retain sizes, order, timing, abort phase, and retries as empirical
   leakage. Run the predeclared same-output mapping swaps; do not treat passing
   unit tests as a privacy proof.

If these conditions are established, this is smaller than DDNNT and its P1
owner-frame *content* is exactly independent of the honest owner's vector. The
end-to-end corrupt view is still only conditionally simulatable, and the
relation-binding argument remains an additional application proof rather than
a result supplied by MASCOT.

## Current selected external-owner path: complete DDNNT

The isolated unfunded MASCOT paths now use the complete **DDNNT Protocol Input
Supply**, not the three-value shortcut. Registered financial execution and
launch remain `CONFIGURED0`.
The paper considers any number of clients and as many as `n-1` malicious
servers. Its input protocol has the servers privately deliver a fresh random
authenticated mask `s` to the client using its Output Delivery protocol; the
client broadcasts `d=x-s`; the servers compute `<x>=<s>+d`. For delivery of
`s`, the servers also sample random `r,v`, compute `w=s*r` and `u=v*r`, and
send each server's local shares of exactly:

```text
(s, r, w, v, u), where w = s*r and u = v*r.
```

The client reconstructs all five and accepts only if both equations hold.
DDNNT Lemma 1 proves that this delivery view is simulatable with statistically
close distribution without the delivered value and that an honest client
accepts a changed value with probability at most `1/p`. The following input
argument then uses uniform `s` to make `x-s` uniform; a corrupt client still
supplies a well-defined value ([DDNNT15, Section 3.1, Figures 1--2][ddnnt-paper]).
This does not make abort impossible--dishonest-majority MPC cannot guarantee
liveness--but it replaces the unproved selective-failure surface with the
paper's explicit simulatable-abort/statistical bound.

The local realization reuses established field operations and adds one random
plus one multiplication per input over the historical path:

1. Reuse the current fresh MASCOT triple as `(s,r,w)`.
2. Obtain fresh authenticated `v` with `random_auth()`.
3. Compute authenticated `u=v*r` with one batched stock MASCOT multiplication.
4. Complete pending scalar MAC checks, then send only P0/P1/P2's local share
   lanes of `(s,r,w,v,u)` to that owner. Never send MAC shares.
5. Require the owner to reconstruct and check both `w=s*r` and `u=v*r` before
   broadcasting the same fixed-width `d=x-s` to all servers.
6. Retain the existing all-server byte agreement, then derive
   `public_constant(d)+s`; poison and consume the fresh attempt on any failure.

The implementation uses a fixed public 4,096-field chunk schedule. Every field
gets its own fresh `(s,r,w)` triple and independent `v`; `multiply_batch(v,r)`
produces `u` within each chunk. Stock multiplication, MAC, and checked-broadcast
work finishes before any local value share is appended, and no frame is sent
until all chunks finish. The exact contract identity is `DDNNT_ACTIVE_5N`; only
the versioned V1/V2 owner contracts are accepted. The old `3*N` and experimental
additive widths/identities fail before owner-private network processing. Each
server frame is exactly `5*n*Fr::size()` bytes in field-major `s,r,w,v,u` order,
and the return frame is exactly `n*Fr::size()` bytes.

No exact drop-in API already implements this at the pin. MP-SPDZ's high-level
client input and its C++/Python external clients all implement the three-value
shortcut, while the original paper's Figure 1 requires five values. Therefore
the safe implementation seam is the existing local owner boundary plus stock
`random_auth()`/`multiply_batch()`, not a call to the upstream helper.

Focused controls now cover exact `5*N` shape/order, canonical decoding, both
owner equations, each component corruption, the paired `r+w` selective-failure
case, common-offset disagreement, capture of authenticated share/MAC lanes,
poisoning, and refusal of old formats. Fresh three-party toy executions derived
and opened the supplied inputs and completed proof verification. Those are
implementation observations, not proof of DDNNT or privacy. Missing admission
evidence still includes actual malicious-server delivery corruptions through
the real TLS path, malformed/different owner offsets across servers, restart
and retry freshness, capture completeness against a frozen producer/model, and
the full 2,635,409-field financial shape. The recognized five-value body is at
most `CONDITIONAL-DDNNT` under Lemma 1 plus the MASCOT/OT assumptions. Sizes,
timing, abort phase, and retries remain `EMPIRICAL-METADATA`.

## Metadata is not a theorem-covered value view

The capture wrapper itself can perturb the metadata it records. Current source
does not hold the capture mutex across the delegated blocking transport call:
it marks an operation pending, executes the upstream send/receive or async wait,
then serializes capture-record emission
([stream](../poc/local-private-payment/mpc-prover/p1_capture_stream.cpp),
[wrapper](../poc/local-private-payment/mpc-prover/p1_capturing_player.cpp)).
Even so, record serialization, hashing, copying, descriptor writes, and capture
failures can change scheduling. The monotonic timestamp is sampled while the
capture frame is emitted after the delegated operation, not at packet arrival
or transmission.

MP-SPDZ documents that `CryptoPlayer` uses TLS and distinct send/receive
connections, while its protocol networking may send/receive in parallel
([pinned networking documentation][networking]). The abstract MASCOT and
SoftSpoken theorems do not model Linux scheduling, TLS record sizes, TCP
packetization, wrapper mutex contention, allocator/cache behavior, or
application exception text.

Thus a mapping-privacy experiment must freeze and retain physical metadata as
an observation family. It may not replace it with a theorem-backed “no leakage”
label.

## Exact assumptions required for `CONDITIONAL-SIM`

All of the following must be stated. If one is not established, downgrade the
affected lane to `UNQUALIFIED`.

1. **Corruption:** P1 is malicious but statically selected before the run. At
   least one computing party is honest (the current observer has two). No
   adaptive/mobile corruption, honest-host memory disclosure, or later recovery
   of their persistent secrets occurs. C1 is an external colluding owner, not a
   second MPC computing-party corruption; all C1 knowledge is explicit
   auxiliary input.
2. **Function equality:** compared mappings have identical corrupt inputs,
   public model/statement, dimensions, schedule, declared outputs, and allowed
   success/abort class. Anything not equal is explicit leakage, not hidden by
   simulation.
3. **Channels and primitives:** authenticated channels/broadcast/commitment,
   correct TLS peer binding, secure RNGs, field arithmetic, hashes, PRGs, curve
   operations, and the stated MASCOT/SoftSpoken assumptions hold.
4. **OT composition:** the pinned SimplestOT/SoftSpoken stack securely realizes
   the ROT/VOLE hybrids needed by MASCOT despite the revised SimplestOT UC gap.
   This is presently an additional assumption, not an inspected theorem.
5. **Freshness:** preprocessing, input masks, Beaver triples, proof masks, MAC
   key/OT state, attempt identity, and randomness follow their required
   fresh/single-use rules. No retry reuses a mask or failed cryptographic state.
6. **Checks:** all relevant OT consistency, sacrifice, broadcast, scalar MAC,
   and output checks complete before a successful result is classified or used.
   The corrupt P1 wire view still includes shares/masked openings transmitted
   before the corresponding MAC check; abort traces remain visible and are not
   discarded.
7. **Implementation correspondence:** the exact pinned, configured C++ path is
   a correct implementation of the paper protocols and serializers are safe.
   DDNNT corresponds exactly to Figures 1--2; the scalar/group path corresponds
   exactly to Smart--Talibi Alaoui Figure 9/Theorem 2 and Ozdemir--Boneh
   Appendix E; any deviation remains unqualified.
8. **No unmodeled side channel:** timing, size, scheduling, endpoints, retries,
   logs, host behavior, and capture observer effects are either explicitly
   included in the leakage function and experiment or excluded from the claim.

MP-SPDZ's own README says the project is primarily for comparing protocol
performance and has not undergone the security review expected for critical
production code ([pinned README][mpspdz-readme]). The pinned release does include
the 0.4.3 fix binding malicious parties to a MAC key across threads/executions
and 0.4.4 security fixes. The accompanying primary documentation explains that
the former bug enabled selective failures, requires OT/encryption instances to
be generated once per fresh MAC key, and says a MAC key must not be reused after
failure ([security-fixes.rst][security-fixes],
[`CHANGELOG.md`][changelog]). This is evidence that the exact pin and lifecycle
matter, not an audit of the local integration.

## Rules for the frozen privacy ledger

1. Make the unit of theorem coverage the **joint recognized stock-MASCOT value
   view**, never a list of independently harmless fields.
2. Record the ideal leakage beside it: corrupt-party/C1 auxiliary input, public
   program and shape, exact opening/output call sites, and the high-level abort
   bit.
3. Split mixed lanes by exact source call site. Unknown peer payloads, new field
   openings, or unrecognized group points default to `UNQUALIFIED`.
4. Keep `EMPIRICAL-METADATA` in the observer vector: times, sizes, counts,
   ordering, peers, forks, connection events, retries, partial capture, and
   failure phase. Freeze transformations and thresholds before looking at
   mapping labels.
5. Keep exact DDNNT frames, the local MAC-key share, both masked Fr/G1 pairs,
   staged local authenticated G1/G2 share/MAC state, group traffic, and final
   `A,C,B2` openings in the modeled observer.
   Do not subtract them as “MASCOT randomness.” Raw `B1` is absent; any new raw
   auxiliary group opening is an automatic unqualified schema change.
6. A theorem-covered assumption is not an empirical pass. Report it separately
   from observed mapping advantage and retain negative/aborted attempts.
7. Limit the claim to the frozen observer and workload. Even a clean result is
   bounded evidence of mapping ambiguity under these assumptions, not proof of
   general anonymity, production security, native-KAS privacy, or absence of
   host/network side channels.

## Primary sources

- Keller, Orsini, Scholl, *MASCOT: Faster Malicious Arithmetic Secure
  Computation with Oblivious Transfer*, Sections 2--6 and Appendix C,
  [IACR ePrint 2016/505][mascot-paper].
- Roy, *SoftSpokenOT: Communication--Computation Tradeoffs in OT Extension*,
  Sections 2.3, 5, 7 and Appendix F, [IACR ePrint 2022/192][softspoken-paper].
- Chou and Orlandi, *The Simplest Protocol for Oblivious Transfer*, revised
  Section 1.1 and Section 2, [IACR ePrint 2015/267][simplestot-paper].
- Damgaard, Damgaard, Nielsen, Nordholt, and Toft, *Confidential Benchmarking
  based on Multiparty Computation*, Section 3.1 and Figures 1--2,
  [IACR ePrint 2015/1006][ddnnt-paper].
- Groth, *On the Size of Pairing-based Non-interactive Arguments*,
  [EUROCRYPT 2016 / DOI 10.1007/978-3-662-49896-5_11][groth16].
- Ozdemir and Boneh, *Experimenting with Collaborative zk-SNARKs: Zero-Knowledge
  Proofs for Distributed Secrets*, Appendix E and E.1,
  [IACR ePrint 2021/1530][ozdemir-boneh].
- Smart and Talibi Alaoui, *Distributing any Elliptic Curve Based Protocol*,
  Figure 9 and Theorem 2, [IACR ePrint 2019/768][smart-alaoui].
- MP-SPDZ exact pinned source and documentation at commit
  [`113c4e47...`][mpspdz-commit].

[mpspdz-commit]: https://github.com/data61/MP-SPDZ/tree/113c4e47dd94bca9ecab029d2f0abe649bea5c52
[share-h]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Share.h#L156-L186
[protocol-set]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSet.h#L21-L66
[data-files-h]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/Data_Files.h#L464-L482
[data-files-hpp]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/Data_Files.hpp#L46-L58
[mascot-params]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/MascotParams.cpp#L8-L18
[n-amplify]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/NPartyTripleGenerator.h#L17-L21
[base-ot]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/BaseOT.cpp#L146-L158
[mpspdz-input-h]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/Input.h#L68-L84
[mpspdz-input-hpp]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/Input.hpp#L93-L149
[mpspdz-input-personal]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/Processor.hpp#L1024-L1047
[mpspdz-client-input]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/types.py#L2751-L2776
[mpspdz-external-client]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ExternalIO/Client.hpp#L46-L120
[simplestot-readme]: https://github.com/mkskeller/SimplestOT_C/blob/7ef7666909e493a18c99efe56f97cc4d13723005/README.md
[networking]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/doc/networking.rst#L37-L69
[mpspdz-readme]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/README.md#L134-L148
[security-fixes]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/doc/security-fixes.rst#L21-L57
[changelog]: https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/CHANGELOG.md#L3-L24
[mascot-paper]: https://eprint.iacr.org/2016/505
[softspoken-paper]: https://eprint.iacr.org/2022/192
[simplestot-paper]: https://eprint.iacr.org/2015/267
[ddnnt-paper]: https://eprint.iacr.org/2015/1006
[groth16]: https://doi.org/10.1007/978-3-662-49896-5_11
[ozdemir-boneh]: https://eprint.iacr.org/2021/1530
[smart-alaoui]: https://eprint.iacr.org/2019/768
