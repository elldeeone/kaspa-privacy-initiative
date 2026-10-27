# Direct composition of the current native relations

2026-10-27. Source assessment only. No compilation, constraint run, setup,
proof, RPC, financial action, Original job or private input access occurred.
This proposes no change to the current financial profile or selected keys.

**Decision:** direct composition deserves a small, separately authorized,
setup-free qualification gate. The actual native Spend and Output circuits use
the same BN254 scalar field, and an existing distributed-prover library exposes
an illustrated Arkworks 0.6 matrix path. It could avoid recursive pairing
verification. It does **not** preserve the selected owner-local-proof authority
boundary automatically: a shared extended Spend witness contains consuming
secrets. The existing exact-effects NIZK design remains the candidate that keeps
those secrets out of the aggregate prover.

## What the existing source establishes

The actual sources are under [the local-payment relation](../../../../../poc/local-private-payment/relation/src/circuit.rs),
not the older owner-private-payment experiment. Both SpendCircuit and
OutputCircuit implement ConstraintSynthesizer of ark_bn254::Fr. They use the
same SHA256 and Baby-Jubjub value-commitment gadgets over that field. Arkworks'
[trait](https://github.com/arkworks-rs/snark/blob/d027f19d699d3af459ae4924366d71159231bc82/relations/src/gr1cs/mod.rs#L54-L60)
accepts a caller-supplied ConstraintSystemRef; appending predicates to a common
system is therefore a concrete source-level route. This is not an executed
joint circuit or a claim that the present public interfaces already compose.

| Existing native component | Source-observed obligation |
| --- | --- |
| Spend, circuit.rs:129–172 | Note168 opening; owner_secret and nullifier_secret; SHA owner/key commitments; positioned HMAC-SHA256 NF; depth 16 CM membership; bounded value and canonical CV opening; exact Spend200 statement hash. |
| Output, circuit.rs:174–184 | Note168 commitment; bounded value and canonical CV opening; exact Output168 statement hash. CFhash is bound, but encryption correctness is not proved. |
| bind_public, circuit.rs:49–56 | SHA256 of the complete statement, split into two constrained little-endian 128-bit inputs. No reduction of a whole 256-bit digest. |
| Native state/effects acceptor | The component circuits do not replace reserve consumption, exact effects, NF insertion, CM appends, CV balance or replay prevention. These remain explicit batch obligations. |

The selected **current native** manifests record Spend: 1,476,992 constraints and
1,461,143 witnesses; Output: 217,807 constraints and 214,998 witnesses. Both have
three instances including ONE. Literal two-Spend/four-Output concatenation is
therefore **3,825,212 constraints and 3,782,278 private assignments**, before any
binding, state or optimization changes. These are arithmetic sums of separate
manifest counts, not a synthesized batch, resource estimate, fee result or
comparison against a measured recursive circuit.

The frozen [full-native aggregate contract](../FULL-NATIVE-VALIDITY-AGGREGATE-CONTRACT-01.md)
does not reject mathematical composition as impossible. It deliberately
selects the owner-local NIZK branch: each owner retains current consuming
secrets and authorizes the final complete effects through its current Spend200
proof. Recursion checks those authorizations without requiring their witnesses.
Direct composition proves the original predicates again and consequently has
a different input/authority problem.

## Calling six existing circuits is insufficient

Six unchanged generate_constraints calls add twelve public SHA limbs, giving
thirteen instances including ONE. The current verifier/key interface fixes
three instances and a 328-byte role VK. Such concatenation is not a current
IC3 proof or a native 2/4 acceptance path.

More importantly, each existing circuit allocates its statement bytes internally
as fresh witness variables and returns only success. Copying the same host
Rust values into an outer batch and a component does not constrain equality
between their separately allocated wires. Changing allocation modes or dropping
the component hash without an explicit replacement could leave effects fields
unbound.

A qualified composition interface would reuse the original constrained gadget
bodies while accepting/returning the **actual constrained statement variables**.
The standalone adapter should retain its original public-hash contract. A new
batch adapter must enforce its selected U/V bijection, bind every complete
statement and output tuple to one exact batch transcript, and expose only the
chosen batch inputs. Byte/range checks, domain tags, SHA/HMAC semantics, path
position bounds and CV checks cannot become host assertions. Its native public
predicate and arity need a separate profile/ADR; current 1/2 entry points must
continue rejecting 2/4.

This reuse need not invent a new cryptographic primitive. It still requires
reviewed constraint refactoring and a new circuit-specific setup/VK. Existing
Spend/Output proving keys cannot be combined or reinterpreted as its key.

Proving a component's witness predicate directly does not verify arbitrary
supplied inner-proof bytes. The frozen recursive contract retains four whole
Output520 tuples including existing proofs; replacing those checks or omitting
redundant proof bytes needs an explicit new frame/predicate decision. A narrow
Output-core gate is useful without sharing a Spend secret: OutputWitness has
only Note and blind. Keeping owner-local Spend NIZKs would still require a
qualified route for verifying those authorizations.

## An existing library path avoids a mandatory Circom translation

At co-snarks commit 436f63fa17f2f10ece38c6650df68da99fbc0307, the workspace and
lock use Arkworks 0.6 and taceo-groth16 0.2.1. Its
[REP3/Shamir library APIs](https://github.com/TaceoLabs/co-snarks/blob/436f63fa17f2f10ece38c6650df68da99fbc0307/co-circom/co-groth16/src/groth16.rs#L329-L424)
accept an Arkworks ProvingKey, explicit ConstraintMatrices, caller-supplied
SharedWitness and a generic reduction; LibSnarkReduction is exported.

The locked dependency's official
[witness_map source test](https://docs.rs/crate/taceo-groth16/0.2.1/source/tests/witness_map.rs)
(:79–108,242–288) illustrates the bridge: synthesize/finalize Arkworks GR1CS,
take all three matrices under R1CS_PREDICATE_LABEL, copy dimensions/nonzero
counts, and concatenate instance_assignment with witness_assignment. Its BN254
test compares a LibSnark proof with ark-groth16 using identical randomness and
verifies it. **These tests were inspected, not executed here.**

The matrix types are not aliases: Arkworks 0.6 returns a map of predicate labels,
while taceo defines an explicit A/B/C structure. A native adapter must reject
unexpected predicates rather than silently export only one. It must preserve
all coefficients, wire indices, constant ONE, public-prefix order, private
offsets, dimensions and the setup's reduction/key identity. The adapter must
explicitly enforce public_inputs[0] equals ONE; length checks are not that
equality check.

The shipped CLI is different: split-witness reads a complete clear Circom
.wtns plus .r1cs; proof generation reads a snarkjs .zkey and selects
CircomReduction. Named input-share merging is not an arbitrary auxiliary-
witness splice. The library route is promising; existing CLI compatibility is
not established by sharing a field or file suffix.

## Owner-local auxiliary wires do not solve authority or MPC security

The actual [SpendWitness](../../../../../poc/local-private-payment/relation/src/lib.rs)
contains owner_secret and nullifier_secret, and circuit.rs:140–143 allocates
them into witness bytes. Giving parties shares of that complete extended
witness still shares those consuming-secret wires. Removing their named fields
from an input JSON does not remove them from the mathematical witness. No
contribution-only protocol that avoids these wires was qualified by this pass.

**Trust consequence:** if the external prover parties can reconstruct that
witness, their collusion threatens funds as well as privacy. In contrast,
reconstructing an owner-local exact-effects proof does not reveal its original
spending witness and does not authorize different outputs. The current native
Exit predicate also proves knowledge of those secrets; its payout OpCheckSig
bytes are the destination locking script, not an independent owner signature
over the reserve spend (policy.rs:474–584).

Owner-local synthesis may compute separable component auxiliaries, but a joint
shared witness still needs one authenticated variable map, consistent shares,
hidden routing and all nonlinear cross-component auxiliaries. Publicly labeled
owner-to-wire/output blocks can reveal the mapping without exposing field
values. The inspected SharedWitness API includes ONE in its public vector and
checks lengths; those checks are not full private R1CS satisfaction.

The inspected REP3 and Shamir APIs explicitly document **semi-honest** security.
They do not qualify malicious extended-witness assembly/proving, opening-by-
opening privacy, fresh proving randomness, active retry behavior or a
MASCOT-to-prover bridge. A valid final Groth16 proof does not establish those
privacy properties. The amount of cross-owner computation is unmeasured.

## Native curve, bases and nullifier-key scope

The actual CV group is ark_ed_on_bn254's normalized
[Baby-Jubjub](https://docs.rs/crate/ark-ed-on-bn254/0.6.0/source/src/curves/mod.rs):
Edwards A=1, D=168696/168700, cofactor 8. Its
[base field](https://docs.rs/crate/ark-ed-on-bn254/0.6.0/source/src/fields/fq.rs)
is explicitly ark_bn254::Fr;
its scalar modulus is
2736030358979909402780800718157159386076813972158567259200215660948447373041.
The native CV encoding is canonical uncompressed x32LE followed by y32LE.
This is distinct from the BN254 G1/G2 groups used by Groth16 proofs.

The existing public generator derivation is also concrete, not a chosen known
scalar relation: cv.rs:107–113 seeds ChaCha20Rng with SHA256 of the fixed public
GENERATOR_SEED_LABEL and calls stock Pedersen setup. Setup samples the R base
first and V second; each table is then the known
[doubling powers](https://docs.rs/crate/ark-crypto-primitives/0.6.0/source/src/crh/pedersen/mod.rs)
of its own base. The selected
[group sampler](https://docs.rs/crate/ark-ec/0.6.0/source/src/models/twisted_edwards/group.rs)
draws a random field y and sign, recovers a
curve point and clears the cofactor. It does not draw a public scalar and
multiply a common fixed generator. No known discrete-log relation between V
and R is supplied by this source path. Unknown discrete log remains an
assumption about the fixed sampler/transcript; distinctness, subgroup and
doubling checks do not prove independence or binding. The public seed is not
Groth16 setup entropy, and a failed frozen derivation must halt without retuning.

At the relation boundary, k is not owner_secret s. It binds the note's key
commitment and computes HMAC-SHA256 positioned nullifiers. Knowing k allows
nullifier computation/linkage for the relevant public CM/position, but current
Spend and Exit additionally require the SHA owner preimage s. k alone is not
current spending authority. The [public recipient KDF](../../../../../poc/future-recipient/v2/recipient.py)
derives both roles with HMAC(seed, fixed derivation tag || role8 || domain32 ||
u64LE(index)), using distinct role tags. k is scoped to
the invoice index, not wallet-wide; reusing that domain/index reuses k. One
disclosed k does not reveal other-index keys/master seed under the PRF
assumption. No actual wallet index use was inspected.

## Separate, established authorization-key alternative

There is an existing design pattern that can avoid putting a master signing
secret into such a joint relation. It is a **new note/profile/key design**, not
an exact reuse of the current Spend predicate:

- [RAILGUN JoinSplit](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L15-L97)
  binds a verification key and separate nullifyingKey into the input note
  identity; its EdDSA verifier is enabled unconditionally over bound public
  effects. The private circuit inputs include a signature, not its signing key.
- [Orchard keys](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L152-L215)
  distinguish ask from the
  [FVK's ak/nk/rivk](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L386-L400).
  Its [circuit binds randomized verification authority](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L686-L704).
  These are source patterns, not drop-in native codecs, signature schemes or
  reusable KPI intents.

There is a real signature circuit source, but no qualified Ark-native drop-in.
Circomlib's EdDSAPoseidonVerifier is a constrained verifier with enabled=1 in
the inspected RAILGUN wrapper. Its Baby-Jubjub formulas use A=168700,D=168696,
which is not the same affine representation as native A=1 CV bytes. Sharing
the BN254 scalar field does not establish point/generator/encoding compatibility
or cross-frontend witness interchange. A new authorization-key scheme could
select its own fully specified compatible representation; none is selected.

In particular, selected ark-crypto-primitives 0.6 provides a
[SigVerifyGadget trait](https://docs.rs/crate/ark-crypto-primitives/0.6.0/source/src/signature/constraints.rs)
but its [Schnorr constraints module](https://docs.rs/crate/ark-crypto-primitives/0.6.0/source/src/signature/schnorr/constraints.rs)
implements only public-key
randomization. Its ordinary Rust SignatureScheme::verify is not a constrained
signature verifier. EdwardsVar/field compatibility therefore supplies useful
building blocks, not an implemented authorization gadget. Exact message,
compressed-point/hash transcript, subgroup/nonidentity checks and gadget
integration require a separate reviewed qualification.

Under a complete adapted predicate, prover reconstruction of note/nullifier
material and a final-effects signature should still not permit signing a
different spend. The owner retains the signing secret. That conclusion needs
the chosen established signature assumptions, key/point admission, binding to
the actual note, and mandatory exact-effects authorization on **every** consume
path, including independent Exit. A host/coordinator signature check is not
sufficient. Adding a signature only to batches while leaving an old unsigned
Exit route spendable with shared current secrets does not protect funds.

The privacy tradeoff remains even if the new signature boundary protects funds:
the selected owner-local NIZK branch keeps note openings and values outside the aggregate
witness. Direct witness sharing includes openings/amounts and relevant
nullifier material. Full prover collusion can reconstruct those data and their
mapping; it may link other notes that reuse the disclosed invoice index. A
signature route could preserve funds under full prover collusion while still
requiring a threshold assumption for privacy. It is a changed threat model,
not an automatically stronger replacement.

An outside-the-joint-proof signature is also only an open alternative: native
consensus must enforce its authenticated verification key and exact message,
and its sighash/proof-byte ordering and hidden-owner interface must be specified.
No suitable current native opcode/interface was qualified here. Do not publish
stable owner keys as an accidental replacement linkage leak. A new key/note
contract also requires migration, wallet KDF/scanning and original-backup
recovery review. The earlier
[collaborative source memo](../COLLABORATIVE-INTENT-PROVING-SOURCE-01.md)
already records this alternative; this assessment does not expand it into a
new subsystem or select it over owner-local NIZKs.

## Smallest useful next gate

1. **Setup-free Output binding gate.** Keep the current crate/files untouched;
   extract the Output core in an owned synthetic-only research copy/adapter.
   Even a predicate-preserving source refactor changes the current source hash
   checked by the manifest loader. Expose constrained variables; retain a standalone
   wrapper that reproduces the original predicate/matrix identity. Give a
   one-component batch wrapper one explicit statement binding. Use the current
   public synthetic fixture, never an Original or funded note. Check the
   genuine assignment and directly inconsistent CM/CV/domain/digest/auxiliary
   assignments in actual R1CS. A private statement copied only in host code
   must not pass a changed outer statement. Preserve range/scalar boundaries;
   parser/generator failures are distinct from constraint rejections. The
   original selected Output matrix identity is 21e21c057dc22d0100d2dd46a6867acba2f89ef1481b8046b4b8c29d8521c116.
2. **Matrix/assignment gate.** Follow the demonstrated official conversion,
   require the complete predicate set and exact ONE/public/private layout,
   compare the native and exported A/B/C evaluations, and reject omitted,
   shifted or reordered wires. This requires no new parameters or proof.
   Wrong-field reduction, matrix loss and a Circom/LibSnark mismatch cannot be
   papered over by a successful parse.

These gates could establish a reusable native predicate seam and exporter
boundary. They do not establish the full 2/4 relation, an MPC construction or
funds-safe secret sharing. Before any shared Spend witness, explicitly choose
the authority boundary. A full batch must still enforce whole-tuple private
bijections, exact owner consent/effects, value/antiwrap checks, sequential
CM/NF state transitions, reserve/fees and replay/currentness. Current Output
still leaves ciphertext correctness/recipient spendability open. No delivery,
independent recovery, native acceptance, malicious privacy or cheaper fee
claim follows from these source findings.

## Exact source identities

Every body/digest input was read through unchanged helper09. Native files are
the actual local-payment source closure 82cf9c59c17c006f79faf2b7689d09690ad505b776f9ce6409f4d1f9ccc79e5c,
also recorded by [the existing public fixture](../native-g16-adapter-01/FIXTURE.json).
Official Arkworks files were freshly captured at commit d027f19d699d3af459ae4924366d71159231bc82
and matched the selected local 0.6.0 dependency bytes. Co-snarks sources and the
locked taceo archive were independently captured by the interchange review;
its source-only appendix/ledger remain under
/var/tmp/kpi-direct-composition-cosnarks-source-01.

| Source | SHA256 |
| --- | --- |
| Native relation Cargo.toml / Cargo.lock | 32665070753ad63b5787923360586952af3af50a06f711503d9d2a5db694386f / 26af87b0b440cbe138a6d619982e2e8e19b262cfc5cb149cf1c9e7655a1d1e9e |
| Native circuit.rs / lib.rs | e13fa9bd6ba33bd01b71e824d10944b3d8561854b3c026f997b282cf57fde4b0 / f93c2593444acd3936595e4e0d07cc680ff8ada05ce9f9c7dd5a47a387245b9e |
| Native statements.rs / exact_sha256.rs | bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123 / 24c7bb2e8c830261a1d000f96a0add5c19d7b992c1d7fcd0021ab272b0c0e9b8 |
| Native keys.rs / native policy.rs | 84095f2c53342f869e8bc833b6af44694e847bd55484454d103e01e93177b955 / 63c56238bac40a8f58b1d2e2442ee7dcc259447515995922c99bb2e502181e7f |
| Current Spend manifest / Output manifest | 4d28ba947357debb486e623c82ef03e778d3b986be9891696eca022926a08464 / c400914d0b68c8f7846c198fd462210b35212f3e893f1f7801c457ad0069d729 |
| Arkworks GR1CS mod.rs / constraint_system.rs / constraint_system_ref.rs | cba08cf8d4e9cc029d475d5811d3a8e1737a625418c0b8344c855a51db1eed45 / e9e52ae9347757946a41c79ad86f979aaee197e4d2575b41f1013a2e4c0ef6ba / 86f2ffa45669be57b67a8be451196172c1c01119179685ff131291e31a74505d |
| co-snarks prover API / witness types / CLI | c36cd18c81a88638d18e5444d9a0c0a31f959cf2b69cb32383c7f969185789dc / 9e859b9629a2b5576c1d7e3539f01270d57d8d7dc1d2aa72dabd988e28424739 / 80d66e197e7cabcc00b68ec39d7829637560e09ea10b3f921d67d07c4efecca6 |
| Locked taceo-groth16 0.2.1 archive / witness_map.rs | c15455295f924d5d96712127577ca5857487f159c26578f05774198de328415f / 6bcb55e2ad4127c16cbb030af3a50850a3fd37922c4a5b6e51bc7dcefeb21938 |
| RAILGUN JoinSplit / Orchard keys / Orchard circuit | afcc38a53ed9f5dcd899a22b54a6e5616f9c9a7aeb9d391926ac2fdc7011ff82 / ed5c26bc7907a928134f07612af322c2f55dd5da28b452660bff77f959c287ba / ce6506c490ce3ebea6ac833432052a8928051c5bea34bb5cdea22ce9ac49600c |
| Interchange appendix / its 13-entry source ledger | 564f501b1d2e61663e2cbe820f85cf8e6f18fa022e306c6a50958374b6243590 / fc225112186426d89e0f3e5ac2bf0547f21b4062a30a4ec8666eaf578e28fd80 |
| Native CV / recipient KDF | 350153426d8ff86905a7956a76311726812151bbe301b319ee254336b33c2f05 / 93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2 |
| ark-ed-on-bn2540.6 curve / base-field alias | 4dbeebd29eed11303995716d523b1b9e9d5637154a2d6e899e1cbccb587163bc / 754fe27aa1d02d7daa6f23612e92ca2c33edc7b7cd29a45044a115bab629db5f |
| Arkworks Pedersen setup / CRH generator powers / Edwards group sampler | 4b7f3a0c55e26475ce2a76a46d924a06f63d13fda8206f1d8083529a7d719b77 / e7d419bb6d6f21771cb8e43a41d3c8cceee0c08857c1f7b75fc067189586ef1f / fd1137f2d271c71083014c01552004d671213b6f4752b78dff23e6c74e8318d4 |
| Circomlib EdDSAPoseidon / Baby-Jubjub formulas | 3e85c0aac26da6e8dd10565643790f82c905e88db0c5a673853e329618e1c29e / fdd45cd3edd59621c203d478218c1a623a03acdd4d5be997208310bc72df61ce |
| Arkworks0.6 signature trait / Schnorr constraints / host Schnorr | aa3f40cfad4c4e369fe4e426b5929f23943abcaa8db20809e3a728b3a375f896 / 2aaf8c2a56cd85df156669e65a28cea478808a7ad46f003987d1572d269a20bc / a3c2e8b32fb5c13b7d69e606d78639290f802cab8176e4ee4123e31ace1f4a25 |

No current native source, key, financial profile, global architecture document,
publication candidate or release was modified. The separate blocked delivery
benchmark was not retried or reused.
