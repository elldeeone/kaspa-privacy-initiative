# NativeAuthSpend B-private seam: execution specification03

Status: SOURCE ONLY, UNCOMPILED, UNEXECUTED. This isolated proposal is outside the repository, frozen publication and candidate16. Root has authorized source preparation and independent review only. It does not select an architecture, accept a new Native profile, or authorize a build or run.

This specification retains SPEC-02.md (SHA6e8cc3539bf1d1472e26f4e42caf85434a264f352b7152c0de0f5d3e714d72f6) and SPEC-01.md (SHA477328a7c98f3a7314944b76abd5be94743715ec0ebdf6ad2e4e1ef340b1f413) and makes the following concrete implementation details authoritative. The initial specification and numbered source/review records remain immutable. No existing Native key/VK/PK is reused. The final constraint system has a new setup/key boundary even if an FFT domain happens to match.

## Question and decisive result

Can one actual Native-style Spend predicate, with its owner-secret preimage commitment explicitly replaced by a NEW authorization-key commitment, be joined to a mature Babyjub EdDSA verifier so that a coordinator's coherent replacement of a recipient fails actual signature constraints, but the same replacement succeeds after deliberate owner consent? Can a valid signature for a different hidden key fail only the actual cross-component key links? This answers one authority/interface question; it does not qualify a2-input/4-output batch, proof system, MPC driver, wallet, recovery or native acceptance.

The public synthetic baseline has one200-byte input statement, one1-input/2-output4077-byte research packet, one NativeAuthSpend component and one signature component. Two separately evaluated reference Output matrices check supplied openings against packet CM/CV/CFhash. Their proof and ciphertext bytes remain opaque dummy fixtures. None is a spendable note or delivered payment.

## Established sources and exact arithmetic

Native SHA256/HMAC, Note168 commitment, nullifier key commitment, positioned depth16 Merkle membership, value ranges and full CV blind range are retained from the exact11-file vendored Native closure. Only the owner authority hash, research domain/tags and statement layout are explicitly new. NATIVE-PREDICATE-DELTA-02.diff records the change. Native helpers use Ark0.6 and actual GR1CS matrices, not a host validity Boolean.

Constraint field P is21888242871839275222246405745257275088548364400416034343698204186575808495617. Babyjub prime scalar Q is2736030358979909402780800718157159386076813972158567259200215660948447373041. P and Q are distinct. Every R1CS/witness coefficient is a canonical element of P. S and the native CV blind must additionally satisfy their existing Q bounds.

Circomlib2.0.5 is locked at archive SHA9f80fa85d9c186589998d15e6dcb8ec59a6ed3fe1ec3cb2f753e493d94dd46b6. The selected inspected files match official commit35e54ea21da3e8762557234298dbb553c175ea8d. CIRCOM-TRANSITIVE-SOURCE-01.json pins all13 transitive circuit files. Circomlib and circomlibjs package manifests declare GPL-3.0; no claim of license compatibility for a future production distribution is made by this isolated prototype.

Stock Babyjub has168700*x^2+y^2=1+168696*x^2*y^2 over P, order8Q, and stock BASE8. Native CV uses the separately typed normalized Edwards curve A=1,D=168696/168700; same coordinate field is not a permission to mix point encodings or group bases.

The wrapper uses stock BabyCheck, BabyDbl, Bits2Num_strict, Num2Bits, IsZero, Poseidon(2) and EdDSAPoseidonVerifier. Poseidon(2) here means the original existing width3 Poseidon with2 inputs, NOT the newer algorithm Poseidon2. No signature/hash primitive is invented. The signature challenge remains stock Poseidon(5)(R8x,R8y,Ax,Ay,M), and S*BASE8=R8+h*[8]A with enabled=1 and S<Q.

Group order8Q and primality of Q are explicit soundness assumptions underlying image[8]=the Q-subgroup. GuardedCofactorImage constrains every preimage/intermediate/target point on curve, performs3 stock doublings with both actual denominators nonzero at every step, checks the final equality to the target, and requires target.x!=0. In the odd prime-order subgroup this excludes identity. Completeness of admitted honest points and guarded denominators remains a coverage/liveness assumption to test, not a theorem supplied by passing fixtures.

## Owner authority and transport

The new research domain D is32 bytes0xa6. Canonical AK is Ax32LE||Ay32LE, both coordinates<P. It is neither a compressed Babyjub encoding nor the Native CV encoding. New Note.owner=SHA256(KPBPOW01||D||AK64||Note.incoming32). Actual consumed incoming bytes remain included. Legacy owner_secret s is neither relabeled nor allocated.

The current owner_signer API exports AK as128 lowercase hex characters; R8 is a pair of canonical unsigned DECIMAL strings and S is a canonical unsigned DECIMAL string. Earlier SPEC01's illustrative32LE R8/S handoff wording is superseded. Conversion to stock host field objects happens only after canonical parsing. Verifier transport must refuse raw Fr aliases>=P, never reduce them modulo P. Values canonical in P but invalid semantically (byte256, limb2^128, S=Q or S+Q) are admitted to the actual constraints for negative tests.

Locked circomlibjs0.1.7 eddsa.js uses blake-hash, not the newer upstream noble implementation. Exact selected body SHA is d0e3934c3a01ec185abe12d46dd123189a5b4515a79eddaeb53496c413f09b3a. Its message API consumes an eddsa.F element. The owner code converts Poseidon output via Poseidon.F.toObject to canonical BigInt, then eddsa.F.e. A bare BigInt is not passed to signPoseidon.

Before any export the owner mirrors oncurve/subgroup/nonidentity checks for A and R8, plus0<=S<Q. A degenerate deterministic R8 causes a stop before returning any signature; the seed/message/nonce is never retuned. A later verifier refusal would be too late for a zero-nonce signature. No zero-nonce signature is constructed by any control. Known test seeds00..1f,20..3f,40..5f exist only in the owner test worker and are explicitly public/unfunded. No real signing key, expanded scalar, nonce prefix or nonce enters the signature verifier, Native circuit, full R1CS witness or interchange. CV blind r is a different permitted value.

Owner and verifier Node requests are fresh processes. Only keys/sign modes dynamically import owner_signer; verifier prepare mode imports verifier_aux and public_packet, and matrix/witness mode imports the selected adapter and qualified stock readers. The source tree is public synthetic; mounting a source file does not itself establish a cryptographic isolation claim. The resolved actual runtime import closure must be authenticated before execution, and the owner signer must not be imported by verifier jobs.

## Exact signed statement and public reconstruction

Statement200 is KPBPSP01(8)||D(32)||oldCMroot(32)||inputNF(32)||inputCV(64)||effectsHash(32). SHA256(statement200) is split into LE(first16) and LE(last16), each128 bits. Native hashes all200 bytes inside its actual CS. Signature M=stock Poseidon(2)(lo,hi) is computed inside its actual CS. This computational hash bridge is not an injective encoding of256 bits.

EffectsHash=SHA256(KPBPEF01||prefix193||body[0:3756]). It commits action identifier, old/new states and reserve values, point, input NF/CV, fee, delta, both complete Output520 tuples including their128-byte Output proof fields, and all transition witnesses. The final128-byte Spend proof at body[3756:3884] is excluded to avoid a cycle. Domain/version/lane/frame tags are fixed for this proposed transfer profile; no Exit format is accepted here.

Mandatory external verification reconstructs statement/public limbs from the complete packet and calls research_wire.validate_public for actual NF successor and CM append paths, then research_wire.require_current_head against the supplied synthetic old State112/point/reserve/tail. The latter compares a supplied head and cannot authenticate a chain, backing, history or original backup. Node public_packet only reconstructs structure/effects and does not replace those public path checks. No caller digest/M, host signature-valid bit, path-valid bit or proof-valid bit is copied into a constraint.

The Rust stdin checker is intentionally a component interface, not an independently safe Native acceptor. Its SAT label describes the joined authorization/spend rows. The closed runner separately requires both referenceOutputFailures==0 for every matrix case. Public validation, reference-output checks and cryptographic residuals must remain separately reported.

## Complete packet offsets

All offsets are zero-based, half-open; counts and amounts use explicit little-endian unsigned integers and integer sompi.

Prefix193: tag[0:8], shape01000100[8:12], input point36[12:48], ff*8 sequence[48:56], old reserveu64[56:64], script-size3700[64:66], inputSPK37[66:103], output-count0100[103:105], new reserveu64[105:113], script-size3700[113:115], outputSPK37[115:152], zero37[152:189], bodylength3884u32[189:193]. SPK37=0000aa20||hash32||87.

Body3884: tag[0:8], fouru16(1,1,2,0)[8:16], D[16:48], actionID[48:80], zero32[80:112], point36[112:148], oldState112[148:260], oldreserve[260:268], newState112[268:380], newreserve[380:388], fee[388:396], payout0[396:404], delta32[404:436], NF[436:468], CVin64[468:532], Output0[532:1052], Output1[1052:1572], NFwitness1160[1572:2732], CMpath0[2732:3244], CMpath1[3244:3756], finalSpendProof128[3756:3884].

State112: tag8,D32,CMroot32,CMcountu32,NFroot32,NFcountu32. Output520: CM32,CV64,CF264,CFhash32,proof128. The fixture starts with CMcount4/NFcount1 and ends6/2. Its sparse CM tree has depth16 and input position3; NF tree depth17 starts with the actual sentinel leaf. All paths are generated from the fixed public synthetic fixture. FIXTURE-RECIPE-01.json and harness/fixture_builder.py define every byte and supplied synthetic head.

## Actual matrix and full witness boundary

Each component has67 instances: ONE, two digest limbs,64 AK-byte field edges. Native allocates this order explicitly. Signature normalization uses the .sym physical witness column and exact selected top-level name bijection1..66, never declaration-order guessing. Unselected optimization aliases follow official Circom semantics; private physical suffix>=67 remains fixed. The selected adapter must preserve every ordinary R1CS row, term, coefficient, raw wire-to-label representative and full nVars witness, with explicit inverse checks. Custom/unknown sections and all unsupported GR1CS predicates are refused, including unexpected empty predicate labels. No constraint family may be silently dropped.

ONE maps to ONE0. Native old i>0 maps i+2. Signature old i>0 maps i+68+Wn. Final instances are[ONE,outerlo,outerhi]. Final witnesses132+Wn+Ws; total variables135+Wn+Ws; rows Cn+Cs+68. Keep two independent component copies. Append2 Native-digest-to-outer,2 signature-digest-to-outer and64 key-byte equality rows. Each row is(left-right)*ONE=0. All component rows are inverse checked before evaluation. All rows are evaluated with actual A*z*B*z-C*z residuals; native, signature and link regions have separate counts. Raw ONE must equal1 and vector length must match before evaluation; otherwise a homogeneous allzero vector can pass matrix equations without being an admitted assignment.

## Frozen source controls and future commands

CONTROLS-01.json defines16 actual-matrix cases:2 expected SAT positives and14 expected residual failures, each with exact region expectations and2 zero reference Output failure counts. They include coherent substituted outputs with old signature, deliberate reconsent, valid wrong-key component with link-only failure, changed outer digest with link-only failure, scalar boundaries, direct byte/limb assignment inconsistencies, bad Native owner/high position, bad cofactor preimage, R8 identity, action replay, coherent identity/torsion owner fixtures. Four tiny assignment-kernel refusals and one raw WTNS field-P parser refusal are additional boundary controls, not cryptographic UNSAT evidence.

CPP0 uses official Circom2.2.3/ad44e915a12bb047b05745c2884aad9cc8326bc6, --O1 --prime bn128, --c --sanity_check 0 --no_asm, and the standard generated Makefile. Sanity0 is not O0; no NDEBUG, generated-code edits, failed assertion suppression, WASM fallback or partial witness is allowed. Require full ordinary/CPP0 R1CS byte identity before any use. A generator refusal is retained as refusal and never receives residual-failure credit. Direct WTNS mutation controls intentionally keep stale auxiliaries and are distinguished from coherent full-witness substitutions.

COMMANDS-02.json has the exact proposed closed argv arrays. Build and run identities are fresh0700 build-01/run-01 under the dedicated public work root. Cargo is offline/locked/jobs1, realgcc15 selected. Build tools/dependency sources and owned source are readonly; runtime mounts only the selected public sources, stock JS dependencies, selected binaries/dat, system libraries and fresh owned output. No home/repo/private/PK/network input is mounted. A separate post-build Root-selected file/hash closure must authenticate the binary, dat, ordinary/CPP0 matrices and .sym before run. Cargo hardlink admission failures are preserved; no unreviewed copy or guard bypass is allowed.

harness/run_gate-02.py authenticates the source freeze and selected post-build closure through unchanged helper09, saves one immutable normalized matrix/map selection before any signatures or controls, retains own selected argv/stdout/stderr and evaluates the frozen expectations. All source files are unimported/uncompiled/unexecuted at preparation. Its first unexpected process, map, field, region, reference or residual result stops and retains evidence. No fixture, threshold, flag, matrix, expected region or generator backend retune/retry under a used identity.

Proposed future resource envelope is nice10, at most2CPUs and8GiB, only after Root releases the main publication/readback window and selects an actual outer scope. The argv alone does not enforce a memory cgroup. Source preparation does not reserve tmpfs or create runtime directories. Large matrices/full assignments/cache remain local reconstructable outputs outside Git/recovery DATA unless separately selected. A source/build failure is not a reason to delay the completed financial publication.

## Explicit unresolved boundaries

All-server collusion may learn amounts, openings, hidden authorization keys/signatures, note membership and ownership mapping from the joint witness; a signature could preserve funds while confidentiality still needs an honest participant. Current owner-local NIZKs keep more of those openings outside the aggregate witness. This is a changed threat model, not automatically stronger privacy. Active retry/cohort/intersection leakage and sender/network views remain unresolved.

The new MASCOT exact-Fr scalar gate does not qualify an active-secure joint witness/prover. Existing Babyjub-Q prepared binaries/sessions/share files are incompatible with P and must never be reused or modulo-reduced. A fresh malicious exact-P sharing/prover profile, witness boundary, simulation/adversarial assessment, proof reduction and key/setup agreement remain open.

No2/4 aggregation, setup, proof, malicious MPC, proof cost/fee benefit, privacy gain, delivery, chain currentness, Native acceptance or complete recovery is established here. Original-backup key derivation, receiver address/scan capability, old-note migration and independent Exit require a separately reviewed new profile. EVERY spend/withdrawal/exit path must enforce the same owner authorization over complete exact effects, destination, root/domain/lane/action/input identity before co-servers can safely be denied spending authority. Legacy notes and exits cannot silently accept this new authority relation. There is no privileged fallback.

The published wallet source-policy withdrawal fingerprint is a separate workload problem: proof cost and hidden signature keys do not erase deterministic amount bands, note selection/order, timing or retry cohort information. Wallet/workload ablation and the payment observer goal remain independent work. The separately blocked native-exit-delivery benchmark remains stopped and is not retried by this seam.

## Source-only corrections retained

COMMANDS01 selected a host Node path that metadata resolved to a317-byte public CA wrapper. The wrapper would execute an unmounted home path in the closed namespace. This was found through unchanged-helper source reads, BEFORE any build/run. COMMANDS02 changes only that read-only leaf mount source to the existing standalone Node122889056bytes, SHAd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c. run_gate02 changes only the commands filename. COMMAND-REPAIR-02.diff preserves the exact change; no permission/check/Native/control/backend change occurred.

The suspected repeated-physical-wire .sym alias hazard was investigated and disproved by official pinned Circom2.2.3 source. Retained original IDs receive unique physical slots; deleted IDs emit -1; raw wire-to-label mapping is the inverse of that same retained mapping. No alias relaxation or adapter02 is selected. signature-component-adapter-selected.mjs is an ordinary byte-identical copy of reviewed adapter01 SHA7cb1579791fe61d2675ebd0f88c923362d6d5632226fcc8f5cb13fe9a7a70161. The negative hypothesis remains recorded in the independent receipt.

The complete-packet owner visibility limitation is explicit in PUBLIC-EFFECTS-OWNER-VISIBILITY-01.md. This current one-input seam does not solve multi-owner full-effects message agreement or private finalization; those are protocol work beyond this authority gadget.
