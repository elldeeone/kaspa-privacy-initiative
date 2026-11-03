# Private EXIT and generic native helper: independent source review

Scope: separate ADR-0050 prototype and ADR-0049 recovery helper. The reviewer
reads source, fixture plans and artifact hashes only. No native/proof/RPC run,
funded action, private profile, private signing key or proving parameter is read here.
Passing this review is not a security or cryptographic correctness claim.

## Generic recovery helper

Source/fixture ACK: `recovery-helper-source-03/SOURCE-FREEZE.json`, SHA256
`a32b17b10a71d0e85f1810d54e21e7670f9a390d55d3bf896b0d0b15457a7111`.
All 14 listed members matched. Helper main is
`c59114c1c5d19f569bce865e9619bed88d5b4b463250908ceceeffa623ebeb5b`.

The earlier caller-supplied tail digest was only consistency: an arbitrary
program could return EvalFalse and falsely suggest the intended owner-signature
gate was reached. The selected helper now regenerates the source-approved
KPX2 program, parses every opcode using the official parser, requires canonical
serialization, patches exactly ten Data32 domain operands and one VK328 push,
and compares the whole program. State112 is the only mutable state prefix.
An adjacent caller hash no longer selects the supported opcode program.

The source requires explicit disclosure consent before preparing a signing
request, quote mode rejects signing material, and errors are fixed strings.
Quote constructs a zero signature with the ALL byte, then requires isolation
PASS and the exact final EvalFalse owner-signature boundary in native Full and
the input engine. It returns neither the revealing payload nor a transaction.
Signing binds the quoted version-one transaction ID, verifies that the supplied
native key matches the committed note payout key, uses official Schnorr ALL,
and requires signed Full/all-engine acceptance and unchanged mass/fees/ID.

Prospective tests include continuing/terminal historical public fixtures,
fresh-domain42fab9 historical quote without any fresh signing key, bad self-hashed
program, domain/SPK/state/NF paths, fee/range/canonical encodings, explicit consent,
quote refusal of keys, quoted-ID substitution, wrong owner and sighash override.
These are supplied-context tests, not accepted current exits. Actual execution
artifacts remain to be checked separately. The first helper version correctly rejects the new private-EXIT policy until
that additional program is independently approved.

The first helper execution packet subsequently closed read-only: pre-run freeze
`65247e7d5f4db0c5cbd7e9cfc9bd74a9ee3077d09fd305588157ce1d2ff24d97`
has 12 exact source/binary/public-fixture members, all rehashed. The ten test
methods pass, including fresh-domain historical quote and public continuing/
terminal signing controls. Result SHA256 is
`e48674c57746231202699be32d50ad9f58fdf667c24046d4540e04431fdd6306`;
the exact test log hash matches its declaration. Cleanup records inactive/dead,
MainPID0 and no owned processes. The reviewer did not repeat any test, native
execution, signing or network request. This remains historical/supplied-context
evidence, not a freshly recovered unspent payout. The dual-program extension subsequently received source/fixture ACK at
`recovery-helper-source-04/SOURCE-FREEZE.json`, SHA256
`196719dcb3b9cf3b04c72012d58d320693169a2d748d4a7c9f271b2266579191`.
All 20 source members matched both current files and immutable snapshots. The
shared parsed matcher permits exactly the same State112, ten domain operands
and one VK328 slot for either entire independently reviewed old/new program;
the response identifies the selected policy source hash. The new public
quote fixture SHA256 is
`c87fa3133af55c6a9556d2d213087e9c3e6433ac5e16be9848339e2d7492624d`.
Its new-domain singleton context and deliberately invalid inactive zero VK328
are labelled supplied synthetic context. It supplies no signing key, and
quote never executes G16. The prospective eleven-method packet retains all
old controls. A prospective v2 test packet then received ACK at pre-run freeze SHA256
`d5f1bdbe780c3cb58c90e188f1579f826177b713ac7da1bef12fea5992bc5f3d`.
All fifteen source/binary/public-fixture members matched selected binary
`a43d07bbff53aba74be6ac966ead53fb72670b22aa19e974e51e61f986512280`.
The external Python addendum adds a twelfth method: new-program public
DO_NOT_FUND authorized sign, requiring quoted ID, literal consent, Full and
all input engines, same v1 ID, terminal no-successor and no key in stdout/stderr.
Its signing key is explicitly public synthetic, not any live trial key. The
compiled Rust/TOML/lock source remains source04; the Python-only addendum is
separately labelled. The v2 runtime packet subsequently closed: all twelve methods passed,
including public new-program sign/Full. Result SHA256 is
`94a949a27d299f736765cfa99b082fd8130fed67d8aaa34f4a84b2e2ee0ac400`;
test log SHA256 is
`dcb90778bdfe462400c9ce568773f40a51b272132cf0ca757271e49dcb640796`;
cleanup SHA256 is
`08cf655ad9534d1033acef4cf5a20e737b7127af05c336f7c95e2f8d70c006be`.
All fifteen pre-run pins remained exact; cleanup was inactive/dead/PID0 with
no owned process. Requested unit caps were2 CPU/2 GiB/swap0; the0.098-second
run did not sample active cgroup limits. The collected unit defaults are
explicitly not an enforcement measurement, and outer-wrapper GNU RSS is not
application RSS. No test/signing/native execution was repeated by reviewer.
This ACK allows a separately versioned wallet compatibility/pin upgrade.

## New private native policy

Source ACK: `private-native-source-02/SOURCE-FREEZE.json`, SHA256
`2bdbbc348a955a025805cb1394f2df54dbc4a2bbdd54fdfce0e117e2eab0359d`.
All six members matched. Policy/native source hashes respectively are
`78a7bff9fc1038cd20cd5424e7cd7ea04bd81469692066e10f0274777d0c3ebf`
and `0a5a535b6baaa86e719d0becacf611129da7a825e3190f632baa9b0cf58f7857`.

The shared action branch binds Auth528 and SHA256's two LE128 public limbs,
actual outpoint/state/reserve, fee and public payout. Native output count,
positions, complete SPK36, immutable reserve successor and covenant metadata
are exact. Ranges keep every subtraction in signed-native range. The terminal
branch checks zero CM64, cipher528 and append witnesses1024 before skipping CM
work, carries CMroot/n, but still executes both NF insertions and m+=2. The
nonterminal branch authenticates both appends. The factory preserves malformed
authorized SPK version bytes so negative native cases exercise the policy rather
than silently canonicalizing them. No native execution result is inferred here.

## New proof relation

Core source ACK: `proof/build-02/SOURCE-FREEZE.json`, SHA256
`a23381ccef4da85daa41f5488b2628d4d82d915a3f56501a9360581f025c6e00`.
All 11 members matched. Library/circuit hashes respectively are
`3b2966f1572159823f65e223eb009843055c48fd7f0272f56d9efad0c77a8b0e`
and `ef8f4fca15bd0f363d50f734d6d751360455b5a52fe35ea6486f01259fa90b64`.

The relation uses constrained Boolean mode predicates, with fixed allocations
and no host terminal/P0/P>0 branch in constraint generation. Integer-slack bounds
and byte widths prevent field-wrap conservation. Hidden s+k ownership, original
positioned real/dummy HMAC NFs, distinct real positions and current CM membership
remain enforced. Public payout and exact SPK are Auth-bound. Payout PK differs
from each real input's emergency key; this proves that inequality only, not
global freshness or key control. Terminal output Note168 witnesses including rho
are zero, public CMs/cipher hash and CMroot/n are constrained, and both NFs remain
mandatory. Actual ciphertext and append-witness zero bytes remain native checks.

The complete-CS runner explicitly bypasses host public-validation rejection.
Fixtures distinguish valid alternative owner statements from proof replay or
native current-NF rejection. Root authorized the first frozen positive sizing
under this source ACK. Before the full negative batch, the reviewer requested a
minimum60M input/payout boundary and an otherwise coherent subfloor input fixture
with recomputed CM/path/NF. Build03 subsequently adds those coherent boundary fixtures and repairs the
out-of-range input membership as well. Its source freeze SHA256 is
`729f3ff60467b605fc446b0821a4ba3593ff30ecd1add378bf893d4b60601dec`;
all eleven pins matched. Matrix-construction lib/circuit/SHA sources remain
byte-identical to build02. The fixture-only changes add minimum60M terminal
SAT and input59,999,999 UNSAT with recomputed CM/path/original NF/R/P and
otherwise coherent terminal conservation. The out-of-range input necessarily
violates several related input/sum/reserve caps, so its result is not evidence
that one isolated range gate fired. The frozen-JSON negative runner calls the
complete constraint checker after parsing; parser/host failure is not UNSAT.
The build03 cheap parser/wire controls passed without synthesis, key or proof.
The first complete relation subsequently closed read-only: report SHA256
`86cb24bb5ed6ce8bc8d8fab2a67f1c3257e73aa56273716963d73cfb80feb62c`
matched result `92514487439828d7afa09910f2b8b8b5abb284fc0e731a68f1637aff12d4e553`.
It is SAT, with3,231,025 constraints,3,195,131 witness variables and3 instances.
The fixture roundtrip matched; cgroup peak was906,129,408 bytes, swap0, and
cleanup was inactive/dead/MainPID0. GNU time measured the outer wrapper in
this first run, so that wrapper RSS is not application RSS.

The prospective batch also received exact serialized fixture/runtime ACK:
49-fixture manifest SHA256
`84ee24ed51c34fb912a6057cb2b3906b473c3cc7f047f91af489606322f64791`,
48-case plan SHA256
`7f3892cf02375aef764e2103e20faf817d0e87cee69a7414783f999c307d0152`.
All49 fixture hashes and all48 runtime-freeze hashes/members matched the
selected build03 binary586c2c5e7704848a7eb8424927d541e213a34992e9de5a1116ece283522c999e.
Each case uses1 CPU/2 GiB/swap0/networkoff, direct complete-CS checking, and
the successful first spend is excluded from rerun. The inner application
GNU-time measurement is present in new case wrappers. The complete batch then closed read-only at aggregate result SHA256
`68101ae1f241a57a5a53f74bf207e97b1175643011cb2b75a94b6e8ff41a6721`.
All forty-eight report hashes, serialized fixture hashes, exact frozen fixture
roundtrips, selected core identities and cleanup records matched. Together
with the first spend counted once, outcomes are8 SAT and41 UNSAT. Every
case has the same3,231,025 constraints/3,195,131 witness/3 instances. All
new cases have inner application GNU-time exit0; sampled cgroup peak across
the batch is906,625,024 bytes with swap0, and all cleanup states are inactive
with PID0. This establishes bounded relation controls, not matrix identity
or proof/native/privacy correctness.

Same counts alone do not establish identical matrices. The fixed-allocation
source review must be followed by shared-VK genuine proofs across ordinary,
partial/change, owned-full continuing and terminal modes, or an explicit matrix
identity check. Actual native/control fixture ACKs and result closure follow
their separate freezes. No setup, proof, privacy or native success is claimed by
this source document.

## Finite lifecycle source pass

The assembler and separate execution closure preserve a four-billion-sompi
public synthetic source, actual funding/admit/private predecessor links, four
private modes under one selected VK, exact native fee/body substitution,
private change and other-owner liability, and terminal no-CM-append semantics.
The executor checks each actual native Full/all-input-engine result, payout
SPK/value/output count, no terminal successor file, recognized positive tails
and actual external source change + founding change + three payouts + all
seven fees = source. It attributes shared prefix/payment fees once and Bob
and Charlie exit costs separately. No native VM/setup/proof was executed by
the reviewer.

The initial executor could trust a substituted unpinned prefix summary while
reporting seven Full operations. The corrected executor SHA256
`3c33a9f8ac1016cf1cb5281b1c6943ecd96e871d52c7cb8455f7344a5098ff63`
received source ACK: the final action freeze now requires the successful
three-operation prefix result and actual body/context/validation artifacts;
the executor rechecks their links, actual fees, Full flags and each input
engine. It also requires the selected fresh setup report and five reviewed
proof-source files and compares each proof report whole source identity to
that setup. Prepared unsigned body/context/metrics/raw-ID files referenced for exact
proof-only substitution are mandatory frozen under the selected materialization.
Declared action P/R'/fees and all prefix fees are compared to actual Auth,
Full and context evidence. The assembler with rejected-only race preparation
is SHA256
`b69e03450dbb063c33486e26ffebd412fabed7d42e242ca6e9d2d575db498c49`.
All continuing and race dummy ciphertexts now use the actual sealed-box
format over random216 plaintext to one-shot delivery keys, rather than raw
random264 bytes with a distinguishable ephemeral-key format. The one-shot
seed is not retained in artifacts; secure memory erasure is not claimed.
P0 shape has two real outputs, so its setup fixture remains unchanged.
Terminal cipher528 is still canonical zero. The pre-fix source/zero-runtime
record remains retained.

The public freeze helper received source ACK at SHA256
`fc35478145d28b5c3050450e6f738c2978d758d5566b04e250e9f888c0e642af`.
The first helper resolved explicit inputs before checking symlinks, losing
the symlink identity. The corrected helper checks every original input path
and component and excluded key suffix before resolving. Its execution flag
is a local root execution record, not a cryptographic approval mechanism. Materialized source/statements, actual
proof and native execution packet ACKs are recorded below.

Separate competing-spend preparation source was reviewed: a fresh genuine
current-state private proof after valid Bob REVEAL retains authentic current
CM membership/outpoint/R and original occupied NF. Its public update witness
authenticates the equal occupied current NF leaf, so strict predecessor<NF
must reject natively even though the private ownership relation is satisfied.
The reverse signed REVEAL uses current after-private paths. Deliberately bad
successor roots are labelled rejected-only and never accepted as a positive
ledger. These branch alternatives must not be concatenated into mainline
payout accounting. The separate race runner source received ACK at SHA256
`8b781aac481a007f89a16e0a15f116c46cdd405949aadff1216496235e4f8ac5`.
It requires the frozen mainline/prefix/setup/proof sources plus current
control bodies and a fifth genuine proof, binds actual predecessor links
and exact proof-only substitution, requires native Full/engine VerifyError
with private rejection below the G16 tariff, and retains failed predictions.
Actual genuine proof/native outcomes are recorded below.

## Actual setup and five-statement packet

The sole resident-session prospective runtime received ACK: plan SHA256
`8b82a18d3626f3680caaf6a2bf33d2c33ac94341baee8c68d163f13b07ecd53f`,
runtime freeze SHA256
`a1baefbc8ba77db667387feed728eb38c0b2df9e20f6dcaf150736d0151764db`.
All fifteen source/binary/shape/plan pins matched, with a fresh stage absent at
review. It uses one fresh OsRng setup under14 CPU/18 GiB/swap0, no network or
old-key/matrix mount/load API. Submission bytes are copied/fsynced once and
reports must match those exact bytes, reviewed sources, query dimensions and
one shared fresh VK. Whole-process setup/proof/idle resources and non-independent
phase peaks are labelled separately from p95 qualification.

The public setup report SHA256 is
`eecd7f7210545b2790d23d597036cb526828a2f4fb8fc3e6428d275c2582dde7`.
The exact328-byte public VK SHA256 is
`5efe60cc6dc2079bd33cae4dd1b241b260afded57bb5beb7fe204e8a90456ba8`;
its bytes equal the report and reviewed source/query/shape identities match.
Setup13.3157s and setup+serialization14.8786s are producer measurements. The
reviewer did not open, read or hash the PK; its public size/hash are producer
metadata. Actual proof and final session resource/cleanup closure are recorded below.

Actual public lifecycle packet received ACK at SHA256
`938accdfe18506e572a7bfd72f9b2b8091f56bef1673ee2fef0e54c8dc32909e`.
All322 public file pins matched. Exact five fixture hashes are:

- P0 spend: `fa7c2260d0519f32ec91796c4a06c1bf3e86d32514b56c207eb92eb4b38487ad`.
- Bob partial: `ae4464e5a5759fced7801877c792117a8ecec301ff5c170aef4430bbbfc40c6a`.
- Bob full continuing: `464e6d9670e9d55b596599c34066e99716dc9a2bde5261765b1f688a08a62052`.
- Charlie terminal: `b5c9acd80ac0312b5abdd52cf57aa2655399685f4f2976691589dfb21efcddd3`.
- Current occupied-NF race: `0c27c49278b30cec2c3620a4d7254e4324a43429f6658d4936edfaefed3761fb`.

The reviewer independently recomputed cheap public SHA owner/K/CM hashes,
positioned real and dummy HMAC NFs, current CM paths, both sequential NF
predecessor and append paths, private output append roots, bounded integer
conservation, terminal all-zero/carry semantics, exact unsigned native body
frames/SPKs/fees and ten actual predecessor links. The race has exactly the
intended authentic equal occupied current NF predecessor; the private ownership
statement otherwise remains coherent. No extra full-CS preflight was requested:
each unique actual statement is to receive one checked genuine proof under
the resident key. Prefix3 Full was prospectively released; proof-bearing main
and race execution received separate exact proof artifact freezes, below.

The actual seven-body accounting is1,914,873,700 source change +57,425,400
founding change +1,943,042,600 total main payouts +84,658,300 fees =4 billion
sompi. Final n8/m9 and Charlie's1-billion-sompi reserve are preserved through
Bob full exit; Charlie terminal drains it to zero without CM append. These
are freeze-only body/accounting facts, not native acceptance or testnet payouts.

## Final native/proof/race artifact closure

The final resident session closes at result SHA256
`1f4aeaf735060b57c1b9f2674a6639954dc04dcfe65a77ff2e19c59757db8188`.
All five exact submitted fixtures have checked genuine proofs under the same
VK and source identity:8.2927,7.9892,8.2000,8.1290 and8.0899 seconds. The
reviewer checked report/proof/Auth/VK/submission hashes without re-executing
verification or reading the PK. This adds shared-VK cross-mode compatibility
evidence beyond count equality, without claiming a raw matrix digest. Inner
GNU-time resource hash is
`ad775823a40682fc966c49dfbc47964273516417bc075ab63e2cfefc602e929f`:
4,148,144 KiB maxRSS,444.26 CPU seconds and6:13.20 wall including idle.
Telemetry hash is
`55b107d593c783624af4b7777bf31aad6b2b1d3309392f39ce30f3ba3041daae`,
735 samples,5,595,713,536-byte cgroup peak and swap0. Cleanup
`54ec3bde3a447f1b4efc6591ef4a298dfd30dedd3ace16b670050c17e06cf73f`
is inactive/dead/PID0, exit0/error null. These are not wallet/p95 qualification.

Genuine-input packet SHA256
`0704bab738403436bda874cf1052ce2ddda88247df5d822a3abddcb471458767`
has377 exact public members. Prefix result
`cff69ae498fd370a541761e323d2a2c9b3ad5a199f669b4e0f50c7a31704cb74`
closes three native Full operations, four accepted input engines, actual links
and fees. Mainline result
`e288a32d10428415742a5c44a408bfb3f2368bd42fa86de63b6d1763ee2ce6c9`
closes seven native Full operations including four genuine private proofs.
The reviewer byte-compared every actual private body to its prepared body
with only the exact proof128 inserted, checked Full/engine fees and the
terminal one-payout/no-successor form, and reconciled seven links,4B external
source,84,658,300 fees and zero recognized positive liabilities/reserve.
Bob's attributed native costs are51,850,250 sompi and Charlie's32,808,050;
Bob's additional partial exit is charged once. This route remains uneconomic
under the unchanged target and is supplied-context, not accepted testnet state.

Race packet SHA256
`5012f0ece74dcb6040a2c709b176fa12a9170c2c3d91b82d172111cc01fbd953`
has418 exact public members. Result
`f40ce9ebfcfc88399ff9aa939930c5630e5e0fd1dc472e033cf63633f98b067a`
closes the separately accounted alternatives: valid REVEAL accepts; signed
old REVEAL after current private partial rejects Full SignatureInvalid(VerifyError)
and engine VerifyError at62,365 units; the fifth genuinely verified current-state
private proof after valid REVEAL rejects the same at171,845 units. Both are
below the14,750,000-unit G16 tariff. The reviewer checked three actual links
and exact proof-only substitution; neither fork payout is counted as mainline.

Ordinary native control source02 freeze is
`f3127920a512a6cbaa8e305bcdc6a3779f2519cb1af3544f1d80056c010ea823`.
The initial80-case runtime packet was prospectively ACKed, then deliberately
not executed: four positive bodies already had accepted native results. The
replacement76-negative pre-run freeze is
`092cfa8a07a49738dfbac15efb6df7d51fbe5ee4bae8c9ae7e4bee06b19e6688`,
with285 exact public members. Baseline reuse SHA256
`54b9cf6c2029c5b8879a27182ed5d1008170b7cd97ce995f54bf473c903e1ba2`
received independent byte comparison of all four validation-case/transaction/
context triples against accepted mainline bodies. No positive native rerun.

Final controls result SHA256 is
`381818c9fd7ffefeb3b19a9704662a8d5ab2c335a01e5736c7f2ccb68818f3a6`;
raw case result is
`ffba4607706f1a8b767150b41dd4cbee9894ac1f9de1532f2c5ee8e846eab247`.
All76 predictions match:68 early VerifyError; seven exact Full/engine G16
integrity errors for destination/P/fee/outpoint/ciphertext and both unsigned
negative-zero amount mutations; one separate zero128 ARK serialization error.
Every raw per-case report matches its aggregate row. All linked artifact pins,
active2 CPU/2 GiB/swap0 sample and cleanup were checked. Inner resources
`e09bb3503a20aa684f0ac1468f7d739474e69d839f964850d97f03b64c1696d9`
records0.42s/exit0. Cleanup
`b3940ac87f374864b132180f3b398ec2877a93d330bae1d1a406bb56fca3eb6d`
is inactive/PID0 with no captured process/cgroup remaining.

## Root documentation consistency pass

I-2/ADR-0050 conserve private outputs, authorized native payouts and explicit
fees under the same backing/authorization requirements. The selected-body
three-action floor56,916,200 sompi at100,2.84581% per10-KAS recipient before
ingress, is consistent with the fixed body masses. The seven-operation
84,658,300 example includes one extra private partial payout. Privacy, node,
DA, setup honesty, current lineage, receiver delivery and p95 limits remain
material. Header-parent/hash and public-VK validator statements were checked
with the separate recovery adversary against its frozen sources/artifacts.

The final root documentation clarifications were read and ACKed. RFC-0022
names every real consumed note's emergency native signing key, while global
freshness/control/curve validity remain wallet duties. RFC-0022, ADR-0049 and
ARCHITECTURE explicitly state that network fetch/replay/template currently
supports old Auth484/KPX2. Helper v2 recognition of the new policy does not
supply Auth528/terminal-skip replay. ARCHITECTURE separately identifies the
new unfunded supplied-context program and older confirmed TN10 program.
Separate old-network recovery and new private cashout success are not a
complete combined new-program recovery lifecycle. No material overclaim or
missing trust assumption remains in the reviewed root additions.

The setup-session freeze pins the earlier4359-byte ADR-0050 identity
`59e09426409c1bcc3d06aaa9fcf102433ae55b77900e4d8345eef2be7584f94b`.
Root restored the exact original ADR bytes/hash by removing the later
measured-cost paragraph. The reviewer rehashed current ADR-0050 at4359 bytes
and that exact frozen identity. Actual measured costs remain in results
documents. The original runtime freeze is unchanged; no extra snapshot is
needed after the exact restoration.

## Explicit invariant clarification

The reviewer found that the literal I-2 transfer identity omitted public native
payouts from the new private action. The exact SECURITY-INVARIANTS.md and
ADR-0050 redline now explicitly records
`sum(private inputs)=sum(private outputs)+authorized native payouts+allowed fees`.
It requires nonnegative bounded payouts bound to actual native amount and
destination, keeps payout principal separate from fees, preserves P0 and
requires reserve decrease P+f with all remaining liabilities backed. This
conserved-output extension received independent ACK; I-1 backing and I-7
withdrawal authorization remain unchanged. It does not authorize extra value
or change an existing funded proof/policy.

## Retained assumptions

Accepted coherent initialization and exact R=L history are external premises;
a supplied root/UTXO is not their proof. Correct receiver encryption is outside
the circuit. Public payout values, timing, priors, drainage and later fallback
disclosures remain privacy inputs. The direct verifier floor still excludes
the 10-KAS two-recipient plus two private-exit route from the unchanged2% fee
target before other costs. New development setup honesty, reference-wallet p95,
independent consensus and durable public data remain unqualified.
