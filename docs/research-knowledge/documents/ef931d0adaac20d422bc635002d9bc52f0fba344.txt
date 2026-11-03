# Independent private integration gates

**Current result:** the new finite supplied-context native lifecycle passes:
six actual Full operations, six physical previous-output links, one genuine
private proof, both recipient seed restores and zero terminal reserve/liability.
Independent exact-relation/native-body evaluation 02 and read-only report/value
closure are recorded in the [independent report](independent-oracle/REPORT.md).
All 63 native controls give the intended accept/reject outcomes; the original
typed score is 60/63 because three predicted error names were wrong. A separate
three-case genuine competing-spend run matches 3/3 typed outcomes, and a third
independent conformance evaluation closes its accepted one-real/dummy body.
No accepted-chain, testnet, privacy, production or R8 qualification is claimed.

**Original design status:** independent design ACK of bounded core sections1–5 of
[`NOTE-STATE-CONTRACT.md`](NOTE-STATE-CONTRACT.md), reviewed SHA256
`7f061067c16a54b4bba399ac9f93053fec2a36f39074f1112b8b6ec1c46a28b5`.
No circuit/key/setup/implementation or admission extension approved by this
note. Baseline `0c2f4c788a4274b381c4838e05cce5e9c32e8536`.
Research only; no funding, broadcast, old owner workflow or new native run.

The deliverable is a recipient-spendable private payment that can subsequently
be consumed privately **or** by a self-funded revealing exit, with the same
atomic exclusion and complete backing. The earlier public checker establishes
neither a recipient's private authority nor the private relation.

## Invariants and source basis

The unchanged [security invariants](../../../SECURITY-INVARIANTS.md) and
[RFC-0012](../../../docs/rfc/0012-useful-privacy-requirements.md) govern this
review. In particular I-14/R2 allow deterministic receipt rejection before
crediting; decryption alone does not establish spendability. I-1 counts every
remaining positive liability, even an undiscovered or unusable output. R6 keeps
later fallback disclosure in the ordinary target's observation horizon.

Pinned existing-work comparisons are the
[requirements source review](../../shielded-kas-privacy-requirements-2026-10-20.md),
[candidate source/options review](../exit-fee/PRIMARY-SOURCE-OPTIONS.md),
[future-format obligations](../exit-fee/ARCHITECTURE-OPTIONS.md), and
[exact-backing review](../exit-fee/BACKING-AND-TAILS.md). Their source identities
are not claims about current deployment. This independent review does not
replace the current upstream refresh.

Reuse: Orchard's separate recipient/value/nullifier obligations; Aztec's
distinction between delivered/decryptable/spendable notes and authenticated
available history; RAILGUN's historical-membership versus current-nullifier
checks; Monero/MWEB's separation of one-sided receipt and privacy objectives;
Kaspa's exact native successor/value enforcement. No new primitive, privileged
recovery path or invariant change is proposed here.

## Design ACK and implementation gates

The exact Invoice176, receipt216, ciphertext264, State112, Auth484 and
PRIVATE4356 layouts are arithmetically consistent. The core selects raw CM
leaves, current-root membership, exact shared positioned HMAC NF, two private
insertions and one revealing insertion, with full256-bit transcript hash split
into two little-endian 128-bit Fr inputs. The sentinel-inclusive capacity
argument below is consistent with those actions. The recipient policy now
retains owner action after unsolicited descriptor reuse. No blocking core
design issue was found. This ACK authorizes implementation against the reviewed
bounded contract, not a production format or a claim that the following gates
have passed in code. Genuine circuit/source/key/setup and native evidence remain
separate gates. Admission is explicitly an unfrozen extension.

| Gate | Required contract and frozen controls | Why it is load-bearing |
| --- | --- | --- |
| G1 Recipient backup authority | Specify exact descriptor, index widths, domain/version tags, independent secret derivations and canonical key validation. A backup predating receipt must derive both k and the committed native signing key from recoverable descriptor data. Reject unknown derivation/profile pairs, wrong index/domain and sender-selected K/PK before credit. | An output that decrypts and matches CM can still be unusable or sender-observable. |
| G2 Public output construction | The sender/private output proof receives public O/K/native PK and cannot be said to know recipient-hidden k. Its actual private constraints must commit to those exact public descriptor fields. Recipient separately rederives/checks them. | Requiring k for output creation makes one-sided payment unavailable; letting the sender choose k exposes spending metadata. |
| G3 Two independent authorities | A real private input proves both undisclosed s ownership and the CM-bound k relation. Reveal discloses k/opening but requires SIG_HASH_ALL from the same CM-bound native key. Test k-only, s-only, wrong s+k combinations, valid signature under wrong key and copied-published-k after rollback. | Same-NF first-wins alone prevents inflation while still permitting theft in a one-credential design. |
| G4 One original NF | Freeze byte-identical domain/CM/position/HMAC encodings for private and reveal branches. Require shared current NF insertion. Test private→reveal and reveal→private with intact membership; each second spend must reject at current spentness. | A detached emergency marker or anchor-relative identity can pay twice. |
| G5 Descriptor reuse and multiplicity | Define whether reuse is accepted and what privacy is lost. Scan accepted history rather than only the unspent set for duplicate descriptors. Preserve distinct positions even when CM bytes repeat. Test same descriptor with two rhos, exact repeated CM at two positions, duplicates in one batch and out-of-order receipt processing. Accept a first payment, let its sender create a later duplicate, and require the first owned claim to remain actionable without that sender. | Revealing reused k exposes sibling NFs; collapsing equal CMs can omit liabilities. A label saying one-time does not enforce uniqueness. Retroactively disabling all claims on reuse gives a sender a wallet-level freeze capability. |
| G6 Monotone knowledge | Reorgs restore only chain state. Preserve prior published openings/k and observed descriptor poisoning. A restored backup plus accepted-chain-only data cannot recover orphan-only disclosures; state that missing-history limitation rather than claiming it vanishes. | Orphaning or rejecting a reveal does not make its credential secret again. |
| G7 NF arity and capacity | State whether NF count includes the sentinel. Define real/dummy insertions for each action and joint CM/NF/history capacities; prove every accepted supported note retains an exit slot. Freeze near-full mixed private/reveal traces and high-bit little-endian NF ordering. | Old v6 adds two NFs per private consumption while candidate C adds one. Its m≤n rule cannot silently survive that union. |
| G8 Exact backing and admission | Authentic initialization and every branch preserve the complete backing equation. Bind actual funding inputs, funding change, deposit/fees, both outputs and immutable policy/VK/profile. No accepted operation imports a root without its required lineage. | A supplied UTXO, proof pass or positive reserve number is not accepted backing. |
| G9 Complete value and fees | Integer sompi only; exact range and no field wrap. For whole-note reveal V=P+f, R′=R−V. Private sum(inputs)+deposit=sum(outputs)+payout+explicit fees. Test 0, floor−1, floor, MAX, MAX+1, overflow, fee/payout substitutions and actual storage/mass fixed points. | Lower fees cannot be obtained by leaving another user's principal or a hidden refund unaccounted. |
| G10 Terminal liabilities | Removing the reserve requires complete zero remaining liability, including pending claims/refundable credits if any. Conditional R=V proof is valid only under prior complete backing and valid unspent ownership. Keep small-tail failures and unsupported contexts separately labeled. | “Last note found by this wallet” is not “last global liability.” |
| G11 Independent availability | Freeze exact public history/ciphertext/parameter/current-witness inputs and what the backup contains. Stop preferred services before authorization; retain independent reconstructible data. Corrupt/withhold data controls must fail explicitly without credited balance or invented witness. | A committed root supplies integrity, not historical data or note discovery. |
| G12 State and policy isolation | Bind domain, version, exact policy/VK, canonical current reserve outpoint and accepted historical anchor. Freeze wrong domain/version/policy, wrong current outpoint, stale NF root and wrong historical count with otherwise valid witnesses. | A current signature or valid proof alone cannot identify the intended state or pool. |

Passing a local reference predicate does not close G2/G3/G4: genuine constraint
and native branch evidence is required. Passing native validation does not close
accepted lineage, privacy, recovery or affordability. Actual source-checked
implementation coverage will be recorded only after the reviewed contract exists.

### Blocking receipt-policy finding before freeze

The initial receipt-lane proposal would quarantine **all** claims for an invoice
index after any accepted reuse. That policy is not sufficient unless quarantine
is only a privacy classification and explicitly retains owner-controlled
spending/exit. A previous sender knows the public descriptor and can create a
later funded duplicate without the recipient's consent. Reuse does not disclose
s or the native signing key, so both claims can remain cryptographically owned.
Automatically disabling the earlier claim creates an unnecessary availability
failure. Rejecting a new duplicate from ordinary automatic credit, flagging
privacy contamination, preserving every distinct liability position and keeping
the owner's recovery/exit path are separate actions. Freeze the first-credit →
adversarial-duplicate → first-claim-actionable regression control. This is a
contract/policy finding, not a runtime exploit or an upstream vulnerability.

### Proposed NF-capacity invariant: independent arithmetic review

The designer proposes CM depth16, NF depth17, at most65,535 CM slots, fixed two
private NF insertions and one reveal insertion. Let n include every appended CM
slot, m include the NF sentinel, C count every positive note ever created, and U
count every globally unspent positive note. C and U are mathematical ghost
counts, not assumed public metadata. Quarantined, undiscovered and lost-key
notes remain in these counts until valid consumption. The sufficient invariant
is:

```text
m − 1 <= 2(C − U)
C <= n <= 65,535
therefore m + 2U <= 2C + 1 <= 2n + 1 <= 131,071.
```

Initialization C=U=1,m=1 satisfies it. Admission creates c positive notes, so
C and U both increase by c and m stays unchanged. A private action consumes
r∈{1,2} real notes, creates c∈{0,1,2} positive notes and inserts exactly two NFs:
the left side increases by2, while2(C−U) increases by2r≥2. A reveal consumes one
real note and inserts one NF, so the increases are1 and2 respectively. Thus
these exact actions preserve the invariant. If U≥1, m+2≤131,071, leaving room
for both a private two-insertion action and a one-insertion reveal. The last
two-insertion action can append at indices131,069 and131,070; both fit17bits.

This is a source/design induction, not a VM result. The weaker public check
`m<=2n+1` alone is insufficient: the stronger premise comes from authentic
initialization, the genuine private constraints and every allowed transition.
An unchecked imported root or a mode that adds two padding NFs while consuming
zero real notes breaks the proof. The exact contract must exclude those modes
or supply a new argument. Historical-CM capacity and future CM admission are
separate limits; rejecting new admission at capacity must not block an existing
note's CM-free reveal/terminal consumption. These statements do not change the
previous candidate-C vectors (which used a different count profile).

### Public admission changes the chain observer's inputs

The native lane's prospective admission branch avoids a fresh SNARK by
publishing O/incoming/K/native_PK/rho/V and checking the resulting CM directly.
If selected, incoming is no longer available only through invoice records or
later reveals: C observes it at admission and can compare it with every later
revealing opening. A stable incoming key links those records and their funding
ancestry without a directory. A directory or participant disclosure can further
map that key to a named role. This does not expose the private transfer
ciphertext's incoming key before opening, but it strengthens disclosure when a
private recipient later reveals under the same domain-level delivery key. The
privacy contract must include every adopted admission field in C, retain the
later observation horizon and count any resulting supported-target failure.
Reducing admission fees does not qualify that leakage tradeoff. This finding
is conditional on the prospective public-admission format, not a newly executed
native or privacy result.

The subsequently reviewed receive-V2 separation addresses this exact equality
channel: new Invoice208 magic `KPX2IN01` appends a stable deliveryPK, while
Note168's incoming becomes the separately tagged per-index HMAC output
`INCOMING`. Sender encryption uses deliveryPK; Note168/Receipt216/Auth484 and
native public openings exclude it. Recipient decrypts with the stable secret,
then derives/checks the indexed note fields. Source review found this narrow
diff consistent with unchanged circuit/native layouts. Invoice holders still
link deliveryPK, reused indices still expose sibling NFs, and orphan disclosure
remains monotone. Retained V1 source/results remain separate; field inequality
is not a hiding proof.

## Implementation review in progress

The recipient reference was read independently before execution. Descriptor
rederivation, current NF checks, duplicate-position preservation and the
predecessor/intermediate-append construction follow the reviewed contract.
Requested corrections before source freeze:

1. `exit_witness` must check the receiver against the expected domain itself,
   validate the claimed position before archive indexing and reject NF zero.
   A caller of that function must not need an earlier `recover` call to obtain
   those guards.
2. A generated reveal successor must satisfy m+1≤2n+1, in addition to the raw
   depth17 capacity. A count-valid supplied context is not a proof of the
   stronger ghost invariant; knowingly invalid next counts cannot be returned
   as a valid current witness. Keep the counter-only source-boundary fixture
   distinct from a valid-lineage recovery claim.

The privacy scorer was also read before execution. Its separated public-wire,
invoice-directory and test-truth boundaries, exact CM/NF recomputation and
nonqualification labels are appropriate. Requested that it enforce the actual
note/payout/fee ranges before a conformance PASS and avoid claiming k/K
consistency for arbitrary random sibling-CM labels. A relation-consistent
synthetic sibling opening or an explicitly algebra-only label is sufficient;
neither is an accepted private/native transaction. No runtime result is claimed
by these source reviews.

The privacy V2 closed result was independently rehashed without scoring again:
all9 source pins and3 input pins match; manifest SHA256
`d08516d0bd446c29d63047b2b2123c24d5d280a1e7e585465af90fd8739ad77f`,
result SHA256
`ca288df89d4c3fcfdfd761ec3cd121bfc4735dabc01df578007cf72decf6648b`.
Public revealed O/incoming/K/PK equality classes are empty in this fixture;
directory deliveryPK class[0,2], two matched disclosed-key canary records and
retained orphan knowledge remain explicit. Actual private/native/ADMIT gates
are incomplete in that diagnostic, and the old amount-workload failure remains.

All requested recipient witness corrections were inspected in source before
its run: expected-domain/position/NF-zero and successor-count guards now exist,
with isolated controls. Receive-V2 was separately reviewed before its freeze:
exact new invoice magic/208-byte layout, opaque indexed incoming, encryption
to stable deliveryPK, receipt rederivation, strict profile/old-version rejection
and retained owner authority all match the selected separation.

After the recipient runs, all9 V1 and8 V2 manifest members were independently
rehashed against their actual files. Machine results report25 and27 methods,
respectively, passed=true and zero errors/failures. The known-answer records
were independently recomputed with stdlib HMAC/SHA: seed role/index derivation
for s/k/delivery/native candidate0, O/K, receipt Note168 CM and positioned NF;
V2's separate indexed INCOMING derivation also matches. No recipient suite,
crypto bridge or native runtime was rerun by this reviewer. An initial review
assertion misread the boolean tests_passed as a numeric count; only that reader
was corrected, and every producer artifact stayed unchanged.

The initial pure private-circuit source was read in full. Raw-CM membership
folds to Auth484's prior CM root at116..148; real input constraints require
both s and k; HMAC and dummy slot domains are exact; all fields/sums/counts have
bounded integer/slack relations; public hash limbs retain both128-bit halves.
Current NF/CM updates remain a mandatory native seam. No blocking constraint
omission was found in that source pass. At that stage genuine relation and
native-context controls remained required. The later 17-case full-R1CS result
and three genuine proofs are distinct evidence, as recorded below; source
inspection and finite controls are not cryptographic correctness proof.

The completed library packet's 42 members were independently rehashed. The
prospective plan and source-build-03 freeze match result SHA256
`0fd8a9c401319ac2440d23fa326ea97fda99fd896ea5dc3a8a53c7de90f9a00b`.
All 17 controls complete synthesis with 4,650,533 constraints and satisfied=false:
wrong s/k, copied k without s, all-dummy/canonical-padding errors, membership,
position/NF/output substitutions, domain, floor/range, fee/reserve and capacity.
Operational failures are excluded from that success criterion. No setup/proof,
native spentness, accepted backing or privacy qualification belongs to that
suite, and no suite was rerun by this reviewer.

The initial native union source pass requested exact successor bounds m'≤2n+1
and≤131071, actual R≤MAX, and continuing reserve≥60M. Valid lineage implies
these for honest states, but a supplied-context checker must not return a
known-invalid profile successor. These checks do not change the frozen old
candidate-C experiment or erase its small-tail failures.
The corrected core emitter was inspected: each requested bound is present.
The separately implemented admission emitter was then read in full; offsets,
funding/signature framing, amount equations, NF preservation, shared CM append,
immutable successor, optional change and G coherence follow the reviewed
contract. Official Full and per-input engines must still validate the real
funding signature; the pool input's framing checks do not replace that verdict.

The separate [native admission contract](NATIVE-ADMISSION-CONTRACT.md), reviewed
SHA256 `bc5e20282b5ee15c80ed7da2e85e4b4cc1c3200ae46566c67351125e1647e2a6`,
received independent bounded design ACK. The1344-byte layout, external-owner
fee/change conservation, input1's actual ALL validation, same immutable
successor, V2 stable-key exclusion and first-spend singleton G coherence are
consistent. Canonical founding/current lineage remain an explicit external
oracle. This design ACK does not qualify any native code or accepted backing.

The fee lane corrected old branch-prefix assumptions prospectively while
retaining arithmetic01. For high-L shapes, the hand-checked no-change pilot
has admission bytes L+1864, private bytes L+4756, and continuing reveal bytes
L+2481. At rate100, one payer funding two distinct10-KAS recipient payments
legitimately allocates half admission/private costs to each. With private budget
B and admission/reveal budgets200, the per-payment necessary fee expression is
`350L+938900+5000B`, valid in its declared high-L mass region. B=1600 gives
`350L+8938900`:24KiB yields17,540,500;32KiB yields20,407,700 and fails20M.
This is conditional on unimplemented source/size/budget/funding shapes and
omits unpriced service/retry/initialization costs. Recipient-plus-change is
still one useful payment; it cannot use this two-recipient allocation.

The subsequent complete isolated pilot source also closes its founding note:
G0=60M plus ADMIT(2B+private_fee−60M) are BOTH private inputs, creating exactly
two 1B recipient notes with no payer note left. Ordinary founding/preparation
change is retained outside reserve. The source-total minus all returned native
value equals every actual modeled fee, and both recipient cashout orders close
all liabilities. These remain conditional shape calculations, not actual
transaction validation or all-in qualification. The arithmetic03 r=60M rows
are exact declared contexts; a continuous monotonicity argument does not make
differences of integer floors globally monotone. A separate rational upper
bound is needed for any all-remainder affordability claim.

The new lifecycle assembler was reviewed before actual execution. It now uses
actual preceding native outpoints/amounts/SPKs, a genuine proof bound to the
materialized Auth, fresh recipient objects from pre-payment backup files and
the complete declared public snapshot, then a continuing and terminal reveal.
Both original Alice notes and both recipient notes remain in historical CM
positions; current NFs determine all four spent flags. Requested exact backup
profile checks and integer per-recipient fee shares, adding each owner's own
actual reveal fee rather than hiding differences in a float average. Accepted
canonical genesis/current head and complete archive remain explicit oracles.

## Independent oracle prepared before artifact evaluation

Root authorized the compact
[`verify-private-auth.py`](verify-private-auth.py), source SHA256
`2998655a8243f61da61f9de6cf6442d2069addf4ca6d67c9e97cb48c6cb0cf18`.
It imports no candidate implementation, verifies exact Auth484/rawCM/O/K/NF/
value/cipher/public-limb relations and every3344 public-update witness byte,
and enforces a 1 GiB address-space cap with one stdlib thread. The
[prospective oracle contract](INDEPENDENT-ORACLE-CONTRACT.md) requires source
and actual artifact freeze before evaluation. The
[three separately frozen evaluations](independent-oracle/REPORT.md)
pass exact relation/public updates and actual native-body/context/P2SH
binding. Evaluation 01's zero proof is explicitly PLACEHOLDER_NOT_VERIFIED;
evaluation 02 reads the actual nonzero proof-bearing transaction without
implementing a Groth16 verifier; evaluation 03 adds the recipient's accepted
one-real/canonical-dummy alternative. Recipient read-only rehash/known-answer
inspection is separate. No duplicated financial graph or native run is used.
Actual native JSON body/context are also pinned and parsed, with standard
BLAKE2b-256 input/successor P2SH checks. A pre-proof zero-proof body is explicitly
PLACEHOLDER_NOT_VERIFIED and earns no native acceptance claim. V1 BLAKE3
transaction IDs are not independently rehashed by this stdlib-only oracle.

## Actual primary closure and frozen negative controls

All six primary Full reports and every input engine were read directly, along
with the actual earlier output used at each of six dependency edges. Seven
consumed outpoints are distinct. Exact input/output sums, Full fees and metrics
agree: one 4B external source minus 3,962,975,200 returned equals 37,024,800 fees.
Both Alice inputs are spent into two 1B recipient notes with no payer note left;
both seed-restored recipients reveal independently, leaving all four positioned
NFs in the final set and zero reserve/liability. The maximum individual fee
burden is 18,517,700 per actual 10-KAS payment in this favorable two-useful-recipient
context. The private proof process used 5.41 GiB including cold loading, exceeding
the 4 GiB target; no R8 or general affordability qualification follows.

The 63-case native fixture freeze SHA256
`aea1f6eae052ac98ed690f7fb700130a6bc48e6655030add46286b6979e0c526`
was independently rehashed: 559 members plus selected ELF match, and policy.rs/
native.rs remain byte-identical to source-final-04. Seven positives and 56 typed
negatives are frozen. The runner requires exact per-input engine verdicts,
Full acceptance and isolation; bad-payer cases cannot borrow the pool input's
rejection. Real NONE2 signatures, exact backing/ranges, immutable successor,
current NF equality, separate stale/corrupt paths and a genuine proof against
changed native-consistent ciphertext Auth have explicit expected outcomes.
The last has the exact Groth16 verification error as its target.

The capacity context derives n=43,691/m=65,536 from 21,845 private splits and
21,845 later leaf reveals with one 60M liability left. Physical indices retain
actual append order; a terminal 17th-bit NF append and a corrupt top-level
append-path control are selected. Historical one-sompi fees, zero historical
ciphertexts and absence of historical proofs/chain acceptance are explicit;
this is a constructive supplied-context boundary, not an accepted-history or
archive-recovery result. Earlier EXPECTED metadata retains historical assembler
pins: the exact 3f155480 snapshot is retained, but the 5fd9de6d capacity-helper
revision has not yet been located. Its historical helper provenance remains
unresolved; current source06, all sealed raw cases and the executed ELF are
independently closed. This limitation must not be erased by the new freeze.

The competing fork assembler source SHA256
`7b4f3f0e9505a59c292855f0d5dfe4ddfe32ca22cdbf3ead4b36a9015b91e7f2`
received separate source ACK. Original Bob NF and its first witness were checked
independently: both paths authenticate CURRENT NF roots, and only fork B's
predecessor value equals the already spent original NF. Both proposed private
relations use one real plus one canonical dummy input, conserving 1B into 500M,
481,248,600 and 18,751,400 fee. Each is a separate hypothetical branch; the
subsequent genuine proof/native closure is recorded below.

### Native control run: observed results, including the failed typed target

The original run returned exit 1 and its frozen typed score remains **60/63**.
All seven positive Full cases accepted and all 56 negative Full cases rejected.
Raw result SHA256:
`d92152c166e13f5f4997d505395f930ed4c71d8d14932767b655bd4b436bff4c`.
All 63 individual raw reports match their result rows and isolation PASS. All
559 fixture members still match after execution. No semantic rerun or expected
table edit was made to obtain a different score.

The three mismatches are corrupt ADMIT signature, wrong ADMIT signing key and
wrong reveal signer: predicted NullFail, observed EvalFalse, Full rejection.
On pinned upstream 01b532e8b553523216471682649693af92f0fd16,
[OpCheckSig](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L827)
pushes the signature check's false result; the
[final stack check](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L732)
returns EvalFalse. The NullFail path at lib.rs:839 belongs to multisig. The
source prediction was wrong; the tested authorization rejection is present.

Both current-spent NF equality cases give VerifyError. Their occupied leaf
values and paths were independently recomputed against their CURRENT roots;
the reveal's raw CM membership and positioned NF also match. The changed-Auth
genuine proof gives the exact Groth16 verification error. The 17th-bit terminal
append accepts at fee 24,816,000 and payout 35,184,000; its corrupt top sibling
rejects. Real NONE2 controls reject at the exact-ALL guard, while the funding
input's independently evaluated NONE2 signature accepts.

### Selected development PK loader: source-only ACK

The new loader source and CLI were independently reviewed twice:
selected_key.rs SHA256
`da94deeee1e892a6173c66eeaca11e440057a8611bc48978b47eb2f447340e92`,
main.rs SHA256
`0f937e9ae378e2cd601969fe52ab571ad8eb0c11beb16c2403ab359cb52bd19c`.
Only the fixed fresh, fully checked baseline PK is selected: exact compiled
selection identity, PK length/full SHA, source/domain pins and native VK.
Unchecked compressed parsing is private and receives the SAME owned immutable
buffer only after full authentication. It checks exhaustion, drops the encoded
buffer and passes the extracted VK through the original fully checked helper
and exact pinned comparison. No caller hash override or generic unchecked mode
exists; submitted proof/VK validation stays unchanged.

Loader-only accepts selection and a fresh output directory, with no fixture or
prove call. Prove mode retains strict original fixture parsing, library proof
verification and an additional check against the fixed native VK. Tiny source
controls exercise changed/malformed selection, wrong-length key and the SHA
predicate's changed bytes/pin; they are not a full-size tampered-key trial.
No source blocker was found for one separately frozen loader-only measurement.
No key load, proof, native runtime or performance rerun was performed by this
reviewer; latency, memory and R8 remain measurement gates.

ADR-0044 SHA256
`8089df15245fbd4e44a5770b8e46833682258b54f0bfdc2e6a06262f7a5f84c8`
was separately read and matches this source boundary and isolated-experiment
scope. Its later fork use does not select an uncompressed cache or change the
baseline/circuit/native policy.

The single loader-only result was then inspected without rerunning it. Runtime
freeze SHA256
`522c4f0517e0d90bf03d4d5c4830ccb2826d0adeccc07e675ad6181190388e04`
closes all six small input/executable pins plus plan/build links. Result SHA256
`dc4bd9e384c79a41f0721cb59785fd6f77d4b682fc8974b5bd6dc0dfa739dd2a`
is PASS with the exact fixed VK328 and no proof operation. Wall time is 156.50s:
read 0.619s, full SHA 0.425s, compressed decoding 155.266s. GNU time reports
2,953,192 KiB peak RSS; cgroup telemetry reports 3,041,153,024 bytes peak. All
310 samples agree with cleanup and have zero available swap readings. Cleanup
confirms MainPID0 and no remaining owned cgroup processes. Serial decoding
dominates this stage; the baseline included proving and page cache was
uncontrolled. Neither a direct end-to-end speedup nor R8 is established.

For the original independent exits, both actual runtime wrappers and the
execution-environment record were read. The isolated network/PID/mount namespace
binds only lifecycle data, frozen assembly, receiver, native emitter and crypto
bridge; the inside wrapper asserts PK and prover paths absent before executing
any revealing authorization. This supports the tested offline dependency
boundary, while canonical accepted head and complete archive remain external.

## Genuine competing-path proof artifact closure

Both separately rebound proofs completed with the same selected PK and VK.
The proof file, report, exact immutable fixture, authorization484.bin and native
vector bytes were compared directly. Proof hashes are
`9008c0fcdafdd2320efbd9377393749a1c4ae01461b2c173f78c8169a8e60162`
for A and
`1defbbdced31276b9ddef8d8cbfa27442e19d532f2e303c05541ef3d3535fc1b`
for B. Their Auth hashes are respectively
`673c8340ef3f765ee35408d9433922c2b474c638406cbb269c11c9a414c92746`
and
`1f1d770e3d77550ff3f0ba258780426c013af744f3c7171ddb868de7cd2c1b7d`.
Both proof bytes differ from the primary proof and from each other. Both
reviewed prover reports state genuine verification against the exact fixed VK;
this reviewer did not run a proof verifier.

A/B whole-process wall times were 184.01s/183.74s, with approximately 159s
loading and 24s proving plus library verification. RSS peaks were 5,644,180 and
5,585,628 KiB, both above 4 GiB; no R8 or matched performance improvement is
claimed. Cleanup reports success/inactive/dead/MainPID0 for each owned unit.

The three actual native cases were separately frozen in SHA256
`dde66f751aa383057a186f7fb659f4c440467246b615c5ca7e6e50f7be9a53c0`;
all 112 members were rehashed before the intended native run. The producer uses
the exact retained 7b4f3f0e assembler snapshot. A consumes the primary private
output; B consumes the primary Bob-reveal output. The losing old-Bob reveal
consumes A's actual output. In all three raw bodies, first NF Merkle paths were
independently recomputed against the CURRENT root: A authenticates an unspent
interval, the two losers authenticate exact occupied original-NF equality.
The losing reveal's original CM membership is also current after A's appends.
The one native run then matched all three exact typed expectations. Actual
result SHA256
`b878ee34ef075b67b9ec23834962c06324c7874d2fd3ffdfaeda531eaa5ea54a`.
Each raw native report agrees with its result row and isolation PASS. A accepts
with 14,947,907 units and 18,751,400 fee. The old-Bob reveal after A rejects with
VerifyError at 58,313 units; B's genuinely rebound private proof after Bob's
main reveal rejects with VerifyError at 51,483 units. Both fail before the
signature/Groth16 branch, at current occupied original-NF equality. All 112
freeze members still match after execution. The original primary fee sequence
and separate 60/63 typed prediction result are unchanged.

The accepted A body also passed one new independently frozen conformance case,
using the unchanged source SHA256
`2998655a8243f61da61f9de6cf6442d2069addf4ca6d67c9e97cb48c6cb0cf18`
and one stdlib thread/1 GiB cap.
Freeze03 SHA256:
`fb20e1feba54b5d5c55d3de9aa2098c2c0577c7cb8d679c104586ea92460270a`.
Result03 SHA256:
`2fc6372f477476f0c08f340d46418b8dcbf35f4372d55b937f76d1f2e9e729cc`.
The real positioned HMAC NF, canonical keyed dummy NF, complete public updates,
bounded conservation, Auth digest limbs and actual body/context/immutable P2SH
all pass. The producer case retains constructor01 paths, independently checked
byte-identical to the actual frozen/validated02 body and context; both aliases
are explicitly pinned in freeze03. All 13 source pins, new case and aliases
were rehashed after evaluation. No implementation import, proof verifier,
native engine or old workflow was run by this reviewer.

