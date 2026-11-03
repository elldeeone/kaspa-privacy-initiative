# Frozen public future-exit feasibility plan

DO_NOT_FUND. New public synthetic format only. ADR0040 / RFC0019 candidate C.
This is not old S7 owner/replay/DRAIN work. No wallet/prover imports, private
material restoration, GPU run, funding, broadcast, accepted backing or chain
history. All fixture secrets are deliberately public and never production keys.
The native wire reveals only k and opening; it does not carry s or signing key.

Use official native revision `01b532e8b553523216471682649693af92f0fd16`.
Raw Full/mass/script helpers adapt `poc/shared-pool/src/native.rs` only; no old
private protocol relation is imported. Cargo lock derives its exact dependencies
from that already-pinned lock. Established SHA256/HMAC/Schnorr, tagged Merkle
and indexed-NF set techniques only; no new primitive claim.

## Canonical wire and state

Exact payload2029 bytes. Offsets/constants in standalone source are normative.
All unsigned integers use fixed u32LE/u64LE; numeric checks preserve sign/range.
`K=SHA256(KEY_TAG||D||k)` (RFC overrides older options note's shorthand).
State112 bytes: magic8, D32, CMroot32, n4, NFroot32, m4. CMdepth16;
NFdepth17. n1..65536, m1..131071 and m<=n before one insertion. m includes one sentinel
and one real NF per consumed note. There is no old parity rule. Separate tags
and CM/NF node tags prevent old-format/cross-tree use. Empty NF leaf uses a
separate tag from sentinel0. Indices are explicit unsigned and range checked.

Input is exactly one version1 native P2SH context. Sequence max, native subnet,
zero gas/lock, no covenant IDs. Signature65 bytes with exact SIG_HASH_ALL=1,
canonical push65 and PUSHDATA2 exact redeem. No caller historic CM root: CM
opening authenticates against actual immutable input state CMroot/n. HMAC exact
NF authenticates against current sorted predecessor interval and current NFroot.
The SAME predecessor path/index is used for old membership and new predecessor
root. Empty append at index m must authenticate that intermediate root; then
one real new leaf creates new root. Successor reconstructs actual immutable
redeem prefix/suffix, preserving D/CM/n and changing only NFroot/m+1. No separate
emergency map; private reference predicate computes byte-identical NF.

Whole note V=P+F, R'=R-V, canonical P2PK payout under CM-bound native key.
Native signature covers the real predecessor, output amounts/scripts and
payload. Budget excluded by native v1 sighash is checked by actual VM/Full/mass.
Terminal R=V has one positive payout and no zero reserve, conditional on valid
prior I1 complete liabilities L<=R and current unspent note V<=L. Then L=V,
so consuming whole note leaves zero liabilities. This supplied fixture does not
prove prior I1/lineage/private relation. Counterfixture R=V plus another unspent
positive note violates I1, and is unsupported rather than an accepted state.

## Frozen positive cases

Every claim V60M, P10M, F50M sompi, no external input, budget200 (2M allowance).
1. Terminal singleton R60M, one CM, sentinel NF.
2. Two-note R120M, remaining note60M and reserve60M.
3. Two-note R80M, remaining note20M and reserve20M.
4. Two-note R70M, remaining note10M and reserve10M.
5. Near CMcapacity n65536, pos65535, NFm65536/append65536. All earlier CM
   openings and their exact derived NFs are constructed publicly, sorted into
   the indexed set. Remaining actual liability60M, reserve120M contains donation
   surplus60M. Synthetic constructibility is not accepted lineage.

Each runs actual minimal redeem and explicitly padded32768/49152-byte envelopes.
Padding is NOP feasibility only, NOT an implemented/private-branch security
argument. Economic future-union inference is conditional on that byte footprint
and identical fast-branch behavior. Full compute/storage/transient/relay/mining
mass and actual signed fee are reported separately, quotes100/200/500. The gate
at500 is mass<=100000 and payout>=10M for <=50Mfee; a failed layout remains failed.
Exact source/payload/redeem hashes are emitted in freeze mode before execution.

## Expected controls and stop rule

All genuine positives must pass official isolation+Full and underlying VM.
Negative magic/mode/opening/K/k/nativePK/CM/position/current-path/NF/predecessor/
next-index/oldpath/intermediate/appendpath/newroot/amounts must reject.
Owner-resigned wrong payout/fee/reserve/successor/domain/stale-current-NF,
weak sighash, extra-input and trailing-payload variants must reject. After ideal
reference private consumption creates same successor NFroot, original reveal
must reject against that current state. Copied public k with wrong s must fail
the separate private reference predicate; deliberately unsafe single-secret
reference must accept it, showing why k-only private authorization is rejected.
Neither reference result is a SNARK or a fully implemented private branch.

Retain all failures and fix implementation defects explicitly; never weaken a
check or change fee/payout/amount/envelope expectations to repair economics.
Freeze source+fixture hash manifest and request adversarial second pass before
first native VM/Full execution. Build/use6CPU,10GiBRAM,swap0 after other native
build releases its slot. No extra GPU proof, network operation or paid resource.

## Pre-execution fee-agility addendum (same unchanged economic targets)

Retain every fixed50M fee/P10M body above. In a separately labeled profile,
for each same fixture and minimal/32768/49152 envelope, prepare actual signed
bodies at rates100/200/500. Start fee f=0, payout60M. Calculate the complete
native mining mass of body(f), including changed payout storage mass. If
f>=rate*mass, retain that fixed point. Otherwise set f=rate*mass and repeat;
if the next f exceeds50M, retain the last supported body and mark economic
FAIL (it does not fund its required quote). No different payout floor, fee cap,
principal, external input or privacy assumption. Monotone iteration with no
arbitrary trial-count cutoff. Fee never decreases, so the reached point is the
least fixed point reachable by this conservative monotone operator, conditional
on full native mass and exact body layout. Record the entire sequence and
native ID at each step, owner-sign the final body, freeze its transaction JSON
and hashes before any VM/Full execution. An economic failure still receives a
native check so fee inadequacy is distinct from consensus/script rejection.

## Adversarial pre-execution corrections

The source reviewer caught a weak-type control that signed ALL but merely
appended NONE; that would confound a missing exact-type guard with an invalid
signature. Before execution it now hashes/signs the ACTUAL requested type2
(SIG_HASH_NONE), independently verifies Schnorr under that digest/key, and
requires native `VerifyError` at the exact-ALL guard. All negative controls
require exact VM `VerifyError` and Full `SignatureInvalid(VerifyError)`; wrong
mass/resource/signature causes are failures of the experiment, not passes.
Extra input uses a distinct synthetic outpoint so isolation duplicates cannot
substitute for the intended one-input check. Counts0/out-of-range/high-bit and
m>n have separate controls. Old predecessor membership is authenticated before
strict predecessor/NF ordering. A second replay control supplies the CURRENT
spent-NF leaf/path and its matching current root, with predecessor value equal
to NF; membership is independently recomputed and native strict-order rejection
must still occur. This supplements the older stale-witness rejection rather
than replacing it. The underbacked R=V plus another positive note countercontext
is recorded analytically as unsupported prior I1, never an accepted-chain claim.
