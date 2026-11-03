# Future compact2/wide32 circuit obligations

**Architecture review only. Neither circuit is implemented or selected.**
ADR-0056 authorizes the native emitter screen, not new matrices, parameters,
proofs or funding. A zero-proof case reaching a typed G16 failure establishes
only the preceding native checks on that supplied public case.

Reviewed 2026-10-23 against [ADR-0056](../../../../docs/adr/0056-compact-native-batch-fee-screen.md)
SHA256 `6901154567d5c48bdc8cb653de2c825df5dd679c5315be40de4e63cc8a5f3b4c`,
[WHOLE-EMITTER-SPEC-01](WHOLE-EMITTER-SPEC-01.md) SHA256
`c4577c3655e2d7143952b75b534aa004fd47e192b19f679df5103982ec779dda`,
and the unchanged [old circuit](../../../../poc/private-cashout-prover/src/circuit.rs)
SHA256 `ef8f4fca15bd0f363d50f734d6d751360455b5a52fe35ea6486f01259fa90b64`.
No old prover packet was modified; no build, setup, PK, private witness, proof,
funding or RPC was used for this review.

## Relation contract that must replace the old one

The proposed roles are compact2 with modes 0/2 and two output witnesses, and
wide32 with mode 32 and 32 output witnesses. These are different relations and
need separately matched future parameters. A compact owner must not need the
wide PK merely to recover or exit. Both roles still have two public inputs:
the complete SHA256(Auth528), split into exact LE128 limbs without reducing a
full 256-bit digest into one field element.

| Obligation | Required future relation |
| --- | --- |
| New Auth semantics | New magic/domain/profile and strict role/mode binding. Bytes 268..299 are the array digest; 300 is mode; 301..303 and 308..331 are zero; 304..307 is LE32 start. These are no longer two raw CMs. Continuing compact2 therefore already needs a new circuit. |
| Canonical modes/ranges | Compact accepts only 0 or 2; wide only 32, with P=0. Mode 0 iff R'=0; modes 2/32 require R'>=60M. Preserve state magic/domain, u32 cursor/count bounds, m<=2n+1, m<=131071 and m'=m+2. For continuing arity N, replace old n'=n+2 by start=ceil(n/N)*N, n'=start+N<=65535 with bounded integer alignment. Terminal has start=0, n'=n and CM-root carry. Native must independently check these against the actual state. |
| Output-list binding | Compute every Note168 commitment using the existing note tag/domain; constrain Auth268 to SHA256(CM0||…||CM[N−1]) in exact physical slot order. Use the full 32-byte digest. Do not add an unselected tag, sort the list, hash only positives, or take a prover-supplied list digest on trust. |
| Active output validity | Every positive output has value 60M..MAX. A continuing zero-value dummy has zero owner/incoming/key/nativePK fields; its rho may vary. Keep pairwise CM inequality for all continuing slots, including padded outputs: 1 comparison for N=2, 496 for N=32. Old Auth268-vs300 inequality now compares a digest with metadata and is obsolete. |
| Terminal inactive fields | Only compact mode 0, R'=0, P>0. Force both entire Note168s zero, including rho. Auth array digest and metadata are zero sentinels, not SHA256(empty) or the commitments of zero notes. Disable continuing list-digest equality and CM inequality only for mode 0; otherwise identical zero notes make terminal unsatisfiable. Bind the constant SHA256(528 zero bytes), despite the omitted ciphertext section. |
| Positive-output gate | Preserve “at least one positive private output OR positive payout.” Wide32 is P0 and needs at least one positive output. 32 slots do not prove 32 real recipients: the economic 32-payment claim separately requires 32 already demanded useful receipts, excluding change/dummies. |
| Exact integer balance | Preserve ΣIn=ΣPrivateOut+P+f and R'=R−P−f; f>0, P=0 or P>=10M, R'=0 or R'>=60M. All individual values are bounded u64; MAX=2,870,000,000,000,000,000. Prove ΣIn<=MAX and ΣIn<=R. The output aggregate then also lies<=R through the exact nonnegative equality. Host sums must use checked u128; never fold 32 outputs through wrapping u64 addition. |
| Input authority | Retain exactly two private real/dummy input slots, at least one real, owner s and k commitments, real-note floor, canonical dummy zeros, position<old n, 16-level current CM membership and distinct positions when both inputs are real. There is no other-owner witness aggregation. |
| Shared original NFs | Retain both actual-slot dummy HMAC formulas, real/dummy selector constraints, nonzero/distinct NF0/NF1 and the original positioned real NF. **Do not change the real-NF domain by mode/VK/role:** compact, wide and retained REVEAL must compete for the same note NF. Role-separated real NFs would permit one consumption per role. |
| Payout authorization | Retain full canonical SPK36/amount/fee binding and P>0 payout-key inequality against every real consumed note's native key. P0 has zero SPK36. Format/equality checks do not prove global destination freshness, possession or anonymity. |

Each compiled role must have fixed allocations and matrix construction. Compact
terminal/continuing behavior uses constrained Boolean predicates, not host
branches that change the circuit shape. A shared maximum32-output implementation
must not silently make compact owners use wide parameters or leave slots 2..31
unconstrained; that would be a separate design choice.

The old aggregate slack checks plus nonnegative bounded outputs can be retained:
even 34*MAX is below 2^67, far below the BN254 scalar modulus. This explains exact
integer equality; it is not permission to use modular u64 arithmetic. Future
negative controls should include 32 individually legal values whose u64 sum
wraps, late-slot commitment/order/duplicate mutations, reserved-byte/mode/start
mutations, wrong-role proofs and terminal rho/hash mutations. Host parser errors
must remain separate from direct constraint UNSAT results. None was run here.

## Checks that must remain native

1. **Actual acceptance/context:** exact current pool outpoint, actual consumed
   P2SH/state/reserve, transaction version/framing/metadata and immutable next
   policy. Check actual payout amount/SPK, complete outputs and fee against Auth.
   Hashing Auth in a proof does not authenticate an arbitrary caller-supplied
   root or establish accepted-chain backing.
2. **Current spentness:** both sequential indexed-NF predecessor/path/absence/
   sentinel/order/insertion checks, m/count/capacity rules and NF-root binding.
   The private circuit proves NF derivation, not current absence. No host
   “unspent” Boolean or unimplemented future gadget replaces them.
3. **Public array/tree/cipher binding:** exact mode-dependent frame length, both
   NF witness offsets, list hash, ciphertext hash, aligned start/new cursor and
   old-empty/new-root subtree transition over every ordered list entry. Private
   note commitments plus an array digest do not prove this tree update. Terminal
   omission requires the exact zero sentinels/constant hash/carry semantics,
   not an unchecked missing section.
4. **Induction and fallback:** founding and every ADMIT/private/REVEAL transition
   must preserve the canonical empty suffix and actual liabilities. The aligned
   boundary authenticates an empty target block, not every skipped position in
   an arbitrary malformed prior tree. Preserve whole ADMIT and owner REVEAL,
   signatures/authority and their shared NF semantics. No admin rescue is added.
5. **Role dispatch:** hardcode/check both canonical VKs and choose wide only for
   mode 32; compact for 0/2. The two valid placeholder keys with zeroProof128 may
   produce the same serialization failure. That runtime outcome cannot identify
   the selected key or establish cross-role rejection. Source/disassembly
   conformance is needed now; genuine role-bound controls belong to a later ADR.

Ciphertext encryption correctness and recipient possession are not proved by
native hashing or the old circuit. Preserve recipient decrypt/rederive/CM/NF
checks and the explicit delivery assumption. Public mode 32 discloses wide
activity, not private real-slot count or 32 independent humans.

Sparse positions matter to wallet recovery: start+i is each output's actual CM
position and original-NF input. Skipped positions are canonical empty leaves,
not receipts to renumber away. Replay/scanning needs a separately reviewed
sparse representation; current contiguous V2 Snapshot is not automatically
compatible. Cursor n is not the number of real notes or people.

**No-append full exit with R'>0 remains UNSELECTED.** Mode 0 still requires R'=0;
mode 2 continuing full cashout still appends two dummy CMs and consumes alignment
capacity. Alignment can reject an append before the underlying 16-level tree is
literally full. The bounded CM126/NF67 lifecycle does not solve sustained-pool
private exit availability or justify deleting the append/zero-note checks.

## Structural sizing, not a performance result

The closed old relation measured 3,231,025 constraints, 3,195,131 witness variables,
3 instances, H length 4,194,303 and 1,290,878,896 public-PK bytes. Its complete
setup/resident session observed a 4.95GB cgroup peak; those measurements do not
bound either future relation.

Logical SHA compression counts before constant folding give a useful planning
check. The old relation has 107 blocks: 8 input-note, 8 owner/key, 10 HMAC, 64 input
membership, 8 output-note and 9 Auth blocks. Compact adds a 64-byte list digest
(2 blocks), about 109 total. Wide adds 30 more 208-byte Note preimages (120 blocks)
and a 1024-byte list digest (17 blocks), about 244 total. Distinctness expands to
496 comparisons. Arkworks 0.6 UInt/eq uses packed byte-field comparisons and a
k-ary reduction, suggesting tens of thousands of extra gates if reused directly;
a naive bitwise design could spend roughly a quarter-million. Output allocation,
range/sum and metadata wiring add further work.

This suggests compact stays near the old size and wide could be roughly 6–9M
constraints/witnesses (a central linear estimate around 7.5M). **These are not
certified bounds or synthesized dimensions.** Constant folding, equality
gadgets and allocation choices change them. Arkworks 0.6 generator.rs88–89
chooses its evaluation domain from constraints+instances; crossing 2^23 required
rows jumps H from 8,388,607 to 16,777,215. Existing H is 2^22−1.

With three instances, A/B1/B2 have W+3 entries, L has W, H has domain−1.
Uncompressed query growth is 320*ΔW+64*ΔH bytes under the current format. The
rough wide range therefore suggests public parameters on the order of 2.5–4GB,
not a measured artifact. Only the compact parameters are an owner-exit dependency.

An 18GiB/14-CPU development run **might fit** the lower/domain 2^23 region; this is
not established. The next FFT step, retained finalized CS, simultaneous query/
MSM buffers, allocator peaks and owned-byte decode buffer can defeat linear
memory extrapolation. 14 CPUs do not establish latency or RAM feasibility. No
setup, run cap, hardware target, p95 or GPU/backend change is authorized by this
estimate. Only after a fitting, reviewed whole-emitter screen should a separate
decision select a circuit and then measure its actual shape/resources.
