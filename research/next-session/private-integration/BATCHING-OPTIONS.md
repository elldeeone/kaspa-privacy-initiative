# Two useful private payments under one native verifier

Reviewed 2026-10-23 against base
`0c2f4c788a4274b381c4838e05cce5e9c32e8536` and the new
[State112/Auth484 contract](NOTE-STATE-CONTRACT.md). Source-only decision note:
no build, synthesis, setup, proof, key restore or runtime was performed here.
Historical proofs below remain historical; none attests the new contract.

**Decision:** two independent owners can retain their secrets by producing
separate private Groth16 child proofs, then letting a fresh outer verifier prove
their public proof/state/effects composition. The established local route is
RISC Zero verification followed by its official Groth16 compression, yielding
one native verification. Its historical approximately five-minute proof time
fails the existing 60-second payment target; this is a compatibility candidate,
not a solution to current fees and latency. Do not launch that campaign merely
to repeat the known timing result.

A direct composite Arkworks circuit is simpler only when one payer legitimately
holds every consumed note secret. It can establish a separate self-batched
two-payment case; it does not solve independent-owner batching. One recipient
plus private change is one useful payment. Two recipients without change is a
favorable separate workload, not the generic two-payment-plus-change route.

## Options and the actual boundary

| Route | Private witness location | One native proof? | Decision for this run |
|---|---|---|---|
| One payer, direct composite Groth16 over two private transitions | One authorized payer owns both private witness sets; no additional disclosure needed. | Yes: one new BN254 proof with two digest limbs, 147,500 native mass floor before body/script/storage. | Smallest direct circuit experiment if the useful workload genuinely contains two recipient payments and retained change. Needs a new composite relation/VK and actual resource measurement. |
| Independent owners, direct composite circuit over both raw witnesses | A conventional centralized prover receives both owners' secrets. | Yes, but at an unacceptable new privacy/trust boundary. | Reject secret pooling. Distributed/MPC proving would be another unimplemented subsystem, not an implicit feature of Groth16. |
| Independent local Groth16 children, outer BN254 Groth16 verifier circuit | Owners keep secrets; outer prover needs only proofs and public statements. | In principle; no such compatible recursive BN254 circuit is implemented or measured here. | Not the smallest supported route. Do not mistake a generic Arkworks verifier-gadget API for a ready same-curve recursive prover. |
| Independent local Groth16 children, fresh RISC Zero public verifier, official Groth16 compression | Inner secrets remain local. Outer input is canonical proofs, Auth/public state and update witnesses. | Yes: established native-compatible wrapper uses five scalars, 155,000 native mass floor before body/script/storage. | Existing source/toolchain pattern worth adapting only after a new reviewed batch contract and explicit latency/economic decision. Historical execution makes a 60-second success assumption unjustified. |
| Same public-proof outer guest, native RISC Zero Succinct verification | Same separation as above. | One 0x21 verification, but 250,000 base mass and approximately 223 KB historical receipt. | Inferior for a two-payment fee screen: base charge alone exceeds the aggregate 200,000-mass ordinary-payment allowance, before serialization or state checks. |

The generic [Arkworks Groth16 verifier gadget](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/constraints.rs#L130-L155)
is parameterized over the inner curve's base prime field. The installed
[BN254 constraint module](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/curves/bn254/src/constraints/mod.rs#L1-L7)
operates over `Fq`; the proposed outer native BN254 Groth16 relation operates
over `Fr`. Those are different fields. Same-curve proof recursion would require
appropriate non-native pairing verification or another supported construction,
with its own constraints and checks. There is no measured cost or ready
implementation here; this is not evidence of impossibility.

## Smallest explicit compositional contract

This is a proposed extension, not a silent reinterpretation of Auth484 or the
already selected private/native union. It needs its own reviewed framing,
immutable verifier identity and byte contract before implementation.

1. **Keep each owner's proof local.** Each child uses the new exact private VK,
   canonical proof128 and its complete Auth484. The outer verifier pins that VK
   and domain, validates canonical/subgroup/nonidentity encodings, reconstructs
   both two-limb public digests and verifies both genuine pairing equations.
   Never accept a host-supplied `verified=true`, caller-selected VK, unfinished
   receipt assumption or old v6 proof under the new identity.
2. **Define child context versus actual UTXO context.** One atomic transaction
   spends the actual outpoint O with State S0 and reserve R0 and creates only the
   final successor S2/R2. No actual intermediate native outpoint exists. A
   possible explicitly defined batch mode pins O as the shared settlement
   anchor for both logical children, requires child0 S0/R0→S1/R1 and child1
   S1/R1→S2/R2, and commits their exact order. It must be clear that child1's
   logical pre-state is not a second actual native input. Existing Auth484's
   standalone description cannot simply be relabeled as that mode. Alternatively
   use a distinct child envelope; select one exact scheme in an ADR.
3. **Prove the public updates somewhere real.** Every child inserts its two NF
   slots and appends its two CM slots in the current authenticated trees. Verify
   the predecessor/empty-append paths and exact intermediate roots, indices,
   little-endian NF order, counts and policy; then enforce S1 continuity. Two
   valid private child proofs alone do not check these updates: the current
   circuit delegates them to native code. Either keep native checks and all
   per-child W3344, or implement and constrain them in the fresh outer program.
   No path can be omitted because it was called public.
4. **Bind fees, delivery and the final native output.** Total actual native fee
   is checked integer `f0+f1`; `R2=R0-f0-f1`, and each child preserves its own
   bounded note conservation/authorized fee. With two transitions, total CM/NF
   increments are four each; retain the capacity/backing invariant and 60M
   continuing reserve floor. Publish ordered NFs/CMs and both ciphertext pairs
   so an independent recipient can reconstruct the trees and decrypt. Bind all
   ordered effects, both full authorizations, initial/final states/reserves,
   actual anchor and immutable program/key/profile into the final journal.
   Native reconstructs its expected claim from actual input/output values and
   the published effects, then verifies that one claim and the exact immutable
   successor. Reordering, omission, duplicate spend and ciphertext substitution
   must fail through actual verification.
5. **Retain a separate owner exit.** A recipient still performs one no-append
   revealing exit from the current state, without waiting for another payment,
   batch or prover. An aggregate private branch must not turn a revealing exit
   into an accepted-ticket prerequisite or require a sponsor. Its larger real
   immutable code/VK changes reveal-body mass and must be measured again.

The common-anchor-versus-logical-step decision also determines whether clients
can prepare child proofs concurrently and what a failed/reordered batch means
for consent. Do not discard a child's committed next state to merge unrelated
proofs without explicitly defining and proving those authorization semantics.
Even sequential logical states need not expose secrets: once their candidate
public effects are available, owners can generate separate proofs against the
specified public contexts. Actual latency and contention are still unmeasured.

Official vProgs provides a useful [continuity/identity checklist](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_aggregator/verifier.rs#L66-L101),
checking each child's lane/covenant/program identities and predecessor state
before committing a bundle. Its [witness conversion](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/witness.rs#L81-L160)
converts the official Groth16 seal to canonical Arkworks proof128; its
[covenant](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs#L1-L43)
binds the expected journal and actual successor. Reuse these narrow principles
and checked byte boundaries, not its entire account runtime/operator stack.

## Fees: keep public-update and change costs in the screen

The [fee lane](fees/PLAN.md)'s current conservative publication envelope is
`356 + 4000*B` bytes before the surrounding transaction/redeem, where each
authorization contributes NF64 + CM64 + ciphertext528 + W3344. This assumes
only explicitly shared header/context fields; the final encoding may need more.
The smaller `356 + 656*B` effects-only possibility is conditional on the NEW
outer verifier actually checking all state updates and binding them in its
claim. It is not the current direct circuit's capability or a measured payload.

At rate100, two 10-KAS useful payments each have a 10M ordinary-payment cap;
thus at most 200,000 aggregate mining mass is available for payment alone.
Native base/key floors leave 52,500 mass for direct composite or 45,000 for the
official RISC Zero Groth16 wrapper. Serialization, actual budget, native checks
and contextual storage must fit inside those residuals; passing a floor is not
passing the complete body. Existing budget1600/1700 numbers do not qualify a
new aggregate script. Fees must be actually authorized; the historical B2 paid
80M remains 80M, not its lower hypothetical reference quote.

The general payment leaves both recipient value and payer change. Those are
separate positive liabilities and ordinarily need two independent cashouts;
change never increases the useful-payment principal denominator. The current
32-KiB envelope's approximately 14.1M reference-rate two-cashout cost already
leaves little of a 20M full-lifecycle allowance before payment and admission.
A smaller actual union or greater genuine amortization may matter; omitting
change, waiting for other users to cash out or assuming zero proving/retry costs
does not repair that route. The fee lane owns exact fixed points and allocation.

## Historical local resource evidence, not a new benchmark

| Exact retained workload | Historical observation | Limit on interpretation |
|---|---|---|
| [Old v6 private relation](../../../poc/shared-pool/TWO-INPUT.md#measured-cost-and-fee-envelope) and [TN10 preparation](../../../poc/shared-pool/TWO-INPUT-TN10.md) | 4,372,824 constraints; 962,197,520-byte compressed PK; four CPU threads; warm proof about20–22s; cold validated load about202–215s. Later preparations measured up to6.44GiB peak RSS. | Old note/tree/Auth format, not new State112/Auth484 or a doubled relation. No new synthesis/proof or old-key restore is authorized by reading this report. |
| [Two public v6 proof verification](../../../poc/two-v6-binding/RESULTS.md) | 77,129,798 user cycles;169 segments;299.604s genuine Succinct GPU proof;4.448s same-receipt Groth16 compression. Sampled6096MiB proving/5332MiB compression VRAM; host cgroup481,013,760B/1,783,631,872B. | Exact historical guest and public development proofs only. Native proof128 compatibility is real; no new contract, actual reserve lineage or lifecycle follows. |
| [Old two-v6 state assertion](../../../poc/two-v6-state/RESULTS.md) | Historical path77,648,328 user cycles;170 segments;303.363s Succinct +4.361s compression. Four current NF inserts/four CM appends added518,530 cycles over the pair-only guest. Sampled6096MiB/5300MiB VRAM and511,438,848B/1,783,369,728B host cgroup memory. | NONFUNDABLE old one-shot state assertion; cannot continue its designated-predecessor fixture. It is a scale preview, not a template to resume or new-state proof. |
| [Later same-claim scheduling comparison](../../../poc/s7-proof-performance/RESULTS.md) | IPC18 took505.118s and sampled3828MiB. Separate actor18 saved a valid receipt around449s but failed operational completion. | Neither reaches60s. Different caps/caches/concurrency prevent a causal general speedup claim; retain the actor failure. |

The state assertion's final complete native body measured163,290 mass with a
2,920-byte estimated transaction, but is explicitly a different one-shot
predecessor policy. The later actual B2 continuation anchor measured196,484
mass with a 24-KiB script and 80M paid fees. Neither is a size/budget/fee result
for the new private/reveal union. Enlarging that historical 24-KiB envelope to
32KiB conditionally gives204,676 mass, already beyond the two-payment ordinary
allowance. No frozen transaction is repriced here.

## Forge allocation and the next decisive gate

The parent run's verified resource inventory is14 logical CPUs,24GiB RAM and
one RTX3070 with8GiB VRAM. The new Arkworks package currently requests its first
frozen-witness synthesis under4CPU/12GiB/swap0; native construction has a
separate3CPU/5GiB build allocation. This is a workable overlapping envelope
with headroom, not evidence that a new two-action proof fits. Do not launch two
12GiB processes or extrapolate that a doubled circuit costs exactly twice the
RAM: FFT domain rounding, key material and matrix storage matter.

Arkworks0.6 currently has CPU/Rayon parallelism and no selected GPU backend,
as established in [the source review](PRIMARY-SOURCES.md#cpugpu-compatibility-use-the-implemented-backend).
RISC Zero's historical CUDA proving/compression fits this card's sampled
single-job envelope, but those GPU phases must be serialized; their peaks cannot
be added on an8GiB card. Its [official compression implementation](https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/groth16/src/prove/cuda.rs#L26-L58)
also requires separately identified Risc0Groth160.1.0 assets and preserves setup
assumptions. Existing authenticated component availability is not permission to
reuse a stopped job identity or old wallet/proof input.

**Next decisive work:** complete the new single-action real private/native
integration and actual minimal union size first; separately freeze a genuine
two-recipient workload with every change liability counted. If one payer owns
all inputs, a reviewed direct composite relation is the smallest new proof
experiment. If independent owners are required, retain independent local child
proofs and specify the explicit public-proof/state outer contract above; first
ask whether its historically failing latency and exact all-in fee residual can
meet the unchanged target. No present source evidence justifies claiming that
either new batching route already passes, or running additional historical GPU
proofs to make the machine busy.
