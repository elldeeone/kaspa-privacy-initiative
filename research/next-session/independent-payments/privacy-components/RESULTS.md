# Existing MWEB components: actual public-only aggregation

**Two independent owner processes successfully created signed, range-proved MWEB payment/change components. A separate process merged their public serialized transactions, and another fresh process validated the aggregate.** The existing upstream machinery works without transferring the owners' spend secrets to the aggregation API. This is concrete component feasibility evidence for an established design family, not a private native-KAS implementation or privacy qualification.

The experiment uses unmodified Litecoin source at `ec1b6489a900d09cf5991e220dce089c77a232a2`. [DESIGN](DESIGN.md), [PLAN](PLAN.json), [source pins](SOURCE-PINS.json) and [source freeze](SOURCE-FREEZE.json) preceded the first test draw. There was no blockchain network, node/daemon, canonical peg-in, real money, KAS proof/program, parameter access or deployment.

## What actually ran

The upstream [aggregation test](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/test/tests/consensus/Test_Aggregation.cpp) builds and validates two transactions, checks sorted input/output/kernel unions and sums both public offsets. The minimal harness executed that same API/assertion sequence using the existing builder/aggregator/validators. It did **not** execute the full Boost/node/DB test fixture or claim the entire upstream suite passed.

The fixed payment experiment then used these separate processes:

1. OwnerA: declared synthetic owned input25 → payment10 + change14 + fee1.
2. OwnerB: declared synthetic owned input40 → payment20 + change19 + fee1.
3. Aggregator: read only the two public transaction files, deserialize, validate, call upstream [Aggregation::Aggregate](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/include/mw/consensus/Aggregation.h), validate and serialize.
4. Fresh verifier: deserialize and validate the4311-byte aggregate, with two inputs, four outputs and two kernels. Process-local signature/range-proof caches started fresh.

Each owner first generated a local declared synthetic peg-in fixture. Its consumed input ID, commitment and output authorization key match that fixture's actual output. This demonstrates owned local test material, not a confirmed/accepted or canonically backed UTXO. Amounts are integer unfunded library test units, not KAS or real LTC. All spend keys and private blinds remain inside their owner processes and were neither emitted nor hashed. Only public serialized transactions, declared test accounting and public IDs were exported.

Upstream [Transaction::Validate](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/models/tx/Transaction.cpp) checks the body, kernel balance and stealth balance. [TxBody::Validate](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/models/tx/TxBody.cpp) checks limits/order/duplicates, signatures and64-bit Bulletproofs. Four fixed negatives were actually rejected through existing upstream APIs: duplicate component inputs/kernels, a removed output, a mutated range proof and an invalid signature. The first two are transaction-level checks; the latter two call the proof/signature validators directly. These are implementation observations, not a soundness proof.

## Receiver-scope correction from independent review

The default upstream **test** helper `test::TxBuilder::AddOutput(amount)` generates the receiver scan/spend keys inside the sender's test process. Consequently the original report field named `legitimate_C1_payment_output_id` is a known-output fixture marker, not evidence of an independently created recipient invoice, private recipient scanning or recipient-only spend authority. The original public-only aggregation and input-owner isolation results stand. Receiver independence/I-14 requires a separate fresh experiment using recipient-created public StealthAddress data; the original files and source remain retained without reinterpretation.

## What observers still see

| Observer/surface | Actual finding | Limit |
| --- | --- | --- |
| Final serialization | One global input vector, output vector and kernel vector, with one summed kernel offset and one summed stealth offset. No separate component output vectors or individual component offsets are serialized in that final transaction. | Missing grouping fields and sorted vectors do not prove unlinkability or exclude an algebraic, timing, amount or auxiliary-data attack. |
| Actual output keys | All four tested outputs have distinct sender keys and distinct receiver keys. | The [test builder](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/test/framework/src/TxBuilder.cpp) uses a fresh sender key for each default AddOutput call. Production [CreateOutputs](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/wallet/TxBuilder.cpp) also draws a fresh ephemeral key per recipient. Uniqueness is a wallet behavior, not a consensus privacy requirement; explicit key reuse can disclose a group. |
| Kernels/fees | Two original kernel IDs/excesses/stealth excesses survive, each with fee1 and features17. | A pre-aggregation observer can retain each kernel's origin; public fee/feature differences can be additional fingerprints in other workloads. |
| Pre-aggregation/coordinator | All four unchanged output IDs, both input references and both kernel IDs can still be assigned to their originally observed components. | This is a complete retained negative for that observer. Public-only aggregation avoids collecting spend secrets; it does not erase the public component mapping already observed. |
| Spent-input references | Each consumed output ID, commitment and authorization public key is publicly serialized. | This materially differs from the current KAS hidden-membership/positioned-NF design. It is not evidence for CM-to-payout privacy or a drop-in replacement satisfying the same invariants. |
| Singleton/timing | A single component remains individually verifiable; upstream Aggregate returns its sole input unchanged. | No independent source or anonymity appears through aggregation alone. Existing sparse/early-cashout and timing failures remain. |
| C1 receipt facts | A separate file supplies one own payment output ID, amount10 and declared payerA; the component-origin map is kept in the explicitly stronger pre-aggregation view. | This receipt-fact subset is not a full payee-opening/key model and no C1 anonymity/guessing metric was measured. The full research packet deliberately also includes the negative observer map, so it is not a blinded observer corpus. |

[PUBLIC-ASSOCIATION-FIELDS.json](PUBLIC-ASSOCIATION-FIELDS.json) inventories the actual input IDs/commitments/keys; output IDs/commitments/sender, receiver and key-exchange keys/tags/masked fields; kernels/fees/features/excesses; and both **public wire-format offset scalars** for the two components, their aggregate and both local funding fixtures. Those offset scalars are public transaction data, not owner spend secrets. Every inspected public input/output/kernel object remains byte-field identical in the aggregate. The additive inspector deserializes/recomputes public hashes; it does not sign, prove, draw randomness or perform new validation tests.

## Build, resources and exclusions

The isolated build uses existing system GCC15.2/OpenSSL3.5.5, unmodified vendored secp256k1-zkp and upstream-pinned fmt7.1.3. The fmt archive SHA256 is `5cae7072042b3043e12d53d50ef404bbb76949dad1de368d7f993a15c8c05ecc`, exactly matching upstream `depends/packages/libfmt.mk`; it is used header-only with no system installation. A small documented entropy bridge satisfies the existing GetStrongRandBytes fixture API with OpenSSL RAND_bytes. No cryptographic primitive, consensus condition, signature/range-proof check, balance equation or delivery implementation was changed.

The first minimal build exposed a missing EXTRAKEYS build define in the checked-in legacy config, while SCHNORRSIG was enabled. The harness enabled that existing module exactly as upstream configure.ac512–520 does; the [failure](build-attempt-01/RESULTS.json) and original CMake preimage remain. All upstream tracked source remains unchanged. No Boost/node/DB installation was attempted.

The successful second build took7.316s/7.421CPU seconds with formatted322.3M peak/swap0; the earlier failed build took10.468s/38.692CPU seconds with formatted1G peak/swap0. The eight-process component run completed in1.550s,1.540cgroup CPU seconds and formatted22.1M peak. The exact pre-exit cgroup snapshot is23,248,896bytes peak, zero swap/OOM events and1,533,597CPU microseconds; final service counters occur later. All child processes were waited; the service ended inactive/dead with MainPID0. These few tiny cases are not throughput/p95 measurements.

Public library outputs/reports, source identities and the minimal harness are selected. Executables, static libraries, full external checkout, dependency archive/build caches and all real private project material stay outside Git. Generated owner secrets were not exported. The frozen232-path capacity packet is unchanged.

## Consequence for the KAS design

This provides an executed mature precedent for owner-local authorization plus public aggregation/global value binding. It makes further design work more concrete than simply wrapping the current per-action proofs. Current KAS Auth/output partitions, SHA notes and hidden membership do not acquire these properties automatically. A candidate retaining hidden membership would need a separately reviewed established value-commitment/binding design, exact spend/output coverage, current NF enforcement, native reserve/payout/fee binding, owner-local proving, private unilateral exits and recoverable data. No hybrid cryptographic protocol or runtime was selected here.

The separate [independent recipient extension](recipient-extension/RESULTS.md) now completes recipient-origin public invoices, actual own-output recovery and production-builder spending with two recipient processes. It resolves the original fixture-marker limitation only for that bounded component test; no privacy/chain/KAS claim transfers.
