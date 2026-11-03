# Existing MWEB component screen review

ACK for the bounded upstream component result; no KAS or privacy qualification.
Reviewed plan/design, actual screen/driver/build/entropy bridge source and public
result. No additional build, experiment, private artifact or key read was needed.
The frozen capacity packet is unaffected.

The harness uses pinned unmodified Litecoin transaction builders, serialization,
aggregation and validators. Two separate input-owner processes write serialized
public transaction objects; a separate aggregate process receives only those
objects; a fresh process validates the aggregate. The original API-equivalent
control additionally checks sorted unions and public offset sums. Four actual
negative checks cover duplicate components, dropped output balance, changed
range proof and invalid signature. This is not the full upstream node/DB/Boost
suite, UTXO acceptance or a KAS reserve relation. The OpenSSL entropy bridge is
local test plumbing, not a replacement cryptographic primitive or production RNG
qualification.

The format conclusion is supported directly by pinned upstream
[Transaction serialization](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/include/mw/models/tx/Transaction.h#L83-L96)
and [TxBody serialization](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/include/mw/models/tx/TxBody.h#L88-L94):
the final object carries two offsets and global input/output/kernel vectors,
rather than original per-author vectors. That does not prove unlinkability.
An observer who already saw each component retains the actual4/4 output mapping;
input and kernel identifiers also survive. Spent output IDs remain public, so
this is not equivalent to the current KAS hidden-membership/positioned-NF design.

Two source limits must accompany any interpretation:

1. [Transaction::Validate](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/src/models/tx/Transaction.cpp#L48-L54)
   checks transaction body and kernel/stealth balance; synthetic peg-in validation
   does not establish backing or accepted UTXO existence/spentness.
2. The test framework’s default
   [AddOutput(amount)](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/test/framework/src/TxBuilder.cpp#L38-L66)
   generates receiver scan/spend keys inside the sending owner process. Thus
   independent input owners/public-only aggregation are tested, but the C1 JSON
   is a synthetic known-output record. An independently generated recipient
   invoice, receiver-secret isolation and recipient recovery/spending were not
   exercised. The public-StealthAddress overload is a relevant later boundary,
   not evidence imported into this test.

The explicit owned-input match to synthetic funding commitment/ID/key is useful.
No owner spend keys or their hashes are exported to aggregation. Public offsets
are protocol fields; observing original components can still expose grouping.
Missing grouping fields and distinct per-output sender keys cannot become a
privacy score or a claim against a coordinator/network observer.

Native-KAS adaptation still requires a separately reviewed commitment/range/
authorization interface, exact once-only output coverage and balance, current
spentness, native reserve/output/fee binding, owner-local witnesses, data
availability, private unilateral fallback and full recipient recovery. Existing
MWEB kernels do not automatically authorize this project’s complete final effect.
Singleton/timing limits remain. No token, mainnet implementation or direct
adoption is selected by this component screen.
