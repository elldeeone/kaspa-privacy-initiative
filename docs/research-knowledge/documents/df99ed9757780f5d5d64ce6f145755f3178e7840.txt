# Public validation API controls

These controls start no MPC, owner client, network peer or proof. They reuse
the compiler flags, actual core objects and standard SoftSpoken libraries from
an explicitly selected successful `BUILD-RESULT.json`.

```sh
python3 poc/local-private-payment/mpc-prover/tests/run_validation_api_controls.py \
  --build-manifest .local/mpc-prover-build-13/BUILD-RESULT.json \
  --output .local/mpc-validation-public-api-FRESH-IDENTITY
```

The output directory must be fresh. Use the allocated1CPU/2GiB resource scope.
The runner first requires a positive header/API compilation, then checks nine
negative fixtures for both compilation failure and the intended diagnostic.
It compiles/links the public field adapter control against the selected real
objects; no test replacement for the field or protocol is supplied.

The executed controls passed27 public field checks: canonical0/1/P-1 and
asymmetric LE encoding; P/P+1/max256 refusal; empty/short/long/trailing/consumed
frames; preserved value on invalid unpack; canonical addition/reset; fixed-coin
cancellation and public Fermat edges. Capability controls admit read-only public
metadata and an rvalue reference to the same instance while rejecting Boolean
forgery, copy/move construction and assignment, private constructor access,
assignment mutation/view and direct consumption.

Receipts are retained in `.local/mpc-validation-public-api-20261028-01/` and
`02/`. Attempt01 passed the positive and all nine negative compiler cases but
the field test failed to compile because stock Fr's unary minus is nonconst.
The test was corrected to `Fr(0)-coin`;02 passed field compile/link/execution.
The unchanged capability evidence was reused only after exact header/fixture
source hash checks. The first failed attempt remains a failure.

Runtime wrong-context, generation/epoch, model/binding mismatch, capability reuse,
MAC failure and pre-opening refusal need the actual protocol controls. These
public parser/compiler results do not establish those properties, coin
unpredictability, complete assignment validity, a financial MPC or cryptographic
correctness. Fixed coins exist only in the separately compiled public control.
