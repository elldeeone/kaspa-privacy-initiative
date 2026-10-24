# One-invoice compact payment preparation

This package adds an owner-local preparation seam for the **existing compact serial policy**: one recipient invoice plus fresh sender-owned private change. It can prepare another invoice payment from seed-recovered change.

The preparation core does not implement a new anonymity protocol or aggregation authority. Root separately selected the public child producer described below, including its namespace/prover workflow. The light controls use public unsafe development seeds, receipt cryptography, sparse state and fake proof processes only; they invoke no PK, Groth16 prover, Kaspa NativeVM or network.

## API

`payment.Request.parse(raw, expected_domain)` accepts exactly:

```text
schema = kpx4-single-invoice-payment-request/v1
domain_hex32
recipient_invoice_hex208
net_principal_sompi
recipient_exit_credit_sompi
```

No recipient list, owner map, seed, operation-purpose hint or arbitrary parameter path is accepted.

`prepare_payment(wallet, snapshot, claim, previous, reserve_sompi, fee_sompi, request, historical, expected_exit_credit_sompi=..., fee_context=...)` returns an opaque `PreparedPayment`. It reuses exact selected `actions.assemble` for original positioned NF, actual-slot dummy HMAC, CM/CF shuffle, normal receipt encryption and sparse append. Both outputs must be positive and exact:

```text
owned input = requested net + explicit recipient exit credit + sender change + exact fee
```

The caller supplies an authenticated own recovery and selected current/virtual context. The request's future exit credit must match the caller's independently selected expectation; it is not a future fee guarantee. A future owner exit must quote the actual body and preserve requested principal.

`fee_context` is explicitly either `STANDALONE_ACTUAL_QUOTE_REQUIRED` or `PROPOSED_VIRTUAL_NEW_POLICY_REQUIRED`. The first still requires the existing exact actual-body quote before witness send. The second requires the separately selected new settlement policy, exact outer quote/allocation and authentic starting head; changing the label does not grant that authority. Old Auths cannot authorize another outpoint/state/fee.

`public_component(prepared, proof128, public_case)` copies only Auth, payload, proof and the canonical-shaped public case, with an explicit **UNVERIFIED_COMPONENT_EXTERNAL_SETTLEMENT_POLICY_REQUIRED** label. It checks wire consistency and exact P0 reserve/fee effects. It does **not** verify Groth16, rederive the official transaction ID, select the child-template tail, validate NF/Merkle transitions, authenticate accepted state or establish native/virtual settlement authority. Send its `public_case` only to the externally selected shared-settlement verifier; never serialize `PreparedPayment`/`Candidate` internals.

## Trust and reuse

`reuse.py` authenticates six exact existing public helper sources and executes their owned bytes under isolated module aliases. Reused algorithms/parameters/native code are unchanged. Installed code/host integrity remains a premise; an untrusted request or capsule cannot choose these helpers. A real owner flow must retain the original metadata alias guard and authenticate whole selected PK/READY **before** reading its original backup. This package opens no backup.

Public request CLI:

```sh
python3 -B prepare.py --request PUBLIC_REQUEST.json --expected-domain-hex32 INSTALLED_DOMAIN
```

It only validates a public request and makes no authorization/quote. It is not an owner client or recovery command.

## Controls

```sh
python3 -B -m unittest -v test_payment.py
```

Eight focused controls pass: exact requested gross/change/fee and original-backup recognition; both output positions; two reentrant invoices followed by own cashouts and exact state conservation; malformed/domain/type request rejection; self invoice/dust/credit rejection; spent NF refusal; public-only copied component; mutated public fee/point/payload/proof/context/header rejection.

The two-payment/cashout control is **receipt-crypto/state integration**, with fake public points/program/proof bytes where used. It is not a genuine proof/native lifecycle, currentness, financial qualification or blinded privacy study. A successful permutation test proves only that both slots are possible.

A known payee may infer the positive sibling is sender change and propagate that association through later spends. Singleton/staggered funding can reveal ancestry. This is the existing serial baseline and may reduce a wide cohort's unrelated-recipient exposure; no privacy improvement is qualified.

## Selected public ADR59 producer

Root separately selected a new integration: two fresh compact/P0 child proofs under the capacity profile, with independently allocated fees and a new wrapper. `public_fixture.py public-note` derives only one deliberately known unsafe actor per process, exporting its initial2B note/CM/CF and index1 public payment invoice. `assemble` combines two public records into n2/m1/R4B without deriving either seed. This constructed prestate is not a GN, two accepted funding sources or backing.

`public_child.py make-context` requires both positive allocated fees, their exact outer total, explicit future exit credit and a quote reference. No fee/credit defaults exist. The selected policy must finally recheck the actual complete outer quote; a changed allocation/effect needs a fresh preparation and proof.

`public_child.py prove-child` authenticates the profile/manifest/ELF, waits for exact whole-PK READY, then derives only its own known public actor and recovers the original2B claim at that actor's position. It leaves the opposite actor's witness private to its process. Root's selected child-template tail builds virtual bodies without invoking the old fixed-domain emitter. Official2.1 public normalization fixes the virtual ID before the witness goes to the prover; it is not a Native Full check. Outputs are selected public COMPONENT/SUCCESSOR/RESULTS plus the verified public proof artifacts. Only finite successful selections may be published; never recursively export controller/failed-normalization directories.

The two actors cross-pay one10-KAS requested invoice each, plus explicit exit credit, retaining positive change. Indices0/1 are excluded from change selection so the already issued index1 receive invoice cannot collide with a random change index. `run_public_child.py` snapshots exactly required public code/inputs into one network-off namespace, mounts one compact PK, and excludes the original operator/PK/prover/controller paths. Root owns resource limits and the heavy execution release; no heavy run follows from a source/control pass.

Fourteen light controls (the original8 plus6 public-producer controls) pass, including missing allocations/credits, corrupted state, wrong profile/READY before seed and reserved-invoice index rejection. The tests use fake proof processes and no actual PK/prover/NativeVM. Public known-seed setup and two cross-payments provide no unknown-third-party anonymity denominator; participant knowledge must include all own controlled claims and own outgoing invoice facts.

[Design/evidence](../../research/next-session/independent-payments/privacy-wallet/DESIGN-01.md) retains the narrower root-selected execution scope. No redundant three-proof campaign is selected. Fresh proof/native work waits for a useful new release/coldbuild/shared-settlement boundary and root's coordinated heavy window.

