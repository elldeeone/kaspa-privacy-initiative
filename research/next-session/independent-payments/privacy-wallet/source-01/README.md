# One-invoice compact payment preparation

This package adds an owner-local preparation seam for the **existing compact serial policy**: one recipient invoice plus fresh sender-owned private change. It can prepare another invoice payment from seed-recovered change.

It does not implement a new anonymity protocol, aggregation authority, namespace launcher or proving job. The current preparation controls use public unsafe development seeds, receipt cryptography and sparse state only. No PK, prover, native validator or network is invoked.

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

[Design/evidence](../../research/next-session/independent-payments/privacy-wallet/DESIGN-01.md) retains the narrower root-selected execution scope. No redundant three-proof campaign is selected. Fresh proof/native work waits for a useful new release/coldbuild/shared-settlement boundary and root's coordinated heavy window.

