# Matched compact/wide native-KAS experiment

The new local experiment completed one ordinary GN entry, one genuine
`wide32` private payment, and **32 original-backup recipient withdrawals**.
Every selected body passed the official native Full validator and every input
engine with its exact supplied context. The last withdrawal returned the
remaining fee credit and left reserve zero.

This is **synthetic local evidence**. No transaction was broadcast. The supplied
UTXO contexts use explicitly synthetic DAA scores; they do not establish chain
acceptance, backing, currentness, human demand, privacy, production safety or a
testnet rehearsal with confirmed payouts. A later live trial requires a fresh
domain, both fresh parameter setups and fresh original backups.

## Exact result

| Item | Integer sompi |
|---|---:|
| Useful payments, 32 × 1,000,000,000 | 32,000,000,000 |
| Ordinary entry fee | 258,500 |
| Wide payment fee | 19,701,700 |
| Each of 31 continuing withdrawals | 18,867,700 |
| Terminal withdrawal fee | 18,718,200 |
| All entry/payment/withdrawal fees | **623,577,100** |
| Terminal fee-credit refund | 149,500 |
| Actual native payout total | 32,000,149,500 |
| Terminal reserve | **0** |

All fees are **1.9486784375%** of the fixed 32,000,000,000 useful-payment
denominator. The refund is not another useful payment. All selected actual-body
quotes use reference rate 100 and include the official mining/storage mass.
The original conservative projection remains separate.

The source reconciles exactly:
`42,623,726,600 = 10,000,000,000 ordinary change + 32,000,149,500 payouts + 623,577,100 fees`.

The 34-body history contains 33 genuine owner proofs. Its final sparse CM cursor
is 126, with 95 actual delivery records and 67 NF entries. Empty physical gaps
are not deliveries; terminal zero sentinels append no leaves.

## Components and boundaries

- `identity.py new --output NEW_PRIVATE_DIRECTORY` creates the original seed
  backups and public invoices for the selected local instance. It does not
  rotate the compiled domain or parameter setups. Files remain outside Git.
- `prepare.py init` constructs the strict singleton ordinary GN entry and the
  externally installed descriptor/role selections. `prepare.py append` appends
  only an exact already verified owner body and predecessor context.
- `run_owner.py NEW_CONTROLLER ... --execute` launches one fresh network-off
  namespace with one original backup, exact public history and one read-only
  role PK. The whole PK is authenticated and the selected READY record checked
  before the first backup-byte read. The witness has no role selector: the
  trusted CLI and selected public manifest choose `compact2` or `wide32`.
- `receiver.py`, `primitives.py` and `history.py` adapt the existing pinned V2
  receiver to sparse physical positions. They independently decrypt, rederive
  and CM-check the owner's receipt and derive its spent NF from public history.
  Strict singleton GN validation is necessary because an ordinary funding input
  does not execute the newly created output policy.
- `actions.py` shuffles wide output slots once, preserves exact ordered CM/CF
  pairs and fixes one immutable candidate before the actual quote and witness.
  `native_runtime.py` permits only proof substitution and the independently
  derived transaction ID after that quote.
- `run_closed_scan.py` / `scan_closed.py` replay the completed public prefix in
  a fresh original-backup-only namespace with no PK or prover. All 32 recipients
  recovered one spent receipt and rederived the payout secret/public key matching
  their exact selected native output. This does not execute a payout spend.
- `closure.py` independently reconciles finite selected bodies, native/prover
  reports, all 33 quote IDs, exact fees and sparse state without reading any
  backup, controller map, private witness or PK. Recorded reports remain trusted
  experiment evidence; the collector does not recreate their executions.

Source reuse and the two actual fresh VKs are recorded in the native source
receipt, ADR57 and the prover's circuit-obligation documentation. The native
policy preserves the existing checks and original real-NF derivation across
compact, wide and retained revealing exits. Passing these controls is not a
proof of cryptographic correctness.

## Selected evidence

The finite publication list is
[`PUBLIC-SELECTION-01.json`](../../research/next-session/compact-batch/lifecycle/PUBLIC-SELECTION-01.json).
Its main summaries contain selected opaque proof/Auth hashes and financial
effects. Raw main bodies, Auth/NFs, histories, quote alternatives, backups,
private witnesses, ownership maps and PKs remain outside Git.

The separate deterministic public canaries establish three genuine role/mode
Native Full positives, two foreign-role/statement proof-transplant rejections,
and a genuine private-SAT proof rejected by the retained native next-CM-root
check. Those canaries retain fee 1,000, which fails reference-rate-100 fees; they
are interoperability controls rather than economic qualification. The foreign
proof transplants are not isolated wrong-VK-only curve tests.

Run the small local controls from this directory:

```sh
python3 -B -m unittest test_primitives test_actions test_scan_closed test_closure
```

These controls use deterministic public fixtures. The real-crypto state test
does not invoke a prover, a native validator, a node or a network broadcast.
