# Original-backup recovery after shared settlement

Research client for the selected ADR0058/0059 capacity profile. It replays the
actual W transaction and both ordered virtual children from public S0, scans all
V2 encrypted receipts using one original backup, and prepares a private no-append
cashout using up to two claims from that same backup. No operator receipt map,
other backup, saved index, outer prover or broadcast service is used.

`run_owner.py` consumes an independently selected software-inventory SHA and a
restored public runtime tree. It verifies the complete listed dependency bytes,
then mounts only 24 fixed source/runtime members, public history, one backup and
(for preparation) one read-only public PK file in a fresh network-off namespace.
Downloaded software does not select its own authority. The trusted host, Python,
system libraries and immutable installation remain assumptions.

- `recover` performs fresh public replay then scans the backup. It does not need
  PK material or a proving worker and cannot establish live spend authority.
- `prepare-full-cashout` requires whole selected PK/VK authentication and exact
  `parameters-ready` before the first backup byte. Its witness pipe stays empty
  through actual fee quotation; only the final candidate reaches the own prover.
- Own fresh quotes use B1500. Aggregate and virtual templates use B1600. Direct
  history accepts canonical native u16 budgets and requires fresh native Full;
  another owner's valid transaction is not rejected by our pricing preference.

Two-real cashout consumes two distinct recognized current positions, preserves
CM/cipher history, inserts both original NFs sequentially and pays
`sum(values) - actual_fee`. Any remaining reserve keeps the exact actual W
program. The established payout KDF uses the minimum consumed physical position
and rejects a retry matching either consumed real note's native key. Historical
recovery credits only an exact actual payout-SPK match, never inferred arity.

The supplied start is constructed and unfunded. There is no KPX4/KPX5 accepted-
chain discovery/currentness adapter. Byte integrity, local native Full and seed
recognition do not establish chain backing, fresh UTXOs, confirmed payouts,
cryptographic security, production privacy or a 2% fee qualification. Missing or
unsupported history fails incomplete. Emergency public REVEAL is not available.

Public-only controls run with:

```sh
python3 -B poc/shared-settlement-wallet/test_wallet.py
```

These use a separate explicitly unsafe public control seed. They do not read the
actor backups, PK, private witnesses or run private proofs/native Full. Execution
source selections and retained control snapshots live under
`research/next-session/independent-payments/settlement-wallet`.
