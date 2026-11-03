# Whole native CASE and accepted-prefix adapter

All RPC uses the official pinned SDK over `rpc.mjs` → a fresh single-session
loopback bridge → established Tor SOCKS5h → TLS testnet-10 peer. There is no
resolver/direct route fallback. Read-only peer failure may try another Tor peer.
Network identity is checked before mining/submitting. Witnesses, seeds and scan
indices never enter RPC; public NF/grouping/timing and transparent exits remain.

- `anchor.mjs`: recent confirmed birth anchor. `fetch.mjs`: retain complete Full
  accepted pages and post-query reorg/race checks from that anchor. `verify_bundle.mjs`
  independently recomputes header IDs, exact witness/budget/context locators,
  transaction IDs and current point observations. Matching txid alone is insufficient.
- `replay.py`: strict3×genuineOutput520 genesis, deterministic CV20/native60KAS,
  exact wholeCASE native Full for every transaction, new native projection,
  genuine component history/state/balance checks, exact actual current reserve.
  It emits role-free `HISTORY.json`, `CONTEXT.json`, current UTXO and bounded result.
- `preflight.py`: actual exact native Full and100sompi/mass quote. Lifecycle mode
  requires complete accepted-prefix replay and exact current head/state/reserve.
- `submit.mjs`: default preflight only. `--execute` verifies two exact live input
  queries around durable trial/stage and transaction reservations, then performs
  one submit RPC. Unknown response consumes that submission; reconcile read-only.
- `confirm.py`: fresh Full acquisition and replay, required expected wholeCASE and SHA (including witness, budget and populated contexts),
  exact actual payout UTXO amount/script/outpoint, zero reserve at terminal exit.

CLI help is available through Python `--help`; `submit.mjs` requires explicit
`--mode --stage --trial-id --selection --selection-sha256 --case --case-sha256
--output --journal`. Lifecycle mode additionally requires externally pinned
`--assets --assets-sha256 --parameters --parameters-sha256 --codec --codec-sha256
--descriptor --descriptor-sha256 --fetch --fetch-sha256 --bundle-directory`.

The selected validating node and retained finite confirmed prefix are explicit
trust assumptions. These checks do not prove independent consensus, continuous
currentness, general anonymity, cryptographic correctness or production safety.
