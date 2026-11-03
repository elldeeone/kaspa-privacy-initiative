# Chain acquisition and submission review

2026-10-25 UTC. Public-source static review only. No funding, broadcast, private
artifact access, attack reproduction or runtime-author edits were performed.

No confirmed financial authorization or value-conservation blocker was found in
the reviewed acquisition, preflight, submission and confirmation paths.

## Checked boundaries

- Acquisition retains complete Full pages, their hashes, populated input
  contexts and canonical transactions including witness and compute budget.
  Offline verification reconstructs locators and graph edges from retained
  pages, rather than accepting transaction IDs or stored success flags alone.
  The later financial/native replay remains mandatory.
- Fixed-frontier coverage, removed-block rejection, exact current UTXO queries,
  post-query delta scans and final UTXO requeries detect the represented stale
  and reorganization cases. A terminal candidate comes from the accepted direct
  exit body and actual payout layout; it is not an empty-query inference.
- Preflight invokes the selected native engine, normalizes only ID/storage mass,
  requires actual Full plus every-input script acceptance and exact reference
  fee, and binds a lifecycle candidate to replayed old state/outpoint/reserve.
  Fee qualification must precede the Spend/effects digest. The known low-fee
  component fixture is not Native Full or testnet readiness evidence.
- Submission queries all exact input contexts twice, with durable stage and
  global transaction-ID reservations between queries. Reservations use exclusive
  creation and file/directory fsync before the one submit RPC. Unknown responses
  permit reconciliation only. Global transaction-ID reservation also covers a
  changed witness/budget sharing a v1 transaction ID.
- Official SDK clients receive the bridge's explicit loopback URL, reject a
  configured resolver, check that exact URL before and after connection, and
  check testnet identity before application use. The bridge forwards one local
  session through explicit SOCKS5h and verified TLS, stops listening after that
  session and has no direct connection or upstream retry path. The supplied
  SDK is an externally pinned dependency; its internal connection-strategy
  semantics are not independently proven by this source inspection.
- Confirmation requires the expected transaction ID within retained accepted
  history, exact whole-CASE equality with an externally pinned expected CASE,
  actual financial/native replay and exact payout UTXO observation. It does not
  equate a mempool acknowledgment with confirmation.

## Evidence limits

The selected validating node's accepted-history and populated-context reports
remain an explicit trust assumption. Header/transaction reconstruction and
retained pages do not prove PoW, transaction inclusion, independent consensus,
independent administration or continuous currentness.

Review identified a submitted-versus-accepted evidence gap in the earlier
ID-only confirmation interface: Kaspa v1 IDs omit witness and compute budget.
The author added required expected-CASE path/hash inputs and exact comparison of
the accepted witness, compute budget, contexts, ID and storage mass before replay.
The updated source was reviewed. This closes the source-level claim gap; actual
confirmation execution remains separate evidence.

Current-view queries derive scripts from the complete public pool graph. They
do not receive view keys, private note indices or an owner-specific private scan
selector. Tor does not establish global traffic privacy or hide the public pool,
transaction grouping, fees or transparent payout scripts from the endpoint.

The accompanying `CHAIN-HISTORY-SOURCES-01.json` retains the first public source
snapshot; `CHAIN-HISTORY-SOURCES-02.json` records the reviewed confirmation and
explicit SDK resolver/URL checks. No execution, confirmed payout or fresh-fixture
acceptance is claimed by this review.
