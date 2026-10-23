# Fresh unspent recovery: both native payouts confirmed

Two separate cold clients recovered their current claims from one own seed-only
backup, the user-pinned minimal descriptor and fresh independently fetched raw
chain data. Each constructed a new native REVEAL without the operator archive,
private profile, payer/other receiver seed, proving key, prover or precomputed
exit. Root submitted each new body once and confirmed its payout.

| Controlled role | Recognized unspent claim | New exit fee | Confirmed native payout | Derived position |
| --- | ---: | ---: | ---: | ---: |
| Bob | 60,000,000 | 4,973,800 | 55,026,200 | 2 |
| Charlie | 60,000,000 | 4,963,200 | 55,036,800 | 3 |

Amounts are integer sompi derived by the cold clients, not an operator expected
payment map. Bob's new transaction is
`043b8919e6c582232479e09f3fd3f553259754c031fe9c204eeacecbe176f060`
(payout1); Charlie's is
`c39d0ca13d326ee3da7f2199b6702e566c429cb827f06bdc42ac306f802b6ca1`
(payout0). Each owner read its own backup once. Recognition, current witness
construction, native mass quoting, new ALL signing and exact-effect/Full checks
completed in wrapper wall times of 0.276 s and 0.272 s on the preinstalled runtime.
These are observations, not cold-install, reference-device or p95 qualification.

The [separate final public closure](../unspent-terminal-01/RESULTS.json) uses a
third fresh descriptor-only fetch after both confirmations. It validates all five
pool transitions with native Full, reconstructs 4 CM/5 NF and terminal reserve 0,
and freshly queries both payout UTXOs as unspent. No seed is read in that final
closure. A changed transcript using the original curve proof reaches and fails
Groth16 in each public replay. Supplied contexts and selected-node acquisition
remain distinct from independent consensus.

## Evidence

- `SOURCE-READY.json`, both runtime freezes and exact launch/exit receipts bind
  reviewed unchanged v1 source/helper, actual inputs and the single-backup mounts.
- `bob-cold-client/` and `charlie-cold-client/` contain only public result,
  metadata, resource and cleanup reports. Signed bodies/context remain outside
  Git in mode 0600 files under mode 0700 directories; no backup bytes/hash or signing secret
  is published.
- `bob-public-replay/` and `charlie-public-replay/` validate their distinct raw
  network inputs before owner processing. Charlie observes Bob's new head and
  nullifier state; it does not reuse Bob's fetch.
- Live cgroup receipts observe 2 CPU / 4 GiB / swap 0 for each cold signer and
  2 CPU / 6 GiB / swap 0 for public native replay. Every unit is collected, inactive,
  dead and has MainPID0.
- Seven mocked orchestration controls pass. The previously closed 30 wallet
  controls and helper controls remain unchanged; passing them is not a proof of
  cryptographic correctness.

## Boundary

This closes the measured funded unspent operator/prover-independent recovery
and payout rehearsal. It relies on the separately authenticated canonical
descriptor, selected validating nodes, retained public history, preinstalled
approved software and correctly encrypted recognizable receipts. An ongoing
pool's recognized total does not prove that maliciously undeliverable owned
liabilities cannot exist. Orphan disclosure/invoice issuance state is not
recovered from the seed alone.

Root explicitly consented before either seed read to public note/value/CM,
positioned nullifier credential/key and payout-key disclosure for these newly
generated test roles. These revealing exits do not qualify financial privacy or
the complete-fee target. Their two fees total 9,937,000 sompi; that is not a complete
lifecycle fee measurement. The proof-private exit prototype remains a separate
experiment. No mainnet, production-safety, independent-consensus, durable-DA,
fresh-machine or 10,000-operation qualification is claimed.
