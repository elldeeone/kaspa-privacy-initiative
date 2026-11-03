# Ordinary TN10 mining feasibility

**Decision:** a small ordinary CPU-mining attempt is plausible. The measured local
rate is 1.789 MH/s on 14 workers; the sampled TN10 target requires approximately
3.234 million attempts per solution. This is a static-header estimate of 1.81
seconds per solution, not a measurement of accepted blocks or rewards. This was
the pre-execution feasibility decision. The subsequently released actual run is
recorded in [MINING-RESULTS.md](MINING-RESULTS.md).

## Observed and measured

- Both fixed public RPCs supported `getBlockTemplate`, reporting synced
  `testnet-10`, server 2.1.0, with an indexed UTXO set. `OBSERVATION.json` retains
  the bounded read-only observation.
- The known accepted public header recomputed to its pinned hash; its real nonce
  passed SDK PoW. The independently decoded compact target matched the SDK.
- One worker performed 100,000 checks in 0.410321131 seconds (243,712 H/s);
  14 workers performed 1,400,000 checks in 0.782724231 seconds (1,788,625 H/s).
  Matrix construction, SDK startup, template refresh, RPC delay, competition and
  DAG reward retention are excluded. The owned benchmark unit used 686,301,184
  bytes peak memory and was stopped and verified inactive.
- The actual template coinbase payload declared a subsidy of 291,352,351 sompi
  (2.91352351 test KAS). Its miner-data script matched the selected fresh public
  A script. Existing template outputs reward parent blocks; they are not proof
  of payment to the current miner.
- Default read-only `miner.mjs --mode plan` passed against the actual SDK/raw
  template shape. It did not construct PoW or start workers. `PLAN-RESULT.json`
  retains selected fields only.

`BENCHMARK-RESULTS.json` SHA256:
`f770be0a25d23553da5ae39bffd03ca62599eb8a4932a593e4b863f188a3f0b5`.

## Proposed smallest live attempt

The frozen `miner.mjs` uses the existing pinned Node and official SDK, 14 persistent
workers, and approximately one-second template refresh. It decodes the current
coinbase payload and requires the exact fresh A script. Workers cover disjoint
64-bit nonce sequences for a fixed job. Main independently checks returned work,
preserves the entire raw template except its nonce, and computes the finalized
header hash. A durable exclusive intent precedes the sole `submitBlock` call for
each unique hash. An unknown response causes a read-only block query; the same
hash is never submitted again.

Mine until current exact-script A coinbase UTXOs total at least 45 test KAS. The
sample subsidy implies about 16 retained rewards, but the retained yield must be
observed rather than assumed. A failed attempt or an operational interruption
must be reported as incomplete. Nothing here establishes privacy-trial readiness.

Coinbase maturity is 1,000 DAA on TN10 (10 blocks/second times 100 seconds).
After maturity, a separate reviewed A-owner operation must create ordinary
non-coinbase 21 KAS A and 21 KAS C outputs plus A refund. Mining itself needs no
wallet backup, private key, signing, daemon, GPU build, or new infrastructure.

The execution gate is **root acknowledgement of the exact frozen source** before
`--mode mine --execute`. Runtime files are readonly inside a filesystem sandbox;
only a dedicated output directory and persistent once-only journal are writable.
All eight owner-backup inode identities and whole owner directories are excluded
before public staging reads. No original owner path is mounted into the miner.

## Trust and limits

The selected public nodes' network labels, validation and full block templates
remain trusted. The miner checks work and binds its submitted bytes to the
received raw template; it does not independently reconstruct its transaction
Merkle root or prove the endpoint's genesis/consensus. A block RPC acknowledgement
does not establish an accepted reward. Exact current UTXOs, maturity, ordinary
consolidation and later payout confirmation are separate evidence requirements.

## Primary source pin

Official `kaspanet/rusty-kaspa` commit
`4edcbbccb449f84832afb1ca157904b35f37d006`:

- [TN10 parameters and 10 BPS](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/config/params.rs).
- [Maturity conversion](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/config/bps.rs)
  and [100-second constant](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/config/constants.rs).
- [PoW target and nonce check](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/pow/src/lib.rs)
  and [SDK PoW bindings](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/pow/src/wasm.rs).
- [Coinbase payload framing and parent rewards](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/src/processes/coinbase.rs).

The selected runtime inventory is
`a4442e933608f8cca58943846a25fb9c06c03c5128ce1044504329cbffbfc100`;
the exact selected source/SDK/Node/public-receipt pins are in
`MINER-SOURCE-01.json`. Miner source SHA256 is
`ea111e81c540f80399d729e77b9289e9c69902e711d22b9e96bc766c199d213a`.
