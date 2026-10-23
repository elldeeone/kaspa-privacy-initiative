# TN10 finite adapter findings

Read-only primary probe confirmed a synced UTXO-indexed TN10 node reporting
server2.1.0, FullV2 acceptance support and100sompi/mass fee buckets. Exact response
is `probe-01/public-network.json`; virtualDAA603993714 at observation. Primary is
`wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh`. LAN
`ws://10.0.3.26:17210` was reachable/synced/indexed but reported2.0.0, so it is not
selected for this pinned2.1.0 rehearsal. No local node was installed or started.

Neither endpoint retained the genesis block. Expected genesis
f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370 is pinned to
TESTNET_PARAMS. Remote network/version assertions remain trusted, not a
binary/header-chain attestation. Official2.1.0 source has no extra Toccata
activation threshold; see sibling confirmation/ACTIVATION-V2.1.0.md. Source
compatibility is not evidence that this fresh Groth16 union ran on chain.

A second read-only FullV2 shape probe returned70 matching added-header groups.
Actual Full populated input keys were amount/scriptPublicKey/blockDaaScore/
isCoinbase/verboseData/covenantId. Both mass/storageMass aliases and zero legacy
sigOpCount are exposed. New adapter normalizes only these documented aliases.
All other transaction fields and actual input value/SPK/coinbase/covenant are
checked. Future native blockDAA placeholders are not predictions; actual scores
are retained separately.

Development checks:16 transport/mock checks passed; no consensus engine or
broadcast was run by those checks. They include full-width sequenceMAX, exact
native serde→SDK→safeJSON roundtrip, SPKversion0, actualFull context/witness,
strict >20 accepting-block depth, current payouts/input spentness and reorg
removal. Python integer/SPK boundaries and JS syntax pass. First development
attempts exposed SDK requirements for deprecated sigOpCount0 and populated
client UTXOs; both were fixed before any fresh six-body roundtrip/release.

No private key, secret profile or wallet workflow was read by this adapter.
No funding or submission has been performed. The actual pilot is a distinct
fresh private TN10 identity; old public DO_NOT_FUND identities/artifacts are
rejected for submission. This stage is a small-payment liveness trial; it does
not alter the sealed40KAS offline fee qualification or establish privacy/security.
