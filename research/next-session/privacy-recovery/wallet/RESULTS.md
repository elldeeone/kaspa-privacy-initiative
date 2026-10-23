# Receiver wallet implementation checkpoint

**Actual refetch/receiver reconstruction passes:** one-backup receiver recognition
over independently fetched and replayed public data. The client has no network
or broadcast interface. Its native
revealing fallback now selects the separately reviewed generic native helper by
complete compiled binary identity; a caller or descriptor cannot replace that
expected digest.

The client itself invokes public replay from the descriptor and fetched data;
it does not accept an operator-supplied snapshot or expected-payment map. A
separately user-selected canonical descriptor digest is mandatory before seed
read. The immutable V2 source and crypto bridge are checked against software
pins, rather than hashes supplied by the descriptor or RPC response.

## Executed controls

The [frozen component run](controls-01/RESULTS.json) passes **28/28 controls** in
1.180 seconds of tests /1.268 seconds of service runtime, with swap zero. Its
network namespace is isolated and no private controller, funded seed backup,
prover or PK is mounted. Tests use source-labelled public synthetic seeds and
real supported sealed-box/libsecp operations. They are not a network recovery
or a native exit result.

Controls cover recognized receipt/current NF/witnesses, wrong seed without a
universal zero-balance claim, duplicates preserving all owner actions, missing
history/ciphertext/current reserve, wrong current root/policy/domain, exact
historical versus current native payouts, later legitimate native spends,
unqueried/duplicate/substituted payouts, integer types, software pins, mandatory
reveal consent, user descriptor pins before seed read and private-file paths.
Independent review caught an existing-file Git-probe bug; the fix probes the
file's directory after link rejection and lexical normalization. Separate
controls reject another Git worktree and `..` aliases. JSON duplicate fields are
also rejected, including nested descriptor and disclosure-consent fields.

Earlier development checks passed20 base and6 payout/pin controls; two explicit
duplicate-JSON controls were then added. The28-control source-frozen run exercises
the actual isolated runtime. No statistical privacy score, accepted chain,
latency percentile or aggregate-wallet qualification follows from those tests.
The exact executed source/input map and cleanup are retained next to the result.

After selecting helper SHA256
`a4c5da2c94691ba39ca9f5be1279b3243a0328481f9ba795e812483c770e1186`, two
additional component checks pass with real native execution: continuing and
terminal revealing exits reconstructed from current state, at rates100 and500.
Both use only public synthetic fixture credentials, require explicit disclosure
consent, construct a fresh Schnorr `ALL` signature and pass actual native Full
and every input engine. No domain-specific factory, PK, saved signature or
broadcast is used. Those checks take0.244 seconds in the development runtime;
their actual isolated-runtime run is retained separately below.

The [second frozen isolated component run](controls-02/RESULTS.json) now passes
all30 controls, including those two real native Full positives, in1.372 seconds
of tests /1.456 seconds of service runtime, with swap zero. The native helper is
read-only mounted; no private funded backup, controller, prover or PK is mounted.
The earlier28-control source/result remain unchanged.

## Actual one-backup network reconstruction

[Two separate receiver processes](network-01/RESULTS.json) consume the same
user-selected canonical descriptor plus independently fetched live data from two
distinct RPC endpoints. Each client **calls public replay itself**; neither
receives a replayed snapshot, intended payment amounts, owner labels or a fixed
operation list. Discovery has already followed the selected founding outpoint
and raw chain activity. The source/runtime freeze is independently reviewed.

Each process mounts exactly one root-authorized old seed-only backup. It mounts
no old operator archive/testtree, private controller profile, payer or other
recipient seed, prover, PK or native signer. Network is isolated. The two current
native payout totals recognized from the respective backups are **95,026,200**
and **95,036,800** sompi. Each recognizes one historical spent receipt; the
replayed pool has zero reserve and the wallet has zero recognized unspent pool
principal. Both exact native payouts are still present in the independently
queried UTXO views. No new signature or broadcast occurs.

Recorded whole wrappers take0.168 and0.157 seconds; GNUtime driver peaks are
29,488 /29,376 KiB, and swaps are observed zero. The requested limits are2CPU /
4GiB /swap0; no live cap sampling was retained for these short runs, so actual
enforced cap values are not claimed. Both units are collected/inactive/PID0.
These timings exclude network acquisition and software/history installation and
do not qualify the10,000-operation/reference-device recovery target.

This closes operator-archive dependence **for this available historical terminal
trace**. It is not a newly generated unspent-claim exit. The selected-node,
retained-data and user-authenticated-descriptor assumptions remain. The generic
client independently rechecks public hash/state relations; Groth16 and signatures
inside these owner processes retain the validating-node premise. A separate
public replay workstream executed native Full on the same five fetched pool
bodies, without private keys or PK.

## Data and privacy boundary

Totals are **recognized correctly encoded receipts only**. The current circuit
binds ciphertext bytes but not their correct encryption; foreign ciphertext and
a maliciously undeliverable owned note cannot generally be distinguished by
failed decryption. No-recognized-receipt is therefore not proof that every
conceivable owned liability is absent in an ongoing pool. A validated terminal
zero reserve is a separate all-pool-liabilities condition.

The client distinguishes a historical payout from a still-unspent queried
native payout. It does not claim a general native-wallet balance. Orphan-only
disclosures and invoice issuance state are not recovered from accepted data.
The node/retained-history assumption remains explicit; this is not independent
consensus or durable DA.

## Remaining integration

1. Prepare a new unspent claim's
   exact native body only after explicit revealing consent, with mass-derived
   fee, Schnorr `ALL` and native Full validation. No precomputed exit is needed.
2. A separately controlled fresh testnet rehearsal must confirm that newly
   generated payout; historical terminal reconstruction cannot claim it.
