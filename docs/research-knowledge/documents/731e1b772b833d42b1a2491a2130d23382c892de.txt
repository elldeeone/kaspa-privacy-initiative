# Finite accepted-record recovery checker

**The17-control baseline, four impacted controls and both fresh private LOCAL
recipient checks pass.** The new standalone
[checker](../../../../poc/future-testnet/recovery_check.py) supports the exact
six-body trial and its pre-exit prefixes. It recovers a recipient using only
their seed-only backup and public records, authenticates current CM/NF data,
and independently checks actual payout keys/amounts plus terminal zero reserve.
It never loads a PK/prover, reads a payer profile, signs, broadcasts or calls RPC.

There is **no network-stage recovery or confirmed payout result in this packet**.
The tests use retained public DO_NOT_FUND offline native evidence with explicit
`LOCAL_SUPPLIED_CONTEXT`. Network claims require fresh accepted-node observations
from the separately reviewed adapter and a fresh private TN10 identity.

## Smallest runtime process

1. Retain the six exact accepted bodies/observations and the four ordered
   receipt ciphertexts/current physical NF entries. Founding and ADMIT publicly
   bind their receipts; Auth484 binds the actual two PRIVATE ciphertexts.
   Pin the canonical founding outpoint, selected trial/domain and exact lineage.
2. Before each recipient quotes or signs an exit, remove payer/prover/PK access.
   Mount only the public recovery identity, that recipient's older seed backup,
   retained accepted records, native executable and pinned crypto bridge.
3. Refresh the validating-node checkpoint/current reserve UTXO and call the
   checker with path-only stdin JSON. It verifies exact accepted bodies,
   predecessor links, immutable BLAKE2b32 P2SH/state and all public CM/NF update
   bytes before using V2 receipt decryption/derivation/current witness routines.
4. After both exits, obtain new accepted-body/UTXO observations for Bob's payout
   and Charlie's terminal payout. The checker compares both native output
   amounts/keys, requires the last reserve input spent and no terminal reserve
   successor, and verifies the selected seed owns its earlier revealed note
   with zero surviving owned pool liability.

The trusted validating node and complete archive are explicit assumptions.
This is a finite pilot checker, not a general wallet, public ledger replayer,
independent consensus proof, pruning recovery or durable-data guarantee.

## Evidence and checks

[Source contract](CONTRACT.md) specifies the accepted-archive/current-view and
path-only request schemas. The checker requires a secret-free public identity
and one precisely shaped seed-only backup. The selected bridge is hashed before
receiving any derived secret; network use also requires its pin from the public
recovery identity. It refuses the legacy domain/public trial classification
for network claims. Generic CLI errors never print malformed documents/seeds.

Independent review caught a historical10KAS amount constant before the first
run. It was replaced by strict `expected_payments_sompi[label]`, matched against
the exact decrypted positioned receipt. The new prospective TN10 liveness pilot
uses100M each; this suite explicitly retains the historical1B-sompi offline
controls. No100M payment is relabeled10KAS, and the old fee/privacy targets are
not qualified by the smaller pilot.

The [17-method suite](../../../../poc/future-testnet/test_recovery_check.py) checks:

- Both seed-only terminal recipients, true zero reserve/owned liabilities and
  current witnesses for both recipients before exit and Charlie after Bob exits.
- Missing ciphertext data, stale archive/current reserve, competing accepted
  spends, duplicated NF, Full-body substitution and changed payout amounts.
- Missing one final payout, wrong current payout UTXO, final reserve input still
  unspent, wrong backup/trial and changed expected amount under intact receipt/CM.
- Refusal to upgrade LOCAL evidence into network confirmation, removed accepted
  anchors, wrong node network, stale observations and changed pinned artifacts.
  Later distinct sinks are allowed because the DAG advances between RPC calls.

The first run retained16 passing methods and one environment error: the
temporary-artifact test could not create a temporary file under the read-only
sandbox root. [Attempt01](attempt-01/results.json) records17methods, one error
and exit1. The corrected launcher adds private tmpfs `/tmp` and separate
attempt02 output. Checker and tests are byte-identical; no validation or
expectation was weakened.

The independently reviewed baseline source/test SHA256 values, retained exactly
in `source-01/`, are:

```text
recovery_check.py       75cd17aa1501b9c9938077644c0f2c1318dc9d74c2d3c1955a544c8e6c2ab6e3
test_recovery_check.py  6e70220094228746f4a754e3bf60f990a40eeb45a1d668b1375ca59c6a3598c4
```

[Freeze02](PRE-RUN-FREEZE-02.json) closes15 source/input files, SHA256
`2f95d012443b4ee344b77218314f7ab7aad7403f2b08a3add8c03489029fd4f5`.
All hashes are checked before and after execution. The unchanged bridge is
external to Git, SHA256
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`.

[Attempt02](attempt-02/results.json), SHA256
`b5df0c46d53d6d6e5ec8b220a1b271c5036253b7d7854e08743760d01e835398`,
records17passes, zero failures/errors and no network/live-trial access.
[Both LOCAL verdicts](attempt-02/local-verdicts.json), SHA256
`db075ecc627cc2e0d8801affc97b04a4242443281647a31bbe476e24426c9bd0`,
report confirmed-with-node false. Mock RPC metadata in negative tests is not
an accepted-network positive result.

## Selected metadata release and actual private LOCAL integration

Before the first network invocation, independent review requested stricter
retained node metadata. The selected checker now requires explicit passing
confirmation policy, exact strict-greater comparison, coherent u64 blue-score
distance and matching accepting-header score. Final reserve absence must be
actually queried at its exact consumed SPK. Its NETWORK branch never uses the
new LOCAL-only wrapper for pinned native Full/isolation/all-engine records.

The updated result separates `both_payout_outputs_checked` from
`both_payout_utxos_reobserved`; the latter is false for every LOCAL result.
This prevents offline supplied outputs from being reported as real node UTXOs.
The prior source, inputs, failed setup and successful17-control result remain
unchanged in the archived packet.

The independently reviewed selected source/test hashes are:

```text
recovery_check.py       c9091b52c8562e30fa567095c2070a8c8845cfdb5c9578e5357aca156fe0677b
test_recovery_check.py  7e41698454484a8b4610f99c12ded4fdc35511d02d94dd29d79b4540204348df
```

[Freeze03](PRE-RUN-FREEZE-03.json), SHA256
`4d1d202d9c14ca3350b1d08fe6a7c8e522a35aae2b5cb7d0f9193e7bdbc87f4c`,
pins16source/input files. Only affected methods01/15/18/19 ran: **4/4passed**
in [delta result](delta-01/results.json). No unrelated17-method suite rerun.
These include false/inconsistent confirmation metadata and rejection of LOCAL
native validation as NETWORK evidence.

The complete path-only standalone checker then independently checked the new
private, unfunded LOCAL pilot from the harness. Bob and Charlie each used only
their own older seed-only backup/public recovery identity and exact six-body
archive. Both actual received notes are100,000,000sompi; native output payouts
are95,026,200 and95,036,800sompi, respectively. Both terminal owned pool balances
and the actual terminal reserve are zero. All actual body/state/ciphertext/NF
and output checks passed without any native, SDK, setup or proof rerun.

Those private requests/verdicts remain0600 under the private trial's
`recovery-checks/`, outside Git; no seed, profile, ciphertext opening or private
runtime packet is copied here. Both verdicts explicitly say LOCAL, network
confirmation false and reobserved network UTXOs false. This is a concrete
standalone integration result, not a testnet payout or chain-acceptance claim.

All checks use network isolation,2CPU/2GiB caps and swap0. Baseline measured
resources are retained in [run02](run-02-resources.txt); later resources/cleanup
record the small delta and standalone checks. All four units are stopped with
PID0 and empty/removed cgroups in [cleanup](CLEANUP.json). Fresh unfunded backups
were read for the explicitly authorized LOCAL integration; no funded state,
node RPC or broadcast was accessed by this lane.
