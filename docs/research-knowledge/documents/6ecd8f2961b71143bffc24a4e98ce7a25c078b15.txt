# Ordinary1600 qualification: passed; factory remains1700

The prospective ordinary1600 commitment passed the four genuine public cases,
28 synthetic boundary contexts and45 exact typed reserve rejection controls.
The unchanged paired1700 body also passed. No policy default or security guard
was changed. This packet supports a separate reviewed adoption decision.

| Genuine ordinary case | Reserve units | Input1 units | Mining mass1600 | Required fee at200 | Actual fee |
|---|---:|---:|---:|---:|---:|
| Bootstrap |14,972,602|—|190,511|38,102,200|40,000,000|
| ADMIT |14,929,160|100,001|191,631|38,326,200|40,000,000|
| SPEND fork0 |14,969,743|—|190,511|38,102,200|40,000,000|
| SPEND fork1 |14,969,321|—|190,511|38,102,200|40,000,000|

For all32 ordinary positive contexts, both1700 and1600 passed official native
isolation→Full and actual per-input VM metering. Changing only input0's typed
ComputeBudget reduced compute mass by exactly10,000. Every other transaction
field, contextual UTXO, redeem/SPK, authorization, proof, cipher, output, cached
and recomputed transaction ID, SIG_HASH_ALL and storage commitment remained
exact. The full transaction hash deliberately changed. Actual work units stayed
the same. These are operational budget changes, not faster cryptography.

All measured ordinary1600 bodies cover rates100 and200 at the unchanged40M fee.
Rate500 still requires95,255,500 (bootstrap/SPEND) or95,815,500 (ADMIT), and fails.
The paired body is byte-identical to retained history: budget1700,15,653,862
units,26,114 estimated bytes, mining mass196,484, fee80M. Its rate500 requirement
98,242,000 still fails. These are fee scenarios and a separate source-adapted
mass/standardness/default-relay screen, not actual mempool admission calls.

The independently reviewed [source bound](SOURCE-BOUND.md) is15,857,502 reserve
units for every successful ordinary source branch under its exact assumptions.
Budget1600 allows16,009,999, leaving152,497 units above that conservative bound.
The highest measured boundary reserve cost is14,970,643. ADMIT's funding input
has a separate budget and100,001-unit meter; it is outside that reserve bound.

The28 boundary contexts use the unchanged genuine ADMIT and two SPEND proofs.
They cover sentinel/first, middle and tail insertions, all five little-endian
comparison limbs, mixed lower limbs, predecessor index127/128 and32767/32768,
and near-capacity counts. SPEND n65533/m131064 reaches n65535/m131066; ADMIT
n65533/m131066 reaches n65535/m131066. No case was dropped or reduced. A full
linked-list consistency check and retained historical CM-prefix/anchor check
precede native execution. These are synthetic prior public states, not claimed
accepted ancestry or verified native KAS backing. Synthetic ADMIT signs its
new context using the published DO_NOT_FUND fixture derivation only; no private
wallet file, setup or new zero-knowledge proof is used.

The17 genuine-case negatives require canonical proof-A pairing failure and
below-measured-minimum meter failure on all four cases, plus exact VerifyError
for domain, stale cipher-hash and output-minus-one changes on the three
single-input cases. ADMIT payload/output mutations are excluded to keep its
original funding signature. The28 boundary negatives require wrong historical
anchor-path VerifyError (SPEND) or canonical proof-A pairing failure (ADMIT).
Every negative passes isolation and requires the exact Full SignatureInvalid
and matching direct reserve TxScriptError. The separate budget65535 control
passes Full and the reserve VM, then fails the native mass-cap screen with
`native block mass limit`; it cannot stand in for a script rejection.

The prospective design/control notes were frozen before execution. The first
build failed on two checker wiring errors (missing derived-count binding and
Vec versus105-byte array); source snapshots and logs remain. The corrected
source built offline in6.39s. Actual execution took approximately0.19s inside
the auditor (241ms service), with25,612,288B peak memory. Boundary execution took
4.995s (5.053s service), with131,407,872B peak. Both used zero swap under2CPU/3GiB
owned units. Input and binary hashes were unchanged before/after. All owned
units are terminal and all recorded PID/start identities are gone; see
[cleanup](cleanup.json).

The namespace sampler matched the bwrap command before checker namespace
creation, so its saved mountinfo is an outer-namespace sample and does not
independently demonstrate checker mounts. The raw record and additive
SAMPLER-ERRATUM files retain this limitation. The frozen bwrap command uses
read-only binary/input mounts and a disjoint dedicated writable output mount.
No repeat was run solely to improve sampling.

DRAIN remains source-bound-only in this fresh profile. The two actual SPEND
forks are independent alternatives against the same predecessor, never a
combined ledger. This work introduces no owner CLI, public replay, exit
workflow, new proving, RPC/broadcast or funds, and makes no privacy, production
safety or accepted-chain claim. Factory1700 and all historical packets remain
unchanged.

## Frozen identities

- Native revision:01b532e8b553523216471682649693af92f0fd16.
- Unchanged S7 policy source SHA:7df243d9b94224e464cd2b49f60cbcce24b0ae2db649c89d7241fd3cdde689cb.
- Checker source03 SHA:b40cd60a1f128992ec35f248139242528ee3bf493b07930462afa43885f134cd.
- [Source freeze03](source-freeze-03.json) SHA:2a7e81098eeb4c5446ca5a7a7c44ce0b5ca198cb9826b9e33aa297733473581a.
- Binary SHA:a5540f0ff3566cbfb16b448330074b413ed94955080372c67c2e9cb37e4ab05e (hash-only external build product).
- [Public input](public-input.json) SHA:1dd639067a871e025e01dbc6493fd4d46814615baf7d73c650caf4d4e717bbb7.
- [Actual report](actual-01/results/report.json) SHA:23aa712b2fb763085341dcfbf9927557dff4bf28a2dea932dc436b4096b32a85.
- [Actual stage manifest](actual-01/MANIFEST.json) SHA:b90acc9fa71ee1e87de1bc88f72ed34d991eb89b58bf0b9a3f8b3c09354ca71a.
- [Boundary report](boundaries-01/results/report.json) SHA:b19c0dcf1b6c82a9e9b5a4a9d5c8bbd11468799e26b28fa2daf61fdbfff5a62d.
- [Boundary stage manifest](boundaries-01/MANIFEST.json) SHA:a747ec92776879b99ed578c7d999c884e6bc9bfe90c74b68b680873016cfc8c3.

## Reproduction

Build source-03/Cargo.toml offline with frozen Cargo.lock, Rust1.95.0, explicit
x86_64-unknown-linux-gnu target, release, -j2, feature s7-native-policy and bin
kpi_s7_ordinary_budget_qualification. The retained build wrapper shows exact
read-only source and cache bindings. The main purpose-built checker is also at
poc/shared-pool/src/bin/kpi_s7_ordinary_budget_qualification.rs.

Run `checker public-input.json NEW_OUTPUT actual`, then a separate
`checker public-input.json NEW_OUTPUT boundaries`. Output directories must not
exist. [run-qualified.py](run-qualified.py) supplies the binary-only offline
sandbox and resource observation. No new proof generation is needed. Do not
interpret public supplied UTXOs or synthetic contexts as chain acceptance.
