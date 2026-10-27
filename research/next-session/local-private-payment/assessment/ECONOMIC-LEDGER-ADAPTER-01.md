# Final public ledger extraction interface

This adapter is separate from the frozen9-file economic observer selection. It
does not change either observer, policy or test. It reads no private plan, wallet,
owner log, truth or ownership map. Its only data inputs are externally selected
terminal public HISTORY, final accounting RESULTS and the19 whole native CASEs
selected by that accounting result. No actual final data was available during
development or synthetic testing.

The fixed accounting contract is `kpxa-independent-public-final-accounting/v1`.
Its `actual_native_Full_reports` selects three ordinary CASEs followed by16 pool
CASEs: GEN3, six payments, nine exits. Each row supplies public transaction ID,
CASE path/hash and integer actual fee. The independent accounting process joins
these to the retained validating-node FULL prefix and native Full verification.
The adapter does not rerun a node/SDK/native verifier or independently establish
accepted-chain authority.

The adapter independently recomputes all19 fees from CASE input entries minus
actual outputs; checks the three ordinary-to-GEN3 inputs; matches GEN3 payload
output tuples and60-KAS reserve to HISTORY; reconstructs the initial occupied
CM prefix/NF sentinel; serializes the15 actual CASE native-effect prefixes and
payloads; and requires exact equality with HISTORY projections. It follows the
reserve outpoint, state, policy SPK and amount lineage, verifies public CM/NF
paths, joins each direct Exit proof/payout/fee, and requires the same terminal
zero-reserve CM15/NF16 checkpoint. The external ordinary and GEN3 fees remain
separate from the private-note ancestry equation. Exit `payout_sompi` is the native
payout; the observer adds `fee_sompi` once to recover the exited note's gross.

Output is strictly `kpxa-public-economic-ledger/v1`:

```text
schema: "kpxa-public-economic-ledger/v1"
terminal: true
terminal_reserve_sompi: 0
genesis[3]: {cm_hex32, position:0..2, value_sompi:2000000000}
payments[6]: {action_id_hex32, event_index, nf_hex32,
              outputs:[{cm_hex32,position}, {cm_hex32,position}], fee_sompi}
exits[9]: {action_id_hex32, event_index, nf_hex32, payout_sompi, fee_sompi}
```

All amounts/positions are exact JSON integers, with bool/float/string rejection.
The total event indices are0..14; public payment append positions are3..14.
There are no destination addresses, owner labels, role labels, intents, target
amount schedule or private filenames in this ledger. The provenance sidecar
records only selected public source/data hashes and explicit authority limits.

Before running, Root must select the final HISTORY/accounting pins and the
published wire source. Authenticate the frozen observer selection unchanged.

```sh
python3 -B poc/local-private-payment/privacy/economic_ledger_adapter.py \
  --history PUBLIC_HISTORY --history-sha256 HISTORY_SHA256 \
  --accounting PUBLIC_ACCOUNTING_RESULTS --accounting-sha256 ACCOUNTING_SHA256 \
  --wire PUBLIC_WIRE_SOURCE --wire-sha256 WIRE_SHA256 \
  --observer poc/local-private-payment/privacy/economic_linkage.py \
  --observer-sha256 f861537240593dfda94fccd499ab802f2f3bbe23a52d6d4c4219e81b97d60641 \
  --output NEW_PUBLIC_ECONOMIC_LEDGER --provenance NEW_PUBLIC_PROVENANCE
```

The CLI reads selected public bytes through guard09 and imports only authenticated
wire/observer source. It refuses output replacement. Then select the output hash
for both unchanged observer CLIs with their respective policy pins. Actual runs
wait for the complete terminal public ledger; synthetic adapter tests use invalid
proof bytes and fabricated Full-report metadata and establish only consistency
checking, never financial or chain acceptance.

GEN3 header bytes72:88 contain the public trial UUID, as specified by
`bootstrap/GENESIS-SPEC.json` and `gn3.decode_payload`; they are joined to the
accounting trial ID. Deposit/fee amounts are checked from public history and
whole CASE effects, not interpreted from the UUID bytes.

```sh
cd poc/local-private-payment/privacy
python3 -B -m unittest -v test_economic_ledger_adapter
```
