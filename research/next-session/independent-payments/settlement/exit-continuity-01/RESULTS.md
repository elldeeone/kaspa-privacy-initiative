# Ordered wrapper and private-exit closure

**PASS in constructed supplied contexts.** The exact accepted wrapper output
`14a3ec5f…:0` is consumed by the first private exit `7587e506…`; its reserve
successor is consumed by terminal exit `b01dbc8b…`. Both fresh public private
proofs verify under current VK074c. Independent public checks reproduce the
actual current outpoints, states, strict sequential NF updates, immutable W
program, noappend CM carry, payout destinations and integer balances.

| Action | Native payout, sompi | Fee, sompi | Remaining reserve, sompi |
| --- | ---: | ---: | ---: |
| Two-action wrapper | 0 | 18,508,000 | 3,981,492,000 |
| First owner exit | 1,973,722,800 | 17,023,200 | 1,990,746,000 |
| Terminal owner exit | 1,973,765,100 | 16,980,900 | 0 |

`4,000,000,000 = 3,947,487,900 payouts + 52,512,100 fees + 0 reserve`.
The CM cursor stays6; NF count advances5→7→9. Each selected isolated owner
execution consumes two claims from its own backup. Each post-drain recovery
receipt reports three historical claims spent, zero unspent claims and one
controlled payout key. These ownership/count assertions are evidence from the
selected isolated executions and frozen source; public proofs do not disclose
owner identity or real-input-slot counts.

The [result](RESULTS.json) and [nine rejection controls](CONTROLS.json) passed
under2CPU/3GiB/swap0 in959ms service time,983ms CPU and45.1M rounded memory
peak. Controls include stale/reordered exits, report/fee/count tampering, a
coherently re-IDed wrong destination and a genuine proof from the other exit's
state. They are public checker controls; copied native reports for mutated
cases are explicitly not new native observations. No native VM or prover was
run by this join, and no backup, seed, witness, private controller or PK was
read. Earlier actual Native Full observations remain externally pinned inputs.

The fee is2.625605% of the declared2,000,000,000sompi synthetic reciprocal
invoice principal, before unperformed entry fees. It already exceeds2%.
Native payouts also return sender change and fee credit; those are not counted
as additional useful payments. This is no accepted-chain backing, currentness,
complete lifecycle fee, financial privacy or testnet readiness qualification.

Review caught an incompatible child-only constructor assumption before
execution. Its [unexecuted preimage](retained-before-W-adapter.py) is retained.
The new adapter pins the exact W tail and its two equal compact VK operands;
the frozen old public policy, native code and original91-file packet remain
unchanged.
