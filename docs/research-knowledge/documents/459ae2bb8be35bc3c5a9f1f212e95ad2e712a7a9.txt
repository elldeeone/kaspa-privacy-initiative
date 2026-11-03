# Independent future-format exit cost review

**Arithmetic ACK.** All60 exact prepared public bodies independently reproduce
size, compute, transient, storage, fee and payout fields. All45 fee-agility
histories reproduce the least-fee fixed point or the correct50M-cap stopping
condition. I rehashed all191 members of pre-execution freeze02. No native VM,
Full validation, proof or funding was run by this reviewer.

| Prepared profile | Rate100 passes | Rate200 passes | Rate500 passes |
|---|---:|---:|---:|
|15 fixed50M-fee bodies|15/15|15/15|2/15|
|45 fee-agility bodies,15 per rate|15/15|15/15|6/15|

The fixed50M results remain intact. Cheaper fee-agility bodies are new
owner-signed authorizations with different payouts/payloads, not revised quotes
for the old bodies or repriced SNARKs. For example, continuing60M remainder at
fee50M/payout10M has storage108,333 and fails500; its lower-fee body below passes
because its larger payout reduces storage.

| Rate500 candidate | Actual fee | Payout | Mining mass | Economic result |
|---|---:|---:|---:|---|
|Terminal, minimal5,979B redeem|14,318,500|45,681,500|28,637|Pass|
|Terminal,32,768B envelope|35,066,000|24,934,000|70,132|Pass|
|Continuing60M remainder, minimal|15,369,000|44,631,000|30,738|Pass|
|Continuing60M remainder,32,768B|35,119,000|24,881,000|70,238|Pass|
|Continuing20M remainder, minimal|45,647,500|14,352,500|107,174|Fail: next fee53,587,000|
|Continuing10M remainder, minimal|0|60,000,000|102,381|Fail: next fee51,190,500|

The high-index65536 fixture has the same economics as the60M-remainder case;
its source assumes60M donation surplus, not another fee denominator. Every
49,152B envelope fails500 before any feasible fee: transient normalization
alone is102,900 terminal or103,006 continuing, requiring51,450,000 or51,503,000.
These are economic failures, not predicted native script rejection. Some failed
agility bodies correctly remain at fee0; they do not satisfy default relay.

Independent accounting uses native01b532e integer rules:
`E=94+54+signature_bytes+sum(18+rawSPK_bytes)+2029`,
`C=E+10*sum(2+rawSPK_bytes)+20000`, `T=4E`, and
`M=max(C,2E,S)`. Every positive has one p1 P2SH input, budget200, no covenant IDs
or external input. The canonical signature script is65-byte SIG_HASH_ALL plus
push prefixes and the exact redeem: length=redeem+69. Payout is canonical
34-byte P2PK; a continuing reserve adds35-byte P2SH. Thus minimal terminal
E8277/C28637 and continuing E8330/C29060 independently match preparation.

Storage is exactly
`S=max(0,sum(floor(10^12/output_value))-floor(10^12/R))` here: the one-input
relaxed path applies and all pluralities are1. Every body satisfies
`60M=payout+fee`, `R-output_sum=fee`, and any surviving reserve is exactly
`R-60M`. Fee/payout u64LE fields in the2029-byte payload match actual outputs.
No rent, sponsor, unrelated principal or change enlarges the60M denominator.

Since M(f) is nondecreasing as payout60M-f falls, monotone iteration from0
cannot skip a cheaper sufficient fee. A converged point is the least point
reached by this operator; if its next required fee exceeds50M, no allowed later
fee can repair it. Rejected rows preserve the last supported body and its own
metrics, keeping the unaffordable next fee separate. I found no stale-metrics
reporting defect.

This review qualifies prepared arithmetic only. Prior complete-liability I1,
authenticated lineage/backing and private-proof authorization remain assumed
or unimplemented. NOP envelopes measure a conditional future code footprint;
they do not implement or justify a combined private branch. These results do
not establish independent data availability, a complete10-KAS lifecycle,
privacy, old S7 owner/replay/DRAIN behavior or accepted-chain exits. Native
validation and typed security controls belong to the separately reported run.

Exact reviewed identities:

- Source03 `main.rs`:29f4d40c0e9457fb541411ad5b92beed3b357c2e0e8e9b4de8816686a3691bf8.
- [Pre-execution freeze02](PRE-EXECUTION-FREEZE-02.json):1c8d432425ced73fc4f7e9a0d74cf992c86d0ad41dc3001504cd1998ba4a3983.
- Fixed manifest:e05f7ec0266c6c953e9b4459a56c6e21826adbc644163131a0072d538ea9faa1.
- Agility manifest:b5d7a01c65afafa5fbe43d2f88eb69f4a35fc433fd6293965dc732e6008111ad.
- [Independent60-body recount](FUTURE-COST-RECOUNT.json):1dd6a61d319ea515873390f79b7474720aba70d91c253a9d8af9f20ad6445484.
