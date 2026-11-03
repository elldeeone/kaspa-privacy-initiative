# A second limit: admission plus exit at the reference rate

For a 10-tKAS lifecycle that necessarily pays for **one unamortized v6 ADMIT
verifier and one fresh direct exit verifier**, proof verification alone costs
at least29,500,000 sompi at the reference100 rate. Its adopted2% lifecycle
budget is20,000,000 sompi. Even free private transfers would not close that gap.

This is a conditional bound on that route and fee allocation. A receiver-only
history, shared admission or an already settled withdrawal voucher has different
accounting. It must be assessed separately. This is not a general impossibility
claim about native-KAS privacy or an instruction to change the requirements.

| Scenario rate | One v6 verifier floor | Two-verifier lifecycle floor |
| ---: | ---: | ---: |
|100|14,750,000 sompi|29,500,000 sompi|
|200|29,500,000 sompi|59,000,000 sompi|
|500|73,750,000 sompi|147,500,000 sompi|

RFC-0012 applies its1%/2% fee caps at reference100. Comparisons against those
percentages in the200/500 result rows are sensitivity diagnostics; the adopted
requirement at those rates is supported user-controlled exits, not the same
percentage cap under arbitrary congestion.

The 10-tKAS ordinary1% budget is10M sompi; a standalone v6 verifier already
exceeds it at reference100. Two-payment aggregation is a different route.
The two-verifier lifecycle lower bound reaches2% only at principal14.75 tKAS
or above at reference100, **before** all transaction overhead, payment proving,
funding, scanning/service costs or retries. This necessary condition is not
evidence that a14.75-tKAS lifecycle passes.

The same arithmetic preserves the earlier small-claim failure: a60M-sompi note
must retain at least10M payout, leaving at most50M for the exit fee. Its73.75M
verification floor at500 exceeds both that fee allowance and its entire value.
Budget1600 qualification cannot remove the opcode charge or reprice an already
proof-authorized fee.

The [calculation](calculate.py) reads and hashes pinned native source and emits
[exact integer/rational results](results.json) for normal amount endpoints and
all three scenarios. It creates no proof or transaction. The [specification](SPEC.md)
and independent architecture review preceded calculation. Reproduce with
Python3 and a checkout at native commit
`01b532e8b553523216471682649693af92f0fd16`:

```sh
python3 research/next-session/fee-frontier/calculate.py /path/to/native/source /fresh/output.json
```

Sources: the pinned [tag charge](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs),
[per-IC-element metering](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs),
[native units/free allowance](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs),
[current v6 route](../../../poc/shared-pool/src/s7_lifecycle/native.rs), and
[unchanged fee requirements](../../../docs/rfc/0012-useful-privacy-requirements.md).

Established alternatives and their changed assumptions are reviewed in
[the source comparison](../native-kas-singleton-fee-alternatives-2026-10-22.md).
Earlier settlement can make the terminal claim cheaper, but its authorization,
backing, disclosure, availability and fee allocation must remain accounted for.
