# Actual private cold exits and payout recovery

Two isolated cold clients built fresh private exits from one own seed-only backup each, authenticated public parameters and independently fetched chain history. Each client performed public SDK/native replay before seed access, authenticated its own local prover parameters before opening the backup, and generated a new proof. The controller submitted both transactions once; both payouts were confirmed.

| Public action | Native payout (sompi) | Fee (sompi) | Mining mass | Cold wrapper time |
| --- | ---: | ---: | ---: | ---: |
| [Continuing private exit](cold-exit-01/transaction.json) | 41,000,100 | 18,999,900 | 189,999 | 12.735 s |
| [Terminal private exit](cold-exit-02/transaction.json) | 41,042,400 | 18,957,600 | 189,576 | 12.711 s |

These were new owner-local proofs, rather than operator rehearsal exits. The public proof/Auth digests differ from all three operator reference actions. Each native result accepts Full and every input engine; each complete transaction/context/rate quote identity was independently checked. The terminal action consumes the reserve and leaves no successor pool output.

After both confirmations, a fresh Electron acquisition discovered all four pool transactions and queried every selected point. Each owner then ran the unchanged recover operation in a separate namespace using only its own backup, that final public capture, selected wallet/crypto and public validation software. No public proving-key blob, local prover, owner cashout helper, previous owner output or operator archive was mounted.

Both actual [recovery projections](final-recover-01/PUBLIC-RECOVERY.json) ([second](final-recover-02/PUBLIC-RECOVERY.json)) report one recognized historical receipt, one spent receipt and one authenticated current default native payout UTXO. Each required replay accepted all four pool transactions. Recovery took about 1.03 seconds per client; the two namespaces ran concurrently. Receipt-to-payout associations, receipt values, positions, commitment openings, seed/key material, private reports and operational paths remain private.

The final capture SHA256 is `4c137a71336dae9ed2dc2f613bbd9b4587010681bc08b3f3942fbb136b0794bf`. The [14-file selected release](OWNER-RELEASE-SOURCE-FREEZE-01.json) remained unchanged. The [15-pin recovery runtime](FINAL-RECOVER-RUNTIME-SOURCE-FREEZE-01.json) adds only a wrapper omitting proving dependencies. [Controls 03](controls-03/RESULTS.json) passed 19/19 before actual private runs; earlier controls, failed premises and the discontinued runtime transition remain preserved separately.

The cold proof units observed 14 CPU quota, 18 GiB memory and zero swap allowance. Recovery units observed 4 CPU quota, 8 GiB and zero swap allowance each. Every unit exited successfully and was collected with no active process. Detailed measurements and exact public payload lists are in each packet's PUBLIC-EXECUTION.json and PUBLIC-FILES.txt.

## Limits

This establishes the tested native testnet service-loss mechanism, not production security or financial privacy. The full-claim wallet exposes each consumed note value as public payout plus fee. Private change, repeated spending, stronger linkability experiments and lower fees remain work. Single successful cold runs are not p95 or cold-install qualification.

Chain acceptance and freshness rely on the selected validating node, finite retained history and current-UTXO observations. SDK hashes and native validation do not independently establish chain inclusion, proof of work, consensus or durable data availability. The local public-parameter cache aliases the same generated artifact; it does not demonstrate independent mirror availability.

The runtime assumes a trusted host, readonly selected source/binaries and unchanged release inodes during execution. It does not resist a malicious host writer. Recognized receipts require correctly encoded encrypted delivery; failed decryptions do not prove absence of all possible owned claims. Recovery covers the selected deterministic default payout scheme, rather than arbitrary external destination secrets.
