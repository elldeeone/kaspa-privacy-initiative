# Protocol note floor and simultaneous exits — TN10

The fresh rehearsal and measured trial both succeeded on 2026-10-19. Each
confirmed the private payment and both native payouts. The losing wallet found
the competing spend from public chain data, generated a new proof and completed
its payout after the winning wallet's process had stopped. Both pools drained;
the interrupted earlier pool was also recovered separately.

The bounded question is whether a minimum-sized private claim can exit and
whether a losing wallet can recover from a competing reserve spend without
another wallet's secrets or an operator-selected successor. The version-2
four-wallet experiment and evidence remain at checkpoint `62c8550`.

Design: [ADR-0017](../../docs/adr/0017-note-floor-and-independent-exit-retry.md),
[RFC-0005](../../docs/rfc/0005-note-floor-and-exit-contention.md),
[source review](../../research/shared-pool-dust-contention-source-review-2026-10-19.md),
[living journal](../../docs/RESEARCH-JOURNAL.md).

## Rule and test

Version 3 enforces a 26,713,000-sompi private-note minimum and a
10,000,000-sompi native-payout minimum in the proof relation. The rule applies
to bootstrap, deposits, both transfer outputs, partial change and real spent
inputs. Nonterminal reserves also satisfy the note floor; terminal exits leave
no reserve. Zero padding is not a real note. The version, domain, transcript,
payload magic and verification key change; no earlier pool is upgraded.

At the fixed 100-sompi/gram rate, the larger full-exit fee is 16,713,000 sompi.
The minimum claim covers that fee plus the payout minimum. Storage mass for
a continuing exit is bounded above by 137,434 and terminal storage by 100,000;
both are below compute mass and the native 500,000 limit. A higher future fee
can invalidate minimum-note exitability. The circuit minimum is an economic
restriction and changes future observer bounds; it is not a privacy improvement.

The workload funds two isolated wallets, bootstraps a 10-tKAS reserve and makes
one private payment assigning exactly the minimum claim to the recipient.
Both wallets prove full exits against the same accepted reserve, then submit
after one common start signal. After that signal, the controller only observes.
Each wallet controls its own ordinary RPC client and a network-isolated prover;
neither sees the other's key file or a future winner/transaction list.

The loser queries Full accepted-chain data, finds the reserve's actual spender,
checks canonical bytes, full hash, proof and propagated history, rescans its
own notes, and generates a new proof against the successor. Its economic
nullifier stays the same. Reusing the old proof in the rebuilt transaction must
fail native Groth16 verification. The original candidate is never rebroadcast.
Success requires both native payouts, zero remaining reserve, exact accounting,
and winner-process termination before the loser's confirmed payout.

## Result and cost

| Measurement | Rehearsal | Measured trial |
| --- | ---: | ---: |
| Accepted transactions / submissions | 5 / 6 | 5 / 6 |
| Recorded initial-submission separation | 0 ms | 5 ms |
| Total accepted fees | 0.508184 tKAS | 0.508184 tKAS |
| Recipient's minimum-note payout | 0.1 tKAS | 0.1 tKAS |
| Sender's recovered payout | 9.399445 tKAS | 9.399445 tKAS |
| Losing wallet's new proof | 10.799 s | 10.845 s |
| First submission to loser's confirmed payout | 16.883 s | 15.027 s |
| Retry submission to confirmed payout | 2.094 s | 1.991 s |
| Winner process stop to loser's confirmed payout | 12.733 s | 12.726 s |
| Cold wallet parameter loading | 141.512–141.550 s | 141.547–142.098 s |
| Initial exit proofs, generated concurrently | 12.884–12.931 s | 12.961–13.015 s |
| Remaining private claims / reserve | 0 / 0 | 0 / 0 |

Wallet 1 (the minimum-note recipient) won in both runs; wallet 0 rebuilt and
took the terminal exit. The winner had stopped before recovery proof completion
as well as before the loser's payout. Neither result was selected for its winner.
These runs do not demonstrate the opposite live winner order; minimum-value
terminal behavior is covered by local relation and native amount tests.

The initial losing candidate was explicitly rejected as a mempool double spend.
It incurred no accepted-chain fee, but its discarded proof still consumed local
computation. Both old-proof substitution controls failed native Groth16
verification on the rebuilt transaction. No stale transaction was rebroadcast.

The accepted private payment cost 0.166718 tKAS; the continuing and terminal
exits cost 0.167130 and 0.166707. Allocation/bootstrap added 0.007629. Including
both successful runs and the interrupted run's recovery, **15 accepted
transactions cost 1.524552 tKAS**. All three reserves were drained.
See the [receipt-derived comparison](evidence/2026-10-19-contention/comparison.json)
and [final accounting](evidence/2026-10-19-contention/final-accounting.json).

Timing includes local polling, RPC and validation overhead. Millisecond
submission timestamps do not measure exact network simultaneity, and payout
observation is not exact consensus latency. Cold startup remains a substantial
usability cost; the fee floor is not a promise about future mining rates.

Fresh experimental setup generated 3,232,330 constraints in 64.158 seconds.
The proving key is 646,975,312 bytes and the verification key 328 bytes. Proofs
are still 128 bytes. Proving used four Rayon threads per wallet on the local CPU;
no GPU was used. Parameters and wallets remain outside Git; exported public
verification keys, source/binary hashes and accepted bodies permit verification.

## Validation status

Local checks passed: eight Rust tests, five chain tests and one sandbox test. The new relation
checks below/equal/above boundaries across all creation paths and payouts.
Native amount/property cases cover 841 continuing and 29 terminal combinations,
plus rejection of a tiny continuing reserve. Mass/policy fixtures use dummy
proofs and do not constitute proof-verifier acceptance. Existing authorization,
backing, integer, replay, stale-state, domain and capacity tests remain active.
Chain tests cover successor discovery, pagination, view replacement, canonical
integer decoding, and conflict versus unexpected/ambiguous RPC failure.
The sandbox test exercises the real launcher and private FIFO connection with
a fixture prover, checks isolation, and requires successful EOF shutdown.

Both full funded runs also passed local native Full validation, default relay
policy, exact SDK encoding, actual node submission, payout-UTXO confirmation and
accepted-body/full-hash retrieval. These are separate evidence levels. Source
review and passing tests do not prove cryptographic correctness.

## Interrupted rehearsal

The first funded rehearsal accepted allocation, bootstrap and the payment,
then failed to launch either wallet because Node was outside the mounted `/usr`
tree. A separate cleanup launch exposed the host's AppArmor restriction on
nested namespaces. Neither launch submitted an exit. Explicit Node mounting and
sibling wallet/prover sandboxes fixed these portability issues without changing
host policy. Their direct FIFOs are not read or relayed by the controller.

A fresh cleanup identity subsequently completed both exits and drained that
pool. No seed transaction was rebroadcast. Original seed fees were 0.174347 tKAS;
cleanup exits cost 0.333837, for 0.508184 in total. This operational recovery does
not qualify as the fresh complete rehearsal. The failures and recovered funds
are retained in [interrupted-run evidence](evidence/2026-10-19-contention/interrupted-run/summary.json).

## Reproduction and evidence boundaries

Build with the locked Cargo dependencies and Rust 1.95.0. The native/SDK pin is
`01b532e8b553523216471682649693af92f0fd16`; the actual TN10 node reports `2.0.0`.
No node or consensus code is changed. Set `KPI_BINARY`, `KPI_SDK_PATH`,
`KPI_TN10_RPC` and `KPI_FUNDING_DIR` for your installation. Keep the TN10 funding
key and all wallet directories outside Git.

```sh
cargo +1.95.0 build --locked --release --manifest-path poc/shared-pool/Cargo.toml
cargo +1.95.0 test --locked --release --manifest-path poc/shared-pool/Cargo.toml -- --test-threads=1
node --test poc/shared-pool/chain.test.mjs
node --test poc/shared-pool/tests/sandbox.test.mjs
# Generate fresh experimental parameters once with the version-3 binary.
$KPI_BINARY setup /private/path/v3-params
node poc/shared-pool/contention.mjs prepare /private/path/v3-params /private/path/races rehearsal
node poc/shared-pool/contention.mjs live PRINTED_REHEARSAL_PATH
# Only a completed funded rehearsal with identical source/binary qualifies.
node poc/shared-pool/contention.mjs prepare /private/path/v3-params /private/path/races trial
node poc/shared-pool/contention.mjs live PRINTED_TRIAL_PATH
python3 poc/shared-pool/export-contention.py PRINTED_TRIAL_PATH NEW_EXPORT_DIRECTORY
```

Fresh preparation is one command. Every native transaction is submitted once;
unexpected failure preserves the used identity and requires a fresh trial.
Expected initial conflict is recorded separately from policy errors and unknown
transport outcomes. Unknown transport outcomes are observed without rebroadcast.

This remains a fixed-size, unaudited synthetic experiment with single-party
Groth16 setup, retained public parameters/history, one correct full-node view
and one eventual uncontested proving opportunity. It does not establish reorg
recovery, sustained-contention fairness, data availability, production safety,
RPC/network privacy or real-world anonymity. The node executable is not attested.
