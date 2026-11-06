# Withdrawal requests, busy pools and existing proof optimization

This extends the [committed batching experiment](../batched-payment-costs/README.md).
Read the [selection](../../research/withdrawal-request-and-busy-pool-2026-11-06/SELECTION.md)
and [ADR](../../docs/adr/0110-withdrawal-request-privacy-and-busy-state.md).

Three separate experiments:

1. A coordinator verifies genuine unspent-note authority without human owner
   indices. Actual RFC 9474 issuance/unblinding/redemption run over direct TCP
   and our own Tor onion service. Complete operator logs retain network peers,
   request timestamps, amounts, nullifiers, proofs and credentials. Tor stream
   isolation separates each wallet's eligibility and redemption phases. The
   analysis includes measured client timing and later owner-disclosure controls.
2. Real unequal private payments, restored discovery, equal withdrawals and all
   remaining change exits test disclosure arithmetic. These use genuine wallet
   proofs and the host kernel; they do not claim outer/native acceptance.
3. Complete RISC Zero receipts and pinned native Full validation test an unrelated
   payment invalidating outstanding approvals, a fresh joint retry and restored
   solo exit. A fixed-key guest reuses the established immutable program-key
   optimization. An exact-input dynamic-key control proves the same journal;
   the fresh bank only accepts its declared pinned image.

The common kernel is generated from the old kernel with only `Verifier::new`
replaced. `generate.py` records both hashes. Fixed key points are fully checked
and re-encoded by `pin`; the host build also checks equality and canonical encoding
of both embedded representations before the runner builds the guest. Submitted
proofs keep their checked decoder. The original wallet/circuit/Ledger and previous
guest stay unchanged. No crypto primitive, consensus rule or spending privilege
is added. The new guest starts a fresh synthetic bank; no pool upgrade is claimed.

The host imports the old proving, native, circuit and receipt modules directly.
Its `bench` includes the old benchmark to reuse its private fixture/transition
helpers, then adds the new experiments. Public replay requires no backup,
issuer secret or proving key. Generation requires the ignored previous fixture.

```sh
python3 poc/withdrawal-followup/generate.py
# Build host, then generate pins from the previous public initial state if absent.
CARGO_TARGET_DIR="$PWD/.local/ci-target" cargo +1.97.1 build --locked --release --manifest-path poc/withdrawal-followup/host/Cargo.toml
# Existing checked public pins are included; never replace them for a bank already created.
python3 poc/withdrawal-followup/run.py OLD_CORE_RUNTIME
python3 poc/withdrawal-followup/run.py --quiet BUSY_RUNTIME OLD_CORE_RUNTIME NETWORK_RUNTIME
python3 poc/withdrawal-followup/network.py OLD_CORE_RUNTIME
```

`network.py` expects the unprivileged Tor binary at
`.local/withdrawal-followup/tools/tor/usr/bin/tor`. It creates fresh data directories
and stops only its own processes. It sends public proof/registration data to our
own service; no wallet witness or native secret leaves the wallet process. There
is no direct fallback from an onion failure. The successful fresh retry retains
the preceding failed transport attempt.

One driver, one host and three cooperative logical wallets do not establish independent-user,
global-traffic, Sybil-resistant or general financial privacy. The coordinator can
deny coordination, but cannot spend; owner-only exit requires no issuer. Busy
state still serializes through one bank UTXO. All native sources are explicitly
synthetic, no transactions are broadcast, and no provider resources are rented.

The quiet path uses the actual onion-registered keys and eligibility notes, then
checks complete native payouts and independent native spending with restored
client-local keys. Registration messages and native effects are publicly matched
as sets, without publishing an owner/key map. The onion transport test covers
eligibility and redemption; approval proofs are produced locally. Anonymous
approval delivery and operational separation of independent clients remain
unqualified. Client native-key backups are needed in addition to private-note
backups and public recovery data. No issuer receives either backup.

Public replay: `bash poc/withdrawal-followup/check.sh`. Generation additionally
needs the existing CUDA worker/assets, Python `psutil`, and Tor. Public replay
needs Rust dependencies and Python `cryptography`; it needs no GPU or service.
