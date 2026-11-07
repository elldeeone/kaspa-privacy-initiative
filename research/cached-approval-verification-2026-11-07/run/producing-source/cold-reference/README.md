# Reuse proof verification; recheck the current bank

Research only. No consensus changes, mainnet, real funds, token or admin exit.
See [ADR-0113](../../docs/adr/0113-cached-wallet-proof-verification.md), the
[selection](../../research/cached-approval-verification-2026-11-07/SELECTION.md)
and [primary sources](../../research/cached-approval-verification-2026-11-07/SOURCES.md).

The authorization guest checks every existing wallet proof once and commits a
128-byte purpose/domain, pool, verifier and complete-packet journal. Retain its
unconditional **Succinct** receipt. The settlement guest pins that authorization
image, calls `env::verify`, applies the unchanged Ledger rules to current state,
and commits the ordinary exact 128-byte economic/native journal. Supplying the
actual receipt resolves the assumption; final compression remains Groth16.
The same new settlement image also supports direct full wallet verification for
matched controls. Neither method trusts a host `verified` flag.

`common` adapts the prior economic kernel by replacing only its proof-verifier
parameter. The original private-wallet relation, Ledger, checked submitted-point
decoder, BN254 arithmetic adapter, native script, claim construction and receipt
checks are reused. The original producing files are untouched. Host build checks
fully decode and compare both embedded key encodings before guest construction.

There are two mutually exclusive profiles:

| Profile | Wallet relation / parameters |
| --- | --- |
| Default `offline` | Original depth-four unfunded domain and fixed packed key. |
| `--no-default-features --features testnet` | Existing dedicated TN10 depth-four domain and new experimental one-party packed key, 1,209,140 constraints. |

They do not share proofs or verification keys. The setup utility creates private
proving parameters and public key encodings; the setup is not production secure.
Every new guest image requires a new bank. Rebuilding a guest can change its image
even after source formatting. Compute and pin the actual authorization image
before building its settlement guest; never silently upgrade an existing bank.
Retained program bytes and producing source epochs bind measured results.
`python3 build.py offline|testnet NEW_OUTPUT` builds the host/key gate, computes
and updates the generated authorization-image pin, then builds the settlement
guest and records both identities. It uses the explicitly qualified local
toolchain/worker assets; it does not broadcast or create proving parameters.

The host has finite diagnostic and experiment commands:

```text
wrap ELF PROGRAM [NEW_IMAGE_FILE]
cases SETTLEMENT_PROGRAM PRIOR_PUBLIC_RUN NEW_CASES
authorize AUTHORIZATION_PROGRAM INPUT NEW_CACHE
settle AUTHORIZATION_PROGRAM SETTLEMENT_PROGRAM INPUT CACHE_RECEIPT NEW_OUT
direct SETTLEMENT_PROGRAM INPUT NEW_OUT
native SETTLEMENT_PROGRAM CASE PROOF_DIRECTORY
controls CASES NEW_REPORT
receipt-controls AUTHORIZATION_PROGRAM DIAGNOSTIC_RUN NEW_REPORT
native-controls SETTLEMENT_PROGRAM DIAGNOSTIC_RUN NEW_REPORT
unresolved-control AUTHORIZATION_PROGRAM SETTLEMENT_PROGRAM INPUT NEW_OUT
conditional-native SETTLEMENT_PROGRAM CASE CONDITIONAL_PROOF_DIRECTORY
combined SETTLEMENT_PROGRAM PRIVATE_PARAMETERS NEW_RUN PUBLIC_ONION_TRANSPORT
fresh-trial SETTLEMENT_PROGRAM PRIVATE_PARAMETERS NEW_PRIVATE_TRIAL
```

`diagnostic.py` finishes a frozen same-input comparison, one GPU worker at a
time. `combined.py` owns fresh Tor processes and runs actual isolated wallet
processes, protected client-owned blind registration, original approvals, an
accepted local competing update, owned stale-worker cancellation, current-bank
retry, work-conserving optional payment batches, complete drainage and eight
restored-key native spends. Both offline histories use the same withdrawal-first
prefix; the reference sends waiting payments separately. Timed arrivals remain
90/330/570 seconds. Earlier completion must not force a three-payment batch.
All offline funding inputs are supplied, not chain-authenticated.

Wallet IPC deliberately returns no group payout key or labelled redemption.
Each actor blinds, unblinds and transmits its own redemption internally over
isolated onion circuits. The service obtains the whole output set from its actual
log. Controller commands/private registration state are auxiliary truth, not
automatic service observations. Same-host root can inspect everything; this is
not a sandbox or an independent-user experiment. Amounts and ordinary outputs
remain transparent, and known owners/request ordering can defeat ambiguity.

`fresh-trial` creates four new unfunded wallets and backups in one command without
loading proving parameters. `testnet.py` waits for complete offline functional
success, checks a real conditional proof's SDK/native refusal, and then executes
one small fresh TN10 rehearsal. The trial uses four test KAS principal, two fee
allowance and one ordinary source change. It verifies real accepted predecessors,
an unrelated accepted update after the original approvals, terminal payouts and
five actual restored-key payout spends. The issuer and Tor stop before the final
updates. The retained `live-chain.mjs` supplies two independent synchronized TLS
routes, exact integers, fresh UTXO checks, persisted one-shot submission intents,
exact accepted bodies and ten-confirmation observations. Never resubmit a used
trial. Failed trials preserve evidence; retry with a fresh identity.

Runtime folders, native/wallet backups, blinding state, raw RPC and proving
parameters stay under private ignored `.local` paths. Public replay must require
no private backup or proving parameters. All scripts are local research tooling;
machine-specific qualified worker/toolchain paths are explicit. No claimed
production privacy, commercial price, sustained-contention or independent-recovery
qualification follows from passing this finite experiment.
