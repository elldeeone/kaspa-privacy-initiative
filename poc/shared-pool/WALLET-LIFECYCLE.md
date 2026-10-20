# Own-key admission and backup recovery

Date: 2026-10-20. Local continuation of `fa1dcf1` on `shielded-kas-research`.
[ADR-0029](../../docs/adr/0029-own-key-admission-and-recovery.md) fixes the scope and
prospective test; [RFC-0013](../../docs/rfc/0013-coherent-v6-lifecycle.md) defines
the milestone 2 integration gate.

**Status:** milestone 2 is complete for the bounded offline integration gate.
Six lifecycle proofs, one separate adversarial proof, nine integration controls
and 29 focused wallet/replay tests pass. Funding ancestry is synthetic; no new
transaction was funded or broadcast. [Public evidence](evidence/2026-10-20-wallet-lifecycle/README.md).

## What changed

The [wallet component](src/two_input/wallet.rs) exposes own-key initialization,
public receiving data, funding information, local inspection and ADMIT/SPEND/DRAIN
preparation on the existing v6 relation. It reconstructs public state using the
committed replay component, actual parent bodies and a separately expected endpoint.
Public state cannot be injected as deserialized wallet context.

A versioned backup holds the wallet's spending, viewing and native secrets and
pins the canonical pool descriptor and exact proving parameters. Only the founder
also retains its initial note opening. Later admission, payment and change notes
are recovered from public encrypted receipts, with ownership, commitment,
position, amount and current positioned-nullifier checks.

The backup is plaintext secret-bearing research JSON, created exclusively with
mode 0600 in a private directory. File permissions are not encryption. No mnemonic,
new key derivation, circuit, covenant or setup is introduced. The original live
runner and historical evidence remain unchanged.

A public receive envelope contains only shielded receive data and the pool pin;
native funding information is a separate local command. Selection requests and
wallet inspections are sensitive local data. Public prepared transactions contain
no selected note positions, private note/payment amounts or payout-key derivation
indices. Native deposit, payout and fee amounts remain public as before.

## Observed complete trace

The predeclared trace passed without changing its amounts, parameters or criteria.

| Step | Observation |
| --- | --- |
| A bootstraps a 20-tKAS reserve | A receives 19.6 after the existing 0.4 fee. B does not yet exist. |
| B initializes and saves its backup | Own keys, unchanged public descriptor, before admission or receipt. |
| B admits 12 | Actual synthetic parent output and B's signature; encrypted 11.6 self-receipt. |
| B stops; A sends 19.2 to B | A has no remaining private claim; original wallet workers then stop. |
| B restores its original backup | Finds both admission and incoming-payment notes: 30.8 total. |
| B spends both notes | Pays C 10 and creates 20.4 private change. |
| C scans and exits | C constructs its 9.6 native payout; local native validation passes. |
| B restores the same original backup again | Old inputs are spent; 20.4 change remains. Fresh exit pays 20 and drains the reserve. |

The six positive pool proofs reconcile 32 tKAS entering the reserve =
29.6 payouts + 2.4 pool fees + zero remaining. Founding and ordinary funding fees
are separate: A's synthetic funding parent costs 0.010124 tKAS, founding costs
0.010126 and B's funding parent costs 0.010166, totaling 0.030416 tKAS.
A local ordinary spend signed with B's restored native key passed validation,
checking control of the terminal payout; its extra fee is 0.002038 tKAS.
That helper receives the locally known derivation index. Automatic discovery of
native payout UTXOs from a backup is not implemented or demonstrated.

Recovery processes receive only software, one original backup, public snapshots
and public parameters. Bubblewrap isolates user, mount, PID and network namespaces;
the host home and controller files are inaccessible and only loopback is visible.
Original files are preserved outside those namespaces. This is same-host process
isolation, not an independently owned machine or proof of endpoint security.

## Review findings and controls

Author-side adversarial review found and fixed two issues before the full trace:

1. A malformed decryptable receipt originally aborted the whole scan. Because
   the circuit binds ciphertext bytes without proving correct encryption, a
   sender could block a victim's unrelated valid notes. The wallet now rejects
   that receipt's credit and continues scanning; public transcript, membership
   and state inconsistencies still stop processing.
2. A public result originally included an exit derivation index equal to the
   lowest consumed private note position. That field was removed. Requests stay
   local; the integration driver checks the exact public result field allowlist.

The delivery control uses a seventh proof on a separate fork: its transaction
and proof are valid, but B decrypts an opening that disagrees with the committed
note. B retained its earlier 11.6 claim, credited no new value, and successfully
prepared/circuit-checked an exit for the valid claim. This is different from
corrupting ciphertext beneath an old proof. That final check creates no eighth
proof; the fork's 0.4-tKAS fee is outside the positive trace accounting.

Nine integration controls passed: foreign selection, duplicate selection,
below-floor payment, spent selection, the valid-proof bad-delivery case, wrong
head, missing history, missing funding parent and wrong pool. All 29 process
isolation checks passed. The original descriptor and B's original backup were
unchanged across both restores. The public transaction wrapper matched its
field allowlist on every positive operation.

Fourteen focused wallet tests and the fifteen retained replay tests pass. They
cover backup/pool/parameter identity, private-file handling, wrong expected heads,
funding ownership/reuse, receipt validation, positioned spentness, selection,
arithmetic/floors and native payout binding. Some scanner/preflight unit fixtures
contain unproved transitions and are explicitly labelled; they do not establish
native acceptance. The complete trace supplies the separate proof-backed check.

## Observed cost and remaining target gaps

Each positive proof has 4,372,824 constraints. Preparation, including the circuit
satisfaction check, took 38.132–39.315 seconds; proving took 20.495–21.486 seconds;
native validation took 3–4 milliseconds. Thus warm preparation/proving took about
59–60 seconds before transport/replay overhead. Reporting only proof time would
omit most of the wallet's preparation cost.

The five positive worker parameter loads took 202.939–205.838 seconds.
These [component measurements](evidence/2026-10-20-wallet-lifecycle/component-timings.json)
are not p95 qualification on milestone 1 hardware or a 10,000-operation recovery
benchmark. The observed warm proof and cold-load times exceed the corresponding
targets; the unchanged 0.4-tKAS operation fee also misses the small-payment target.
The integration pass does not waive those failures.

## Reproduction

From `poc/shared-pool`, using the already cached dependencies and exact retained
v6 parameters:

```sh
cargo +1.95.0 test --release --locked --offline --lib two_input::wallet::tests -- --test-threads=2
cargo +1.95.0 test --release --locked --offline --lib two_input::replay::tests -- --test-threads=2
cargo +1.95.0 build --release --locked --offline --bin kpi-two-input-wallet --bin kpi-two-input-lifecycle
python3 two-input-lifecycle.py \
  --params "$KPI_V6_PARAMETERS" \
  --wallet-binary target/release/kpi-two-input-wallet \
  --helper-binary target/release/kpi-two-input-lifecycle \
  --output-parent "$KPI_LIFECYCLE_PRIVATE"
```

Set the two paths to the existing parameter directory and a private output parent.
The driver creates a fresh private run directory, preserves failures and uses
no network client or broadcaster. It uses the existing four-thread proving
configuration and at most two loaded prover processes concurrently.

The PK is 962,197,520 bytes, SHA-256
`6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593`.
The VK SHA-256 is
`9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`.
Both retained files matched these hashes before execution. Runtime loading checks
the full bytes before parsing, checks the decoded stream again, validates point
encoding and requires the embedded VK to match. No replacement setup is generated.

Private backups, requests and wallet views must remain outside public evidence.
The [source/reuse review](../../research/shielded-kas-admission-recovery-2026-10-20.md)
records parameter provenance, existing designs and retained assumptions.

The evidence directory includes both complete public lineages, funding-parent
bodies, public VK, expected heads, native payout-spend control and result summary.
Both exported lineages were separately replayed and reproduced their recorded
state/accounting. Before/after manifests match all 17 recorded source, driver
and binary hashes. Public exports passed a recursive private-field check and
comparison against the ten fresh wallet-secret/initial-randomness values;
no backups, requests or inspection views are included. These are checks on this
export, not a general data-loss-prevention guarantee.

## Evidence boundaries

Funding ancestors and accepted endpoints in this experiment are synthetic inputs
from the offline driver. Results report `chain_acceptance_verified: false`.
Native validation is real local execution of the pinned validator; no new
transaction is accepted on Kaspa by this test.

A valid prefix plus an equally stale supplied endpoint is still stale. A live
client must authenticate accepted history, currentness and funding unspentness
independently. Missing older parents or ciphertexts remain availability failures.
The strict supported parent formats have not been generalized.

The original single-party setup and unaudited relation/composition remain trust
assumptions. Three generated wallets are not three independent human participants.
Passing this trace establishes no privacy, cryptographic security, general
recovery, fee adequacy or milestone 1 hardware/latency qualification.
