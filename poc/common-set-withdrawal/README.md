# Finite common-set withdrawal diagnostic

Experimental, unfunded, current-rule test of **payout ownership assignment**.
See [RFC-0005](../../docs/rfc/0005-common-set-withdrawals.md),
[ADR-0107](../../docs/adr/0107-finite-common-set-withdrawal-diagnostic.md) and the
[selection](../../research/common-set-withdrawal-2026-11-05/SELECTION.md).

Three synthetic public input claims approve the same complete payout set.
RFC9474 blind registration keeps the selected output out of identified issuance;
one common Groth16 relation proves each claimant's preimage/HMAC authorization.
The actual native script reconstructs the effects from transaction introspection.
Seven finite subset policies provide joint and independently authorized solo
exits from the same reserve. No coordinator/credential signature spends KAS.

## Run

```bash
PYTHONDONTWRITEBYTECODE=1 python3 poc/common-set-withdrawal/run.py
```

This builds the locked Rust 1.97.1 package, freezes source identities, generates
fresh synthetic secrets/setup, runs real RSA/Groth16/native checks and re-verifies
the public artifacts in a new process. Separate observer processes see one
declared view each; predictions are sealed before controller truth is read.
Each run uses a new ignored `.local/common-set-withdrawal/` directory. Failed
runs remain there. Do not fund generated scripts or reuse this setup.

The native/public replay uses `verify-public PUBLIC_DIRECTORY`; it needs no
proving key, claimant secret or private controller truth. The checked-in public
run can be checked without generating proofs:

```bash
bash poc/common-set-withdrawal/check.sh
```

Rust 1.91.0's existing formatter can format this package; the current pinned
Kaspa crates themselves require Rust 1.95 or newer. The lock retains the blind
library's compatible RSA `0.10.0-rc.18` / PKCS1 `0.8.0-rc.4` dependency pair;
automatic upgrades to later prereleases failed compilation and were not patched
locally. This is experimental upstream-library reuse, not security approval.

## Scope

- Known input owners, three equal denominations and independent recipient keys.
  This is not a shielded-note ledger or a complete deposit/payment protocol.
- The observer enumerates real owner-to-recipient-key assignments under stated
  RSA blindness/Groth16 assumptions. It does not test those cryptographic
  assumptions, posterior probabilities, independent humans or network anonymity.
- Native script-engine execution plus component mass quotes are narrower than
  full node/relay validation, authenticated funded state or chain acceptance.
  Local UTXO conflict/rollback observations are explicitly a supplied-state model.
- Joint and solo policies use `n*(D+F)` reserve: principal `D`, explicit per-claim
  fee allowance `F`. Zero final model backing/liability is not paid-cost evidence.
- The fixed compute-budget profile is publicly captured. It is a resource
  parameter, not an anonymity signal assumed absent. Actual outputs, payload,
  sequence, locktime, gas, subnet, outpoint and successor rules are constrained.
- Current note/nullifier integration, general DAG/reorg recovery, arbitrary
  amounts, network registration privacy, audited setup/cryptography, received-
  output spending and complete lifecycle/cost qualification remain open.

No consensus modification, new asset, real funds, RPC, broadcast, paid provider
or paused MPC run is part of this package.
