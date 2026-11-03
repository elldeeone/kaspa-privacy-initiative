# Fresh registered trial bootstrap

`bootstrap_registered_trial.py` creates one fresh **unfunded** registered-service
identity in one command:

```text
python3 -B financial/bootstrap_registered_trial.py --output ABSOLUTE_FRESH_ROOT
```

It generates three TLS server identities, pins their canonical certificate DER
hashes into the fixed research `EpochKey`, writes a typed registration, and
initializes three matching empty journal/anchor pairs. The completed root is
published by one same-filesystem rename only after direct journal reopen and
full public-structure verification. Existing or partially created target roots
are never reused.

Public authority is limited to `public/SELECTION-CANDIDATE.json`. It is
explicitly `UNCONFIGURED_BOOTSTRAPPED`; private keys, journals, anchors and
candidate workspaces remain local beneath the trial root. Public receipts
contain private paths but no private body or private-body hash.

Verification is direct and repeatable:

```text
python3 -B financial/bootstrap_registered_trial.py \
  --verify-only --output ABSOLUTE_TRIAL_ROOT
```

The bootstrap does **not** configure or start the registered financial driver,
contact a node, accept owner input, execute MPC/proofs, broadcast, or settle.
The accepted-head/exporter/native/roster transport selections remain separate
gates.

`controls/test_bootstrap_registered_trial.py` covers fresh-identity separation,
target reuse, partial targets, symlink/hardlink aliases, wrong certificates,
wrong registrations, direct journal mismatch and the no-private-body-hash
boundary.
