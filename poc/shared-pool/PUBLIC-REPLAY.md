# Public funding replay: first milestone 2 component

Date: 2026-10-20. Local work based on `cbeaa6f` on `shielded-kas-research`.
[RFC-0013](../../docs/rfc/0013-coherent-v6-lifecycle.md) defines the integration
question; [ADR-0028](../../docs/adr/0028-public-funding-replay.md) bounds this slice.

## Question and result

Can the unchanged v6 relation replay the preserved native histories without a
predeclared participant/funding roster, while checking actual public funding
outputs, signatures, state transitions and reserve accounting?

**Yes for the two retained histories.** The new
[component](src/two_input/replay.rs) and
[CLI](src/bin/kpi-two-input-replay.rs) reproduce each founding transaction and
thirteen pool operations through drainage. Transaction bodies/full hashes,
authorization/proof bytes and final compact public state match the retained
evidence. No new proof, setup, funding or broadcast was used.

This removes the roster dependency from this offline component. It does not
establish a new participant's admission, a general wallet, recovery, privacy,
cryptographic security or fresh chain acceptance. The original live runner and
its four-participant descriptor remain unchanged.

## Inputs and trust boundary

The public descriptor pins format, testnet/genesis, domain, initial commitment,
integer-sompi initial reserve, verification-key hash and founding transaction
ID/full hash. It contains no participant list. Users must authenticate its source.

The caller supplies an ordered pool lineage, public verification key and actual
funding-parent transaction bodies. Each consumed external outpoint is resolved
from its parent, including the founding input. Parent IDs, supported envelopes,
selected value/script and funding single-use are checked before native validation
of the founding/pool transactions. Authorizations cannot invent input context.

The accepted-chain view remains an external assumption. The component neither
recursively validates funding-parent ancestry nor proves acceptance, current
spendability, absence of an external double spend or current-head completeness.
Every successful output explicitly reports `chain_acceptance_verified: false`.
Missing data rejects; an unavailable old parent is still an availability gap.

Support is deliberately limited to the existing strict native version-1 parent
envelope, empty payload, zero locktime/gas, no output covenant metadata and an
ordinary P2PK selected output. Unsupported formats reject. Founding-only replay
reports `bootstrap_validated: false`: admission requires the founder's valid
bootstrap transition first.

## Checks performed

From `poc/shared-pool`:

```sh
cargo +1.95.0 test --release --locked --offline --lib two_input::replay::tests -- --test-threads=2
cargo +1.95.0 build --release --locked --offline --bin kpi-two-input-replay
```

All **15 focused tests passed**. The
[tests](src/two_input/replay/tests.rs) consume only tracked public evidence and
the public verification key. They include both retained histories plus controls
for descriptor/VK identity, canonical encoding, missing or altered funding,
unsupported parents, selected-output range/script boundaries, conflicting parent
bodies, funding reuse, admission before bootstrap, damaged signatures/proofs,
altered ciphertext/state, missing/reordered/duplicate history, and malformed or
post-drain terminal behavior. Unrelated valid parents and identical repeated
parent bodies do not change the result.

Some rejection controls mutate transactions or call the funding resolver
directly; they are not independently accepted alternative chain histories.
Canonical rehashed parents exercise the selected-output amount/script checks
after ID validation. Native rejection controls reach signature/proof execution.

Both CLI modes also passed on each retained history:

```sh
target/release/kpi-two-input-replay check descriptor.json vk.bin lineage.json parents.json
target/release/kpi-two-input-replay replay descriptor.json vk.bin lineage.json parents.json
```

To reconstruct those temporary inputs, use either `rehearsal` or `trial` under
[the retained evidence](evidence/2026-10-20-two-input-tn10):

- Decode `verification-key.json`'s `hex` field into `vk.bin`; check its SHA-256
  against the old descriptor's `vk_sha256`.
- Copy `network`, `genesis`, `domain`, `initial_commitment` and `vk_sha256` from
  that run's descriptor. Add `format: "kpi-v6-public-replay-v1"` and
  `initial_value_sompi` as the canonical decimal string of old `initial_value`.
- From `chain-confirmed.json.transactions`, pin row 1's transaction `id` and
  `fullHash` as `funding_txid` and `funding_full_hash`. Use rows 1 onward's
  transaction bodies as `lineage.json`; use row 0's body as the sole member of
  `parents.json`. Do not copy the old participant roster.

`check` returns compact state; `replay` returns full public state and records.
The smoke check matched compact state against the retained result and all
transaction bodies/full hashes against retained rows. An empty parent array
returned exit code 1 with no successful partial output.

For each history, public reserve accounting is:

| Item | Sompi |
| --- | ---: |
| Initial reserve | 2,000,000,000 |
| Later admissions | 3,600,000,000 |
| Native payouts | 5,080,000,000 |
| Pool-operation fees | 520,000,000 |
| Remaining reserve | 0 |

Thus 56 tKAS entered the reserve, 50.8 left as payouts and 5.2 as pool fees.
The founding input/change/fee are separate: 2,100,000,000 =
2,000,000,000 + 98,987,400 + 1,012,600 sompi. These are historical trace costs,
not a new performance result or compliance with milestone 1 fee targets.

Rust formatting, documentation links and whitespace checks pass. A second
adversarial code review found no implementation blocker and requested the direct
selected-output boundary controls now included. This is author-side review,
not independent cryptographic assurance.

## What remains

Milestone 2 remains open. Connect local keys/backups, independent new-admission
construction, recipient scanning, ordinary spend/change and independent exit to
one current-version state interface. The decisive trace is a previously unknown
participant joining after valid bootstrap, receiving while offline, restoring
from a prior backup, spending and withdrawing after the original controller
disappears. No participant-list edit, plaintext-note export or saved exit may be
required. No new funded trial is initiated by this component.
