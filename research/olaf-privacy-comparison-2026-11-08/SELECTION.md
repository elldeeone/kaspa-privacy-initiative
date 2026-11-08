# Olaf TN10 privacy comparison: fixed question and observer

Fixed 8 November 2026 before running the comparison. This is an offline test
of published evidence and public field semantics, not a fresh network trial.
No consensus changes, real funds, mainnet work or protected-host access.

## Sources

- Olaf upstream `main`: `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`.
- `poc/recovery-tn10/live-2026-10-20/evidence/result.json`, SHA-256
  `26e13486d15ec2b0947d1bc4eb0f72f8b064a997133f2befb1d6178a304bb164`.
- `poc/recovery-tn10/src/wallet.rs`, SHA-256
  `ad6da512c460fabe8b4d872238a5f32511e14b4be75e124b2a66319e45b5af60`.
- `poc/private-note-wallet/src/protocol.rs`, SHA-256
  `2593052d61b4997e5f3d66e768edcaab51b6a4c862afe1368aa19c6d36a5708b`.
- `poc/recovery-tn10/live-2026-10-20/README.md`, SHA-256
  `036097e066519d61de3d39f81e814b68d2b3e7c330f02ac177af933697006d66`.
- This branch's already frozen and scored 47-KAS wallet history:
  `research/note-granularity-privacy-2026-11-08/PREDICTION.json`, SHA-256
  `d392ea489638af35c0440784e0df8ecb2e277e185a62a15d296571e45d474fc0`;
  `RESULT.json`, SHA-256
  `971979cd3fecc38f27284c80ba370ee8f01f56942c6bde614298b39310351a48`.
- This branch's `poc/private-note-wallet/src/protocol.rs`, SHA-256
  `2bf0e6e9d22acc68c61121671beb3b2ff2332e15ff06a0b4b5d75e4a5a0b5526`.

## Question and rules

Olaf's published trial has one 10-KAS Alice deposit, one Alice-to-Bob private
transfer, then Bob's complete 4-KAS principal exit and Alice's complete 6-KAS
principal exit. The native payouts additionally refund 0.5 KAS rent to each.
Read the pinned result to get the actual public payout and refund values; read
source only to establish operation/field semantics and the actual fixture truth
for the later score. Do not feed the wallet's hardcoded 4-KAS payment to the
protocol-level amount predictor.

1. **Published-fixture observer:** can read the public repository and trial
   reports. Report the actual confidentiality of this specific publication,
   including hardcoded fixture amounts and role labels.
2. **Known-owner observer:** knows Alice funded the 10-KAS deposit, Bob started
   at zero, the only private contact is Alice-to-Bob, each fully exits and owns
   the named payout. Compute all positive integer-sompi transfer values that
   satisfy conservation and the observed exits. This extra owner/contact map
   is assumed, not claimed as chain-only discovery. Score exact payment amount
   and relationship separately.
3. **Bare-chain structural control:** remove repo role labels and owner map,
   retain only the two principal exit amounts and the one-transfer/full-drain
   structure. List arithmetically possible recipient amounts, but do not call
   the resulting count an anonymity set or claim proof-byte indistinguishability.
   Full public operation bodies are not published, so no precise chain-only
   ownership score is available from this source.
4. **Our system:** show the already measured actual 47-KAS wallet result under
   its own stronger known-owner/contact observer (4/7 exact). Also apply the
   same 10-KAS, one-transfer, two-full-exit *field-level counterfactual* to our
   current public-exit semantics. Mark that arm as unexecuted; never compare
   1/1 and 4/7 as architecture rankings across different workloads.

**Hypothesis:** with known owners and a single transfer, the public complete
exits force Bob's payment amount to 4 KAS regardless of the hidden transfer
proof or optional payout-service timing. The same sparse workload would force
the same amount under our current L1 exit fields. This does not establish who
an unknown chain observer thinks owns a payout.

**Stop/decision rule:** if the known-owner amount is exact in both the observed
upstream trial and matched field-level control, neither design has demonstrated
a better complete-lifecycle *amount* privacy result on this workload. Do not
start a new expensive proof/Testnet/cost campaign or announce a comparative
architecture winner. Keep optional service-timing evidence separate. Record
what a future matched independent-user trial would need. Reject a report if
source hashes, refund reconciliation, zero final reserve/liability or actual
truth membership fail. No hidden-label/commitment-position privacy scoring.
