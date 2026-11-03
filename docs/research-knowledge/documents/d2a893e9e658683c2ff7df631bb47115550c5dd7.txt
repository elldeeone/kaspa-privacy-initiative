# Offline native key-separation evidence

Ten genuine pool proofs, three fresh arms, synthetic parent UTXOs and local
native verification. No funds, broadcasts or chain-acceptance observation.
Fresh v2 purpose separation and explicit v1 compatibility are separate claims.

- `native/<arm>` contains only the seven approved public snapshot files.
- `recovery/<arm>` contains terminal payout and signed public native payout spend.
  These were not observer inputs. Native payout spending supplied a known index;
  arbitrary native UTXO/index discovery was not tested.
- `native/summary.json`, `native/source-before.json`, `evaluation/freeze-public.json`
  and `evaluation/prediction-batch-public.json` are marked derivatives with source
  hashes. Their bytes/hashes differ from the private retained originals.
- Prediction seals and public predictions are byte-exact. A seal's freeze hash
  names the original freeze, and completion's batch hash names the original batch.
  Withheld-truth hashes are provenance commitments, not privacy-preserving redaction.
- `evaluation/runs` preserves controls, predictions, hypothetical assignments,
  separate scores and structured process/isolation attestations. No logs are copied.
- `review/control-reasons.json` records exact ownership-error matches for both
  wrong-purpose controls and hashes the withheld stderr; it contains no raw log.
- `review/{witness,unsat,integrity}-review.{json,py}` preserves post-run reports
  and checker source. The checks cover 180 hypothetical SAT
  assignments across 16 profiles, 24 unrestricted solver queries for six forced
  facts, and source/seal/rejection integrity. These are author-team checks, not
  an external audit or security proof. The integrity checker is an explicitly
  marked derivative with two host path constants replaced; its report retains
  the original checker hash. The remaining five files are byte-exact. That
  checker expects retained original metadata, so this export is not a
  self-contained replay of it.
- `source/code` retains tested public source; markdown copies use `.md.txt`.
  The revision is the base commit plus pinned source manifest and tracked patch,
  not merely the base commit. Binaries and proving keys are identified by hash only.

The combined export is not a blinded observer input: arms share fresh wallets,
and the frozen driver/specification disclose deliberate fixture choices. Each
observer saw only its own approved public inputs. No actual backup, receive
envelope, action, private wallet view, plaintext truth or operational log is
exported. Predicted hypothetical note assignments are not recovered secret notes.

`export-manifest.json` records original and exported identities. `SHA256SUMS`
covers every exported file except itself. Historical evidence remains unchanged.
Removing this equality-based inference does not qualify general payment privacy,
the 32-role target, cryptographic security or production readiness.
