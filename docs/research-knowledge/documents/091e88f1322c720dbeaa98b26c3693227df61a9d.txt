# Retained public evidence for completed TN10 attempt 06

This archive contains 100 byte-preserved public files from the successful
2026-11-02 Testnet-10 run: the original eight-file result bundle and the 92
public inputs bound by the corrected scorer and transaction analysis.
`ARCHIVE-MANIFEST.json` binds their sizes and SHA-256 hashes.

The original result manifest hash is
`1259c42cb7cde08fac0b9da29176e46cc20dddc963682c680a19958eefd5b88c`.
Its `RESULT.json` and `SCORE.json` preserve a historical incorrect
stronger-observer claim. Read [CORRECTION.md](../../CORRECTION.md) and
[NEXT-PRIVACY-RESULT.md](../../NEXT-PRIVACY-RESULT.md) for the superseding
assessment. No sealed original or corrected result has been edited.

The native evidence records two deposits, three private transfers, five
confirmed payouts and seven receipt-backed settlements. Terminal user
principal and outstanding exit accounting are zero; state rent remains
separate. Owner mappings are experimental auxiliary evidence, not chain facts.

Public-only predictions can be reproduced offline from the experiment directory:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 score_live_correction.py predict \
  run/tn10-attempt-06-public /tmp/NEW-native-kas-correction
PYTHONDONTWRITEBYTECODE=1 python3 reserve_lineage_privacy.py predict \
  run/tn10-attempt-06-public /tmp/NEW-native-kas-lineage
```

Each output directory must be new. Execution-truth validation requires the
retained private run; its recorded validation reports are in
[`live-correction-v2`](../live-correction-v2) and
[`next-privacy-v1`](../next-privacy-v1). The archive supports replay of the
bounded observer calculations, not independent replay of the complete native
validator or a fresh RPC confirmation. Request-file absolute paths are
historical provenance and are not portable execution instructions.

Wallet stores, sponsor/payout keys, proving parameters, witnesses, private
truth, raw RPC pages and live receipt workspaces remain outside Git. This
archive includes no newly generated proof, broadcast or protocol change.
