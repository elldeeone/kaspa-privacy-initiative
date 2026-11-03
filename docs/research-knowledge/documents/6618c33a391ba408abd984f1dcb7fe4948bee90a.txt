# Independent public state assertion fixtures

**NONFUNDABLE synthetic state-path and journal fixtures.** Existing genuine
public bundles are unchanged. These files do not authenticate accepted history,
native backing, recipient spendability, owner exits or a deployable reserve.

The stdlib-only oracle independently reconstructs the published count-3 CM
context and declared public NF/history sets. It outputs the fixed 11,219-byte
state-aware input and independent J336 for current count3→7 and historical
count5→9 contexts. Both use the genuine count-3 anchor. Full framing, constants
and source review are in
`research/state-aware-public-pair-source-review-2026-10-22.md`.

Recheck every frozen byte without writing:

```sh
python3 poc/two-v6-state/public_state_oracle.py --check poc/two-v6-state/public-fixtures
```

The oracle does not verify the inner proofs. The separately implemented state
core must verify both unchanged proofs and the exact P relation before accepting
their historical membership and transition. No generated proof, new parameter
setup, wallet material, native transaction or guest image is contained here.
