# Final public evidence packet plan

**2026-10-25. Prepublication checkpoint.** Nine actual native payouts and three
fresh terminal seed reconciliations are complete. The selected terminal public
metadata/native-case snapshot exists. Its audit/publication and final public CI
HTTPS/native replay remain pending; no new local terminal HTTPS pass is claimed.

## Reuse the existing immutable snapshot

Keep the accepted-R2 recovery snapshot unchanged:

- Candidate inventory SHA
  `106f850e04cfafab896c9f2c6d17a71779534f9c7da26612dcaf947a870ddaa5`.
- Portable recovery index SHA
  `3ae9be6ddb6f6af1efc5d6012c9ed0b2fcb3c233eb1d79d28ecb5323332db278`.
- Actual HTTPS selection SHA
  `ea50ce2c0d06d5ebb534c7e8730aaaa54110d7a733880cdc59c2c37654f77566`.

The selected 64 objects total **1,712,656,346 bytes**: 18 static objects and
46 accepted-data/bootstrap objects. The latter contain 24 complete compressed
pages (**374,645,258 bytes**) plus 22 other objects (**473,342 bytes**). Their
exact decoded page bytes total **1,607,688,476 bytes** and belong to the
publication audit, not redundant uploads. These are existing selected sizes,
not an estimate of the future terminal prefix.

Match final objects to existing release assets by **both SHA256 and byte
length**. Reuse the existing URL only on an exact match. Retain final logical
page names/placements in the new metadata even when their bytes are reused.
An earlier partial page or post-query page may change; never infer reuse from
its page number, first block, transaction ID or apparent common prefix.

## Final finite allowlist

| Public object | Existing producer to reuse | Required final meaning |
| --- | --- | --- |
| Twelve accepted native cases | Unchanged replay's `native-0000` through `native-0011` `case.json` | GN3, two mixed rounds and nine actual exits, with full proof witnesses, budgets and populated input contexts |
| Native validation and metrics | Each corresponding `native/native-validation.json` and `native/metrics.json` | Actual Full and every input script passed for that exact case; exact integer fees |
| Complete accepted-prefix inputs | Final strict observer/replay handoff's exact ten selectors: HISTORY, CHECKPOINT, RESULTS, fetch, CURRENT-ENTRY, selection, descriptor, parameters, sessions and source pins | Actual final accepted state, complete body/context joins and source identities |
| Complete main/post-query pages | Every page named by final fetch metadata and the replay packet | Whole compressed hashes/lengths; exact decoded hashes/lengths for audit; no missing coverage |
| Native payout observations | Exact final observer/handoff public payout-query rows | Nine actual outpoints, amounts, destination scripts and birth DAA; current query result/time retained |
| Neutral terminal accounting | Reviewed accounting allowlist renderer | Whole-trial integer conservation, fee buckets, frozen 21 KAS denominator, zero reserve and final fee verdict |
| Aggregate terminal recovery | Reviewed neutral aggregate renderer | Three original-seed scans, exact accepted-cohort equality checked locally, all claims spent and payout keys rederived; booleans/counts only |
| Outage evidence | Neutral owned-process/path-isolation receipts | Original coordinator/shared R0/writers stopped; actual replacement execution uses downloaded public software with original paths absent |

The case indexes express **public chain order**, never owner/client order. Use
these existing replay outputs directly; no new case converter or financial
parser is needed. The existing three-case R2 replay already produced 81,169
case bytes, 1,480 native-validation bytes and 2,271 metric bytes. The selected terminal packet now has all twelve cases with validation/metrics:
36 files totaling 272,807 bytes. Raw pages remain outside Git.

Publish a small terminal evidence manifest/index with exact roles, byte lengths,
hashes, public URLs and joins to the final fetch/replay/checkpoint. Its final
replay packet must use actual terminal expectations, not the R2 packet's
three-transaction/empty-payout assumptions. Keep the R2-only assembler and
snapshot immutable; use a separately reviewed explicit terminal allowlist for
metadata assembly. This is evidence packaging, not a new financial or recovery
architecture.

## Review outside Forge

An independent reader can obtain the manifest and referenced public objects,
authenticate all complete bytes, unpack the selected software and run the
existing fixed SDK/native/financial replay over the complete final prefix.
The emitted twelve cases/checkpoint/results must match the manifest. The final
observer separately checks every payout and the absence of a continuing reserve.
This route requires no owner backup, proving witness, MPC or shared outer prover.

Proving keys already have immutable public URLs and need no duplicate upload.
The static verification subset of profile/component/native-policy, codec and
software archive/inventory/member metadata totals **54,447,229 bytes**. Its read
contract is confirmed by the unchanged replay bootstrap: all 63 software files,
codec, the six dynamic inputs, every declared page and external expected
HISTORY/CHECKPOINT hashes; no PK, role manifest or relation prover is read. Final
manifest/schema/pin audit is still required before claiming a complete portable
terminal verification packet. The full recovery experiment continues to use
its complete selected parameter closure.

## Publication boundary

Exclude client restore/READY/scan exports, per-client scan hashes/selectors,
participant-to-note/nullifier/exit/payout links, private selection/order data,
controller plans, registry contents, raw argv and logs. Public protocol payout
rows are allowed; associating those rows with a recovering owner is not.
Terminal cohort equality is verified locally and reported only in aggregate.

The frozen manifest flag `owner_client_associations_selected=False` means no
additional private recovery-client-to-note/NF/exit/payout association artifacts
were selected. It does not assert absence of public participant IDs, ordered
input labels or the source-established funding/session-to-NF/CV channel. Full
public protocol data remains necessary for independent replay. The known
acquisition marker is already on chain; excluding its raw ledger/three raw
cases from this packet does not remove that visibility.

Root combines the explicit final payloads and repository changes into one finite
publication audit. Include exact decoded compressed-page bytes as audit-only
candidates and retain their derivation map; do not upload redundant decoded
copies. Literal canaries supplement the semantic allowlist and do not establish
general transformed-secret absence.

Retained validating-node evidence does not prove independent consensus or
continuous currentness. Same-host namespaces and same-administrator release
hosting do not prove independent custody, separate administration or long-term
retention. Functional payouts do not qualify financial privacy.
