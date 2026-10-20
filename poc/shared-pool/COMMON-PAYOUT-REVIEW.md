# Common partial payouts: adversarial second pass

Scope: the author reviewed the H17 additions separately from implementation.
This is not independent review or cryptographic assurance. See the
[frozen specification](COMMON-PAYOUT-SPEC.md) and
[measured report](COMMON-PAYOUT.md) for the eventual execution verdict.

## Invariants and mechanisms

| Concern | Check and remaining boundary |
| --- | --- |
| Inflation or reserve theft | No change to circuit, covenant, parameters or `settle`. Each Q payout debits exactly Q plus its fee and retains positive private change. All original funding and every partial/final payout are reconciled. Native validation and the existing transaction mutations run on the genuine fixture. |
| Double spending and stale proofs | Original full exit and partial payout use the same real NF. The new harness checks both winner orders on cloned public states. After partial success the old capability is rejected; saved change exits and fresh alternatives also exclude each other through terminal state. |
| Unauthorized exits | The experiment calls existing owner authorization/proving. It introduces no withdrawal key, admin branch, signature bypass or fee subsidy. Wrong-domain/root/payout/binding defenses remain those of v6; H17 is not a re-review of its cryptographic composition. |
| Dependency loss | Saved exit workers get their own capability, VK and supplied public state only. They do not mount wallet keys or the proving key. Creating a new partial or a fresh fallback still requires the owner's witness and public parameters. Losing every authenticated copy of history remains a liveness failure. |
| Reorg and contention | Current state changes are handled by existing settlement witnesses; the native fixture is a synthetic linear accepted history. H17 adds no reorg, malicious-RPC or simultaneous-network validation. |
| Fee exhaustion | Each extra partial costs a real fee from that claim. Reject sub-floor remainders; do not assume extra deposits to pay them. Saved authorization has an exact fee, not a guarantee under all future fee rates. |
| Privacy regression | Public Q payouts, fees, sequence, destinations and final remainders remain visible. Test both the incomplete and drained histories, original payment links, and original cashout provenance. An input graph that merely changes which Q-change note is spent cannot count as a new original source. |
| Fake population | Four wallets are a hidden fixture fact; the observer is not capped at four owner labels. No extra deposits/users/cover payments are generated. A repeated common payout may come from an earlier common-change note in an alternative graph; the observer has no hidden fixture instruction that each wallet participates once. |
| Disclosures and truth leakage | Each H16 participant view is separate. Own receipt values, authored inputs and address aliases are explicit extra knowledge, never described as chain-only. Views are cut at each horizon. The observer has no `/proc`, host paths, private plan, claim/leg matching, other views or network. |
| Unsound solver shortcut | A relaxed result is positive only after the entire selected graph is certified with integer-sompi constraints. Original provenance is a deterministic function of that graph and checked against the query. Rejected integer graphs are blocked; unknown is an error. The independent tiny oracle also enumerates provenance and participant constraints without these solver encodings. |
| Misleading success | Primary targets are the original seven claims, not the eleven resulting payout events. Leg candidate sets are never intersected using their secret grouping. Separate-participant distinct counts do not represent one colluding observer. Zero singleton coverage is not hidden ownership, amount secrecy or statistical anonymity. |

## Limits and issues found during review

The size was chosen using the previously visible fixture, then frozen before
the new analysis. This is a bounded policy screen, not a blind holdout or an
estimate of general users. The fixed interval makes complete withdrawal 40
minutes later. The existing 30-minute target is knowingly not met; it must
not be rewritten to manufacture a pass.

The first small floor-control fixture accidentally emptied the whole reserve
in normal mode, so the existing parser correctly rejected it before reaching
the intended change-floor test. The control was corrected to retain an
unrelated funded note; no protocol/parser check was relaxed. This happened
before the measured observer run.

Whole-crate `cargo fmt --check` finds historical formatting differences in
unrelated source files. Only the changed harness files are formatting-checked;
historical protocol/evidence sources remain byte-identical to their pins.

The public-body calibration verifier mounts only its executable, one selected
public trace, system libraries and an empty result directory. It receives no
private plan or unused exit requests. Its `/proc` is not used as an observer
blinding boundary; the inference workers use the stricter no-`/proc` sandbox.

The model treats cryptographic bytes as opaque and does not prove hiding,
soundness, recipient anonymity or resistance to implementation fingerprints.
Preserving usable exits is intentionally independent of achieving a privacy
screen. A participant may choose its old fallback when normal policy is
unavailable, even if publishing it leaks its earlier anchor.
