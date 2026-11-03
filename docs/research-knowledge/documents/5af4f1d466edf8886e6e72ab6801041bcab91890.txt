# Public two-action settlement transcript

Problem: independently valid compact2/wide32 proofs bind individual Auth528
transitions. Verifying both does not establish a shared native settlement. The
first experiment must locate that boundary with actual proof verification and
byte-derived public state/money updates, without receiving a note opening.

Scope is new `poc/shared-settlement` plus a narrow public verifier adapter owned
separately under `poc/shared-settlement-verifier`. Old code, packets, keys and
funded instances remain unchanged. No new proving setup, aggregation primitive,
native policy, deployment or accepted-chain assertion is selected by this plan.

## Assumptions and reuse

- Reuse the installed compact2/wide32 VKs and full-program tail independently
  selected from the sealed public packet. Actual G16 verification consumes only
  role, Auth528 and proof128; no PK or owner witness is opened.
- Translate pinned rusty-kaspa2.1.0 `01b532e8...` v1 transaction-ID encoding and
  existing indexed-NF/CM native-policy checks into a small independent public
  checker. Standard keyed BLAKE2b/SHA256 are reused; no primitive is invented.
- A trusted starting head, valid reachable prior state and complete public
  material remain external premises. Supplied-context fixtures cannot establish
  accepted ancestry/currentness. Missing/stale/wrong data reject or halt.
- Existing Toccata, vProgs/research, Orchard, Aztec, RAILGUN, Monero and MWEB
  source comparisons remain in the predecessor [source review](../../compact-batch/SOURCES.md).
  Their authority/DA/privacy guarantees are not imported. New source findings
  are recorded in `PUBLIC-SOURCE-AUDIT-01.md` before relying on the checker.

## Candidates and decision

| Candidate | Experiment decision |
| --- | --- |
| Existing native ordered transactions | Implement public transcript checking first. Retain exact Auth/outpoint binding and the priced2-call private fallback. |
| Native aggregate/intent settlement | Unselected architecture candidate. Needs explicit cross-action state/NF/body and fee/rebate authorization, recipient inclusion, DA and private unilateral exits. |
| Based App shared settlement | Unselected comparison candidate with the same obligations. Prior public-account feasibility is not a shielded settlement or exit proof. |

Root owns RFC/ADR/architecture integration. The bounded decision is to prototype
only the public semantic contract already requested by the compatibility memo;
no funded-policy change or weaker invariant is proposed.

## Decisive controls and result rule

The positive is the retained public wide canary followed by its genuine compact
successor. Both proof predicates, canonical v1 IDs, exact prior outpoint/state/
reserve, sequential strict NF absence/insertion, ordered CM/cipher digests,
aligned subtree append, exact successor program and native amounts must pass.

Negatives retain valid proofs where possible: mutually exclusive alternatives,
duplicate action, reversed order, fresh privately valid occupiedNF, old Auth
rebases, wrong head/currentness scope, role/domain/root/CM/NF/CF/path/order,
destination/payout/reserve/fee/body mutations and malformed encodings. Recompute
body IDs for coherent body mutations so JSON-ID mismatch is not the only guard.
Explicitly separate native-binding checks from selected-budget/mass profile
checks. Native permits a sufficiently funded larger budget; B1600 is this profile.

Every outcome records actual cryptographic validity separately from public
semantics. A true G16 predicate with false NF semantics is an expected decisive
negative. A proof report boolean is never a verifier substitute. Passing the
two-action transcript establishes no new aggregate proof/native acceptance,
privacy, currentness or fee reduction.

After second-pass review, use this contract to choose or falsify the smallest
new settlement design. Proceed beyond the harness only with an explicit
authorized fee/reserve equation and a separately priced private unilateral exit
from own backup plus public data, without another owner's witness or arrival.
