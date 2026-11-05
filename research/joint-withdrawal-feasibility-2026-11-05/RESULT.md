# Joint withdrawals: the existing exit wrapper fails feasibility

**Date:** 5 November 2026 (Australia/Sydney).
**Decision:** reject batching/shuffling around the existing public EXIT path as
a way to hide its request-to-payout assignment. The conditional complete-lifecycle
comparison was not run. This does not establish impossibility of a redesigned
application using current L1 rules.

## What the retained transactions establish

The [public-evidence audit](audit.py) verifies all 100 retained attempt-06 files
against their original manifest, then decodes five actual public EXIT payloads.
Each contains the native recipient key, destination hash and principal amount.
The destination and amount are part of the wallet proof's public statement;
the key is appended to the published operation. The audit independently
reconstructs its intent ID from those bytes.

The audit matches requests to recipient scripts across the entire payout set
**before** checking the permission/payout IDs and consumed outpoints. It does
not assign recipients by filename order, unique amount, wallet truth or private
secrets. The source/permission checks then corroborate the exact public path:

```text
public EXIT statement + recipient key
  -> intent ID / permission output
  -> consumed permission input
  -> public recipient script and principal + permission-rent refund
```

| Check | Result |
| --- | --- |
| Hash-bound historical archive | 100/100 files unchanged |
| Public request-to-recipient links | 5/5 exact |
| Links without permission/payout payload tags | 5/5 exact by recipient script |
| Auxiliary mapped-owner links | 5/5 with the separately supplied owner map |
| Reorderings of the five recipient outputs | All 120 retain all five script links |
| Equal-amount control | Distinct public scripts remain linkable in all six three-output permutations |

An address is not a human identity. The chain-only result links a request to an
output; the owner result additionally uses the retained explicit owner mappings.
The audit does not infer IP addresses, authenticated service origins, which
private note was consumed, or every earlier payment. It does not claim that
every outside observer knows these owners.

The permutations are an **exposure control**, not newly signed or valid
native joint transactions. The retained application admits only one unpaid
exit at a time; its native permission policy pins a selected reserve, input
positions/count and a single-exit output layout. Moving outputs or combining
permissions cannot be assumed valid. These safety checks were not changed.

## Feasibility decisions

1. **Batching/shuffling existing requests: rejected.** The assignment is public
   before assembly. Equal values or different output order cannot erase the
   public key/script link. Hiding service records cannot conceal information
   already published to L1.
2. **Ordinary CoinJoin after individual exits: a different, narrower benefit.**
   It may obscure ownership of downstream outputs under its participant and
   network assumptions, but the original payouts and any payment facts already
   inferred from them remain visible. It does not pass this gate as a repair of
   the earlier exit disclosure.
3. **Replacement common-set authorization: unresolved application redesign.**
   Current output introspection and supported Groth16/RISC0 verification provide
   a plausible implementation surface. Each owner could authorize one complete
   output set after locally checking its full expected entitlement; individual
   public statements need not name a selected output in such a *different*
   relation. No complete proof/native authorization/registration path was built
   or validated here. Proof-opcode availability alone does not pass feasibility.

The third option needs protected output registration: if the coordinator
receives Alice's identified request together with her chosen key, it already
knows the map. It also needs exact reserve/state/output-set/fee bindings,
current spentness, liabilities, malicious-party/abort handling and independent
fallback. A privacy model that deletes current public statements or substitutes
an ideal anonymous-registration service would skip the unanswered question.
The [source report](SOURCES.md) pins the current upstream identities and
distinguishes this design seam from the implemented path.

## Why the comparison stops here

The [selection](SELECTION.md) required a concrete construction with a concealment
path before the full workload comparison. The existing wrapper fails directly;
the replacement has no implemented or qualified observation/authorization path.
Therefore no synthetic candidate was credited with hiding existing public
fields, and no comparative privacy benefit is claimed.

The scope is **the proposed wrapper**, not all current-L1 applications. No
consensus change is required by the future design seam, and no consensus
extension is proposed as a solution. Known-owner/full-drainage arithmetic and
the historical absolute qualification failures stay in scope. A future joint
protocol would have to improve financial facts under stated observations and
still disclose its sparse, collusion, cost, recovery and fallback limitations.

## Verification and adversarial second pass

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/joint-withdrawal-feasibility-2026-11-05/audit.py --check research/joint-withdrawal-feasibility-2026-11-05/RESULT.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s research/joint-withdrawal-feasibility-2026-11-05 -p 'test_*.py' -v
```

The [machine-readable report](RESULT.json) reproduced exactly. Ten controls pass:
equal amounts, absence of owner/event tags from the matcher, every truncated
request prefix/trailing data, substituted key/destination, ambiguous/missing
scripts, wrong amount/rent, output reuse, integer boundaries, duplicate JSON
keys/changed manifests, and explicit negative-result scope.

- **Inflation, double spend and reserve release:** this is a public-data reader;
  no transition/proof/authorization code or invariant changed. It rejects reused
  payout inputs and checks the retained principal/rent amounts, but is not a
  consensus validator or a cryptographic audit.
- **Privacy:** real public script bytes supply the assignment. Owner labels are
  explicit auxiliary evidence; output indices and label permutations are not
  counted as anonymity. Equal-value controls rule out relying on amount uniqueness.
- **Missing dependencies:** the audit needs only Python and committed public
  evidence/source files. Missing/changed evidence rejects. This does not prove
  wallet recovery or public proving-parameter availability.
- **Reorg/stale state:** confirmations are retained historical observations;
  no fresh live-state, selected-chain or finality assertion is made.
- **Trust:** original node observations/manifests and inspected source bindings
  are evidence inputs. No new independent human, native-node or cryptographic
  verification is implied. Hashes establish byte preservation, not truth.

No new cryptographic primitive, proof, wallet, native transaction, RPC, testnet
trial, real fund, mainnet action, MPC run, commit, push or external post occurred.
No architecture or invariant was changed; this rejection needs no new
architecture-adoption ADR. The future replacement remains an open RFC question.
