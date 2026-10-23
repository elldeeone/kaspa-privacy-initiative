# Prospective wallet policy and bounded-search review

**Source ACK for further fixed PUBLIC development checks only.** Final method,
API, source/dependency manifest and public performance outcomes still precede
any heldout material draw. Source/public-report review only; no hidden labels,
keys, seeds, backups, PKs, native/proof/runtime jobs or network were used by the
reviewers. Date: 2026-10-23 UTC.

The retained public probe02 is reported COMPLETE for both identical development
fixtures: wide7.936s/2275 solver checks, serial26.807s/2273, with independent
certificate/true-history validation. Later public prefix/C+8 checks completed
wide prefixC, wide drainC+8, wide prefixC+8 and serial prefixC, but serial drainC+8
hit its4GiB outer memory limit. The latter is a retained incomplete performance
result, not ambiguity or a privacy success. No heldout sample was used to tune it.

## Exact current wallet versus future varied workflow

Current `poc/compact-batch-lifecycle/actions.py` SHA256 is
`a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484`.
Its cashout derives a claim-specific key from HMAC(seed,
KPX3PAY||D||foundingpoint||receiptCM||physicalposition||retry), rejecting equality
with the receipt's native key. This is not a repeated payout key per backup.
Fresh sampled valid payout keys in the model are an explicitly declared PRF-output
distribution abstraction, not execution/recovery of the exact derivation. Exact
public destination bytes remain in attacker input.

The financial demo's wrapper also supplies one common positive gross amount to
all32 distinct wide receivers. Under known equal-value wallet policy, the public
input value/fee fixes all32 claim values even before drainage. That current-demo
negative control must not be omitted while scoring a broader amount distribution.
The new primary policy explicitly models a future varied-value wallet with all
wide outputs positive; a separate current-uniform policy additionally constrains
them equal. Solver and independent certificate checker both enforce these policy
tags. The primary16-ledger workload is therefore not described as exact anonymity
of the current fixed-value financial demo or as a protocol-wide model.

## SAT-only refinements and resource behavior

The new open-prefix helper fills unknown leaves from public minimum/slack and
retains disclosed participant values/NF occurrences. It remains an incomplete
template. Every successful result is checked against the original sequential
ledger and exact requested predicate; failure falls back to SMT. The independent
reviewer found a successful-open-result cache entry left as None; the corrected
build stores the returned certificate before reuse. This fixes performance,
without adding a satisfiability assumption.

The additional serial value alternative permutes two unanchored native leaf
values/choices and recomputes intervening change values. Original checker and
exact alternative-value predicate are required before SAT. Protected participant
positions remain fixed. Search failure never becomes UNSAT.

For full-native events, `selected[p] => value[p] == payout+fee` is entailed by
exactly one selected input, aggregate conservation and zero private outputs.
The new local implication exposes that existing fact to propagation; aggregate
equality and the independent original checker are retained. It does not shrink
the permitted integer worlds.

Prospective per-view Z3 memory bounds return UNKNOWN. Recognized Z3 out-of-memory/
max-memory exceptions map to the same incomplete status; unrelated exceptions
still fail-stop. First UNKNOWN prevents further solver work in that view and
unresolved cells receive no scored forcedness. Continuing the remaining frozen
views is compatible with the global all-predictions-before-truth barrier; partial
cells cannot become qualification. Actual outer-process OOM remains an incomplete
operational failure, not evidence about candidate count. No post-heldout retries,
refits, replacement seeds or selective favorable rows are permitted.

Both confidence tails now use `log(2*M/alpha)` withM128 comparisons and width1/2
as appropriate, explicitly accounting for256 directional tails. Four independent
workload clusters yield intentionally weak bounds; they do not become256 samples.

Reviewed functional snapshot hashes:

| File | SHA256 |
| --- | --- |
| `construct.py` | `51d4c97cee7a8066ea3b63123ce6c0772525cda8b0165e43b6ce5c5a3fada11a` |
| `model.py` | `fc5ffda31cfc64f11a6601877488da5ef7f928794377ac350e1cb79b13cd4b3b` |
| `certificate.py` | `841e48bd37a6b0c718753521c458e5ec420ad11f60259eaf47634f228854e80e` |
| `prediction.py` | `3e20f1c7c2a73667655cf49a3e6abf394f2c1d16aae932c498970f101649da4a` |
| `schema.py` | `9101c68aa6b0ad2f816e3dfaeec7924840c3394675531a5b61ac660abef1b7a5` |
| `aggregate.py` | `25e642553c17f891ff8264948d8aeee954540f713c152254251213ac107f9475` |
| `run.py` | `7f6d74509a33d28c0882219c247b64bcfb68de7192ff270fb304b8e4cfb6d51d` |

These hashes are a review snapshot, not a final heldout freeze. Subsequent source
changes and public results must remain separately bound before release. The old
amount-prior failure and missing owner-world/cryptographic probability constraints
remain explicit; no financial privacy qualification is granted.
