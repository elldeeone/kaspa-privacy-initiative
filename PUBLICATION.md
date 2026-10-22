# Public research checkpoint — 22 October 2026

This branch publishes source, public test data and retained observations from the
local native-KAS research push. Native proof composition was demonstrated without
vProgs in these bounded experiments. A complete fundable private payment system
has **not** been demonstrated. DO_NOT_FUND.

Two snapshots preserve separate experiment identities:

| Snapshot | What the retained evidence establishes | Start here |
| --- | --- | --- |
| This branch: `work/intensive-research-20261022` | Binding-only J42, synthetic one-shot state-aware J336, native opcode and supplied-context Full checks; public observation and v6 budget qualification | [Final checkpoint](research/intensive-2026-10-22/FINAL-CHECKPOINT.md), [results](research/intensive-2026-10-22/RESULTS.md) |
| [Fresh-profile branch](https://github.com/elldeeone/kaspa-privacy-initiative/blob/work/s7-owner-lifecycle-20261022/PUBLICATION.md) | Fresh four-proof setup, initial native prefix, two alternative ordinary SPEND checks and genuine paired J336 proof plus native Full check | Separate domain, key, pool and image; partial lifecycle only |

Useful entry points on this branch:

- [Binding-only experiment](poc/two-v6-binding/README.md) and [synthetic state experiment](poc/two-v6-state/README.md).
- [Saved one-shot body's official Full validation](poc/public-state-consensus-check/README.md); its supplied UTXO/DAA context is not an accepted chain view.
- [Native observation](poc/shared-pool/PUBLIC-NATIVE-OBSERVATION.md) and [v6 budget 1600 adoption](poc/shared-pool/PUBLIC-V6-BUDGET-1600.md).
- [Requirements consistency](research/privacy-target-consistency-2026-10-22.md), [architecture](docs/ARCHITECTURE.md), [open questions](QUESTIONS.md) and [threat model](THREAT-MODEL.md).
- [Reproduction guide](REPRODUCE.md) and [public-view omission inventory](publication/OMITTED-ARTIFACTS.json).

## Scope and limits

Passing software, guest or native checks establishes the behavior of the tested
implementation under its stated inputs. It does not establish cryptographic
correctness, security, chain acceptance, reserve backing, permissionless exits
or useful financial privacy. No mainnet deployment, funding, broadcast or live
trial forms part of these checkpoints. Single-party development setups are
untrusted test setups.

The original fixed rehearsal instance, the later development instance and the
fresh-profile branch are distinct. Their proofs, images, journals and context
must not be mixed. The old J42 statement remains binding-only. The old J336
native diagnostic deliberately cannot continue. The fresh owner CLI, public
ledger replay and DRAIN workflow were blocked by automatic tool-safety review
and remain unimplemented/unexecuted in this run. Existing privacy requirements
and the completed frozen price-leakage failure are unchanged.

Cost failures remain results: the old one-shot 80M fee fails the 500-sompi scenario;
the fresh ordinary 40M fee fails 200 and 500, and fresh paired 80M fails 500. A
passing proof-verification check does not close those cost gates.

## Public view and historical provenance

Git contains a **source/public-data view**, rather than the full local packet.
Generated host/guest software binaries, caches, the large public proving key,
producer-only plans and test-wallet files are excluded. Public verification keys,
proof bundles, receipts, P/J bytes, native-body data, reports, source and locks
are retained where listed by the publication inventories. See the
[omission inventory](publication/OMITTED-ARTIFACTS.json) for exact paths, sizes,
hashes, local-retention status and rebuild references.

Frozen manifests and historical reports are unchanged. Some therefore name
omitted files or original absolute/sibling-worktree paths; a full local manifest
cannot be completely rehashed from Git alone. These locators describe the
original run. For portable navigation, use this page and the fresh branch's
publication page. Do not rewrite old manifests to make an incomplete public view
look complete. [Copy04](research/intensive-2026-10-22/evidence/integration-copy-04.json)
records earlier source/evidence overlays and the explicit historical-source
exceptions.
