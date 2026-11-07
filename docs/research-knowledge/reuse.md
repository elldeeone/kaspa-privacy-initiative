# Reuse decisions for future work

The [atomic-bundle candidate](../../research/atomic-bundle-withdrawal-2026-11-07/RESULT.md)
reuses the existing private wallet, RFC9474 blind-signature implementation,
proof-backed eligibility, whole-set consent and unchanged economic kernel.
Only the experimental wallet availability check and local public-board
simulation are new. Do not import this offline file as L1 acceptance or a
production coordination service.

[Knowledge guide](README.md) · [Source index](sources.md)

These decisions carry knowledge into the active branch. They do not claim an old
component's runtime code has been integrated or is a drop-in replacement.
**Carry** means preserve the rule/result in new designs and reviews; **adapt when
needed** means qualify it against the selected current interface/instance;
**archive** means retain evidence without treating it as the next implementation.

| Component or finding | Decision | Local knowledge / condition |
| --- | --- | --- |
| Mature protocol and Kaspa source comparisons | Carry | [Architecture](architecture.md); refresh exact upstream sources before semantic implementation. |
| A0 native proof-gated reserve release | Carry | Exact native context, fee policy, storage mass and integer handling; [operations](operations.md). |
| A1 successor/reorg/physical-loss controls | Carry | Preserve actual input lineage and atomic rollback; [recovery](recovery.md). |
| Public-account Based App and recursive runtime | Archive as completed feasibility | Current [conclusion](../based-app-feasibility-2026-10-17.md); expand only for a demonstrated requirement. |
| Offline-wallet proofs/recovery and GPU receipts | Carry result; adapt only selected mechanisms | Original `b4114173` history and local source versions; its I-2 change is not adopted automatically. |
| Direct self-funded deposits/exits | Carry | [self-funded native trial](documents/014b5ea21d0f081ff7d490033d77095a57e44930.txt); narrow fee/profile evidence, not an anonymity claim. |
| Compact-state reusable authorization/conflict retry | Adapt when needed | [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt); preserve exact history and successor bindings. |
| Cached wallet-proof validity with fresh economic settlement | Carry bounded mechanism | [7 November result](../../research/cached-approval-verification-2026-11-07/RESULT.md); actual Proven Succinct receipt, fixed image/packet/domain/pool/key, fresh Ledger/effects and unconditional final claim. First use saves nothing; a new guest starts a new bank. |
| Own-key admission, roster-free scanning and backups | Adapt when needed | [Recovery](recovery.md); keep ciphertext/history/parameter availability explicit. |
| Independent/equal-net deposits and two-input payments | Carry experiments and limits | [Privacy](privacy.md); no automatic complete-lifecycle privacy. |
| Address separation | Carry channel-specific mitigation | [address-reuse diagnostic](documents/2571bc032d3c4d3c2c5e55d3264d482b887ca351.txt); it does not eliminate amount/timing correlation. |
| Common cashout, working balances and schedules | Archive rejected selected policies | [working-balance screen](documents/c8f4c9560f157dce4e97190cadeba02133070b6f.txt) and [research journal](documents/a99d0c7618070857506be9bfaa31780dadf32d56.txt); retain mechanisms and failure conditions. |
| Price/participant/known-policy observer models | Carry controls and negative lessons | [price-prior calibration](documents/567b363e0c6151c6d5754b7f79296cc81507a4ba.txt), [participant-disclosure study](documents/bd8f75b9b970b58f9f777314514847c5e8999829.txt); freeze legitimate information and compare priors. |
| Native payout/successor/per-input admission controls | Carry regression contracts | Original `dd00ceed`, `c430dd8a`, `fde0c288` commits in the [ledger](commits.md); do not infer unsampled native modes. |
| Relation ownership/range/padding/tree-capacity controls | Carry regression contracts | `2251864a`, `67793fa4`; constraints and no-mutation refusal are narrower than proof/native qualification. |
| One-v6 adapter and changed-input rejection | Carry actual evidence; park unused adapter work | `acba8b04`, `6fdc5fc6`; one-bundle compatibility is not paired-state settlement. |
| Orchestration/GPU variants/blocked builds | Carry deferrals and compatibility findings | [orchestration record](documents/44291489bf0e020e23b7bf0ba5e92a329ea5c0d9.txt); retain failed attempts rather than starting new variants by default. |
| Paired proof/compression/state journal | Adapt only if the architecture needs batching | [paired proof/compression results](documents/832da77252bdfb3f3b56bd920b236442143f8c2e.txt); distinguish supplied-state proof, state-aware proposal and accepted history. |
| Strict decoding, arity and subgroup checks | Carry | [strict encoding/arity differential](documents/1849f7b489e307a5b02a1b15182d259c64e8819f.txt); preserve full input consumption and version-specific controls. |
| Authenticated uncompressed parameter cache | Adapt when needed | [authenticated cache measurement](documents/90a8571364109e2cb5f360b33e966fedd0ca7308.txt); preserve hashes/trust and measure memory as well as time. |
| Selected SHA/HMAC circuit reductions | Archive as sizing candidate | [selected HMAC sizing](documents/7eb487100c8e69f48abe417e7bcd98c681b24e3b.txt); full relation/proof/native/negative qualification remains necessary. |
| Favorable two-recipient fee layout | Carry bounded result | [two-recipient offline layout](documents/e26b3bf00641382ebabf9b4b577cc31ee1c27d7d.txt); do not transfer its fee ratio to another lifecycle. |
| Reveal exits | Carry explicit tradeoff; archive as private-exit solution | [owner-signed reveal exit](documents/33ec1c21fd325c288ffbc8f1dce471e5113e9f9c.txt) reveals an opening and retains fee/tail limits. |
| MPC/private owner construction | Archive as paused research | [paused handoff](documents/8afbd3d859a68dc4d80194cbdc3f0cc36e5e9961.txt); ADR-0065 result and registered W1 are distinct; rejected patch stays uncommitted. |
| Wallet-local private spend/change | Carry current mechanisms and corrected privacy limits | [Current lessons](../RESEARCH-LESSONS.md); later transparent exits remain a blocker. |
| Historical package replay and owned-group deadline | Carry current implemented repairs | [Repair record](../../poc/remote-cuda/CONSOLIDATION-REPAIR.md); keep exact source and descendant-death checks. |
| Unfinished paired lifecycle/replay/publication reviews | Carry design constraints and corrections | [Unfinished work](unfinished.md); proposed and source-reviewed paths remain labelled. |

Every original branch is represented in [coverage](coverage.md). Branch aliases
share committed knowledge; unique uncommitted work is handled by the preserved
notes and private archive, not inferred from matching HEADs. There is no pending
requirement to merge every experimental runtime merely to access these lessons.
The [regression contracts](controls.md) carry concrete cases from the code-only
native, admission, relation, capacity and verifier-control branches.
