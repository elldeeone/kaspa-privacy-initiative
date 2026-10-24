# External source review, initial in-progress snapshot

Read from the user-referenced Codex task `01a16d64-20c3-7e42-b7d6-60a2e9b4491b`
on host `remote-ssh-discovered:forge`. This is the reviewer report, not a security
approval or evidence that the later integrated implementation passed. Source
was changing during the review; findings must be checked against their hashes.
The independent reviewer made no implementation edits. Original task access
mode/model is not inferred from the thread title or this report.

The implementation team is addressing the fixed-domain and variable-size
transport findings; later source receipts identify those changes. The initial
review did not include genuine component proofs or Native acceptance.

## Report

+**Review result: incomplete.** The current prototype has a source-level complete-row shuffle design and a public wire parser, but it has not demonstrated private native-KAS payments or resistance to input-to-output grouping. I made no repository changes.

### Confirmed findings

1. **Financial verification is not implemented.** The relation crate contains witness request parsing but no circuit entry point, Spend/Output proof implementation, or tests of those relations. The current public parser explicitly reports `g16_verified: False` and `native_VM_executed: False` ([request.rs](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/relation/src/request.rs:91), [wire.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/verification/wire.py:207)). A file listing found no native guest or predicate in this prototype. Value conservation, canonical commitments and scalars, membership, stable nullifiers, replay prevention, and actual native acceptance therefore remain **incomplete**, regardless of host assertions.

2. **The MPC session validator accepts a foreign domain.** It checks that `domain_hex` is 32 bytes of lowercase hex, but does not require the contract’s fixed D ([codec.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/codec.py:68)). A fresh synthetic session with `domain_hex = "ff"*32` was accepted. This is a descriptor validation gap; no native cross-domain acceptance is demonstrated.

3. **The trusted launcher is a material privacy boundary.** It stats each owner’s input file and has working Docker daemon access ([backend.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/backend.py:201), [backend.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/backend.py:293)). Decimal input length depends on the two supplied rows. In a fresh synthetic six-row fixture, input file sizes were `2615, 2621, 2619`; knowing one participant’s two rows left one pairing of the other four consistent with ordinary 74–76-digit betas. **This exposes grouping to the launcher, not to the newly isolated coordinator process.** The source now gives that coordinator public IPC without owner paths or a Docker socket ([coordinator.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/coordinator.py:33), [BOUNDARY-02.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/BOUNDARY-02.md:9)). The launcher must remain a trusted administrator; its Docker capability must not be attributed to the coordinator or silently included in the coordinator observer model.

The public digest layout matches the intended authorization distinction: in a synthetic framed body, changing a Spend proof byte left `EffectsDigest` unchanged, while changing an Output proof byte changed it ([wire.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/verification/wire.py:202)). That permits a different **valid proof witness** for the same effects; it does not permit a changed output, fee, state, or other covered financial effect. No owner code yet checks those effects before producing a genuine Spend proof.

### Unconfirmed concerns and missing coverage

- [kpx7_mix.mpc](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/kpx7_mix.mpc:8) calls `secure_shuffle()` on complete rows and checked reveals of rows and aggregate Delta. I did not run the pinned malicious MPC engine or obtain a complete legitimate coordinator transcript with one participant’s knowledge. The IPC includes per-party completion times; their effect on grouping has not been measured.
- Owner-local output checks, final authorization, recipient recovery, and rejection of omission, substitution, duplication, equivocation, participant loss, and late disclosure are documented but not integrated. A previously authorized valid body may still settle; timeout cannot establish revocation.
- There is no genuine nine-proof positive, actual native predicate result, or accepted-state replay test. The six current codec tests passed; they establish only the tested byte and parser behavior.
- A synthetic hardlink read probe was rejected by `PublicGuard.metadata` with `public-aliases-original-private`. I stopped that probe. No existing backup, private runtime input, or ownership map was read.

### Three priority fixes

1. Implement and test the separate Spend/Output relations, owner-local effects checks, and actual native guest/predicate together, using genuine proofs and adversarial state and balance cases.
2. Use constant-length owner input transport and remove unnecessary per-party timing from coordinator IPC; keep the Docker-capable launcher explicitly outside the adversarial coordinator boundary.
3. Enforce the fixed domain and selected profile/context at session ingress, then implement and test failure, retry, and old-body reconciliation without disclosing honest output mappings.

**Privacy statement:** The reviewed source specifies a complete-row shuffle that could hide grouping from its isolated coordinator. The current tests do **not** demonstrate that privacy property for genuine proofs and a complete native body. They also do not cover launcher compromise, timing correlation, transparent entry or exit, or recipient and external knowledge.

**Snapshot:** HEAD was `212378eee9681c2b1aed31b0276c39d211f18e82`; the prototype files were untracked and changed during review. These are SHA-256 hashes from the final source check:

| Reviewed file | SHA-256 |
| --- | --- |
| [AGENTS.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/AGENTS.md) | `c605a5c07d1edbdee45ada102e0c21913e663a506219190818d846179bc6d6fb` |
| [SECURITY-INVARIANTS.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/SECURITY-INVARIANTS.md) | `67b6e7ab82d8a57ab43967e1ac8414b07d34ca769717e52a1b941650ac2da2f5` |
| [ADR-0063](/home/luke/projects/kpi-intensive-2026-10-22/continuation/docs/adr/0063-owner-private-payments-prototype.md) | `28ca1f1bcd4523e56e8345081753c83f3a9e38aa61f0f842e3ab0c653b509dba` |
| [CONTRACT.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/owner-private-prototype/CONTRACT.md) | `6f93593a2073761719ab0e71ee74553f29ca5890e71fbe568a3abd0c92aedd34` |
| [construction/API.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/API.md) | `49dcc205bd914e987b63e57629d33e8adbb4a5417e2de2a01b37dd479665638f` |
| [construction/BOUNDARY-02.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/BOUNDARY-02.md) | `58e463965101fbf6b5619fce896aa2d7808b6bd28072d1a59efcf9068e51b70b` |
| [construction/DESIGN.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/DESIGN.md) | `fb8de6d6258c181ace635ae62f6e01162ef482d6de208b0291c5f88997676c17` |
| [construction/DESIGN-01.json](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/DESIGN-01.json) | `9dd80cf3f8ebc4ee7fa7b16dd16f6e4a4c375d7531be483a2732bdb6f020d7a5` |
| [construction/SOURCE-01.json](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/SOURCE-01.json) | `bf96ba61ed939f9440301249596b3ea2bff0cb447994cb6af97776d70c35d0cf` |
| [construction/backend.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/backend.py) | `525d8609ebf339707869d16ef58f7e56987989c9183bcf5f8eca38e53c2f8a48` |
| [construction/codec.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/codec.py) | `d891786a59b961346eb4f6b266b1087b0c5f95df67c89839791efc80c20ae484` |
| [construction/coordinator.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/coordinator.py) | `99fb2e738664fe77290d2fb3cde9158fba33b756a96d0b29ae334ccdabd57f98` |
| [construction/kpx7_mix.mpc](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/kpx7_mix.mpc) | `fbf7b425cfd996db032edf33151440c3bf14dba2b8a89eaa3df9be7888bcf44d` |
| [construction/party.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/party.py) | `4a521f44dc601a19088e39185f145c1aa90b1fa3a2b949f39a527ec7e3b48849` |
| [construction/test_codec.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/construction/test_codec.py) | `3fd28c4bc90cfbc4207ff25a7d44b042fba40154d80e3c1972b5621b8da13357` |
| [relation/API.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/relation/API.md) | `585dd91f7ece2bc46afd737671e3e860af0c0d2ac289b97ccc6134a66947c5fd` |
| [relation/Cargo.toml](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/relation/Cargo.toml) | `1de5f4bd03f1ef5af2f0acd290a10b55b1c787260e38b5a2c58b83d901f7460c` |
| [relation/src/request.rs](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/relation/src/request.rs) | `d9c64fb104896989282c026bef11e5c0057e4501ae237305fd725891826a8802` |
| [verification/DESIGN.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/verification/DESIGN.md) | `9f5d72d1ef9f0bb11dd7bf284ad60eb27eebac98d44f7112302ba6a1731bd0e8` |
| [verification/wire.py](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/verification/wire.py) | `e4a8c388d00399a3c41b6592912f07b0f8e39db521433a01a4ac9a73e75e9ae0` |
| [wallet/BOUNDARY.md](/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/owner-private-payments/wallet/BOUNDARY.md) | `004a28fa2b6cc2b6991b823983da554413daec3040107c6e5d60a77a24fbfabd` |
