# RFC-0004 bounded agent self-review

**Date:** 2026-11-03. **Classification:** agent adversarial self-review and
primary-source/specification checking. This is **not** independent specialist
review, a security audit, approval of cryptographic soundness, or consensus
implementation qualification. No wallet, prover, node, trial or funded action
was run. Only this review note was written by this reviewer.

Reviewed [RFC-0004](../docs/rfc/0004-native-kas-private-payment-boundary.md),
802-line draft, against unchanged
[SECURITY-INVARIANTS.md](../SECURITY-INVARIANTS.md), the current knowledge guides,
the [Kaspa boundary note](native-kas-consensus-boundary-2026-11-03.md) and the
[five-protocol primary-source refresh](native-kas-shielded-value-sources-2026-11-03.md).
Line references below refer to the reviewed draft, before any parent-agent fixes.

| Reviewed artifact | Identity |
| --- | --- |
| RFC working-copy Git blob hash | `c700103197c0a3357ff6dbbd29737ca7da61427c` |
| RFC SHA-256 | `3e63450b806cda61e0934c030a0d08e33133cae5400863c1214427db1e2dcc98` |
| Unchanged invariants SHA-256 | `44cf983d06c8895c61a492107f65487725331a1b2f93d1c89e7353fb5399733d` |
| Repository HEAD during review | `4db133a9004313f2015ec26e800ff5236c4e5166` |

## Result and required corrections

No balance-sign error was found in the proposed equations or five worked
arithmetic rows. The draft correctly leaves the primitive/backend, I-1/I-2
boundary interpretation, DAG integration, long-term data contract and complete
privacy qualification unresolved. Two documentation/specification corrections
are required before presenting it as a source-checked proposal. Neither is a
claim of an exploitable implemented vulnerability.

### C1 — qualify what removing ordinary payout fields establishes

**Location:** RFC lines 235–250, especially 247–250.

The text says the native shielded representation removes the observed attack
inputs and that the balance enumerator can no longer assign terminal amounts
it cannot observe. It removes the **explicit per-owner ordinary payout fields**;
that does not show terminal balances cannot be inferred from other legitimate
information. The proposal deliberately publishes `b` and `B`. If an observer
validly knows only one owner retains the domain's remaining value, public `B`
can disclose that owner's total despite hidden note fields. Counterparty
disclosures and known crossings can supply other constraints. This is a design
inference from the draft's own public accounting and observer model, not a new
privacy experiment.

Likewise, the subtraction statement at 235–237 is exact for one remaining unknown
payout; with multiple unknown confidential outputs it reveals their aggregate,
with individual amounts dependent on additional information.

**Required correction:** say the representation removes the explicit ordinary
payout amount/script inputs used in the retained run; public totals, crossings,
isolated activity and legitimate disclosures may still reconstruct amounts or
relationships. Replace the unconditional individual-payout subtraction wording
with aggregate/one-unknown wording. Preserve the existing no-privacy-pass caveats
at 307–313 and 323–329. Neither an execution result nor a complete observer
analysis exists for the hypothetical representation.

The protocol comparison supports this narrower conclusion: the Zcash protocol
explicitly exposes value crossing between transparent and shielded pools,
and MWEB exposes peg-out amounts/scripts. Neither promises that auxiliary
economic information becomes ineffective. [Zcash boundary](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L3240-L3256),
[MWEB boundary](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L141-L152).

### C2 — make identity-point rejection depend on the cryptographic role

**Location:** RFC lines 378–383, especially 380–381.

The draft groups identity points with encodings that universally reject while
leaving the primitive/profile unselected. Established constructions have
different validation rules for value commitments, signature keys and encryption
keys. Orchard's `ValueCommitment::from_bytes` decodes a Pallas point without a
blanket identity exclusion; its coordinate helpers explicitly handle identity.
Orchard ephemeral encryption keys, in contrast, reject identity. [Commitment
decoding and identity handling](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/value.rs#L379-L405),
[ephemeral-key rejection control](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L966-L987).

**Required correction:** require canonical encodings and the selected
construction's role-specific curve/subgroup/identity checks. Reject identity
only where that role's reviewed rules forbid it. A new profile may deliberately
choose stricter rules, but that choice needs an explicit compatibility/soundness
argument; it cannot be attributed automatically to Orchard or to a generic
"valid point" requirement.

## Checks with no correction identified in this pass

| Topic and RFC lines | Bounded review result | What remains open |
| --- | --- | --- |
| `b`, `F`, `B`; 401–460 | `b = S_in - S_out` has the stated positive-outward sign. `T_in + b = T_out + F` and `B_next = B - b` agree. Each of the five table rows satisfies both equalities. `-F` change in ordinary UTXO stock plus `B` follows algebraically; fees must enter the existing reward path once. | Concrete circuit bounds and field-to-integer proof, all fee/reward application paths, global supply induction and migration. |
| I-1/I-2; 354–358, 444–467, 658–664 | Current I-2 literally lacks boundary credits/debits. The RFC expressly proposes a generalization and blocks implementation until invariant/ADR review. It does not classify payout principal as a fee or silently adopt an old branch amendment. `B` is not counted again as an ordinary reserve UTXO. Atomic direct exits retain the claim unless accepted native effects occur. | Accepted definition of consensus-reserved native backing and liability/supply accounting. An unchanged file is not acceptance of a new interpretation. |
| Ordinary exit versus shielded ownership; 24–37, 307–319 | Public amount/script cannot be concealed after publication. Staying shielded is distinguished from ordinary full drainage. The incompatibility remains explicit if the fixed requirement insists on both full transparentization and hidden known-owner public boundaries. | Q1 owner/privacy interpretation and full observer analysis; apply C1. |
| Nullifiers, domains, versions; 469–501 | Current spentness is separate from historical membership. Duplicate real markers reject, and a verifier/profile update cannot reset a note's spend marker. Exact-once migration must invalidate the old claim and preserve usable artifacts. | Chosen note/nullifier construction, dummy behavior, cross-profile compatibility and vectors. |
| DAG races and caches; 503–529 | Conflicts include shielded markers despite disjoint ordinary outpoints. Nullifiers, pool balance, commitments, ordering and fees commit/undo atomically. Cached proof validity does not bypass current acceptance checks. Accepted order rather than service arrival order governs. | Exact consensus storage/parallel/cache integration and conflicting-block/reorg vectors. |
| Economic effects; 385–399, 427–431, 600–612 | The effects digest includes actual ordinary outputs, outpoints, domains, anchors, `b`, `F`, note outputs and delivered bytes. Sponsor mutation requires express authorization. Dummy bundles cannot bypass missing-input authorization. | Final digest construction, signing/transaction-ID paths and permitted repricing semantics. |
| Duplicate note identity; 549–556 | The draft preserves multiplicity and global positions while explicitly rejecting the assumption that position-based legacy nullifiers and Orchard note identity can be mixed. It requires each counted output to yield the intended spendable claim. | A selected coherent creation-identity scheme, duplicate/migration/dummy rules and Q4 vectors. |
| Recipient delivery; 531–563 | Recipient acceptance requires commitment/domain/range/spendability checks, beyond tag/decryption success. Proven delivery and detectable malformed delivery are distinguished. Viewing authority is not claimed to be complete spending/spentness recovery. | Concrete I-14 guarantees, encryption/key roles, backup metadata and failure behavior. |
| Independent recovery/pruning; 565–596 | Roots cannot restore absent ciphertexts/parameters. Retaining the complete authenticated accepted log is the conservative reference. Independent reachable data or a sufficient owner copy is an explicit liveness assumption. No claim that every copy may vanish while a seed restores value is made. | Bootstrap authentication, mandatory protocol retention/serving roles, cost, pruning and a matched complete-service-loss demonstration. |
| Fees and timing; 598–625 | Exit authorization, affordability, relay policy and inclusion are distinct. Shielded funds may pay public `F`, and service compensation is an explicit transfer. No designated sponsor or free economic exit is promised. | Native fee/mass rules, repricing, dust affordability, long-term retention charges and complete lifecycle cost. |
| Implementation status; 277–289, 675–695, 747–768 | The extension labels itself a requirements proposal, keeps Q1–Q10 open and requires profile/invariant/data decisions before implementation. It authorizes no trial, proof campaign or resumed MPC. | External specialist decisions and later separately authorized implementation/qualification. |

The algebra above is a paper check of the stated equalities, not executed
implementation verification or evidence that a circuit enforces them.

## Protocol-comparison cross-check

| Reference | RFC conclusion checked | Source-supported scope |
| --- | --- | --- |
| Orchard; 240–273, 488–493 | Native note/commitment/nullifier/binding mechanisms are useful design inputs; its Halo2/Pasta proof is not directly accepted by the current Kaspa tags. | Confirmed against the [source refresh](native-kas-shielded-value-sources-2026-11-03.md#orchard-native-shielded-pool-reference). No code port, backend selection or inherited security result follows. |
| MWEB; 228–238, 722–725 | Confidential native value and transparent amount/script peg-outs are distinct; maturity conflicts with the no-forced-delay requirement. | Confirmed; inspected consensus requires six-block peg-out maturity. Confidential-UTXO spend graph differs from hidden note membership. Apply C1's aggregate qualification. |
| Monero | RFC refers to the comparison note rather than treating rings as native KAS note-pool machinery. | No conflict found: RingCT balance, CLSAG/decoys/key images and native-chain/pruning assumptions remain separate. No ring anonymity-set guarantee is imported. |
| Aztec; 540–547 | Delivery modes have materially different guarantees. | Confirmed against current pinned docs and the resolved public `labs` submodule. Onchain constrained delivery constrains encryption/tagging; other modes and historical retrieval have additional assumptions. No sequencer/prover/L1 availability claim is imported. |
| RAILGUN | RFC refers to the comparison note without selecting ERC-20/EVM custody, relay/PPOI policy, administrator authority or code. | No conflict found. V2 contract/circuit/engine pins remain independent of deployment identity, and circuit licensing is unresolved. Public unshielding remains public. |

The reviewer did not re-run upstream programs or convert source inspection into
network activation, privacy, cryptographic or production-safety approval.

## Handoff

Parent-agent action: apply C1/C2 to the RFC, retain its unresolved gates, and
record this artifact as **agent self-review**. The concrete cryptographic profile,
native accounting interpretation, consensus integration, recovery contract and
privacy target still require the specialist reviews named in Q1–Q9. This note
does not supply those approvals.

## Resolution verification

**Checked:** 2026-11-03, limited to C1/C2 wording resolution. Current RFC SHA-256:
`5d069ca6dc29dec43f62d15af8cab9ae4b3a21d221c753d6516e10904f97fbee`.
The original draft identity, findings and line references above remain unchanged.

- **C1 resolved:** under **Established mechanisms to adapt, not invent**, the
  **Confidential native UTXO** paragraph at lines 235–240 now distinguishes
  aggregate outflow from the one-unknown-payout case. The **Native shielded KAS
  pool** paragraph at lines 249–254 limits the claim to removing explicit payout
  fields and retains inference through public `b`/`B`, isolated activity and
  legitimate counterparty disclosures. It explicitly disclaims a privacy pass.
- **C2 resolved:** under **Proposed transaction bundle and encoding obligations**,
  lines 382–390 now require canonical field/group encoding and subgroup checks,
  while identity rejection depends on the selected construction and specific
  cryptographic role.

This is a bounded **agent self-review completion check**, not specialist review,
security/audit approval, a fresh full-draft review or implementation validation.
No new research, experiment or change to the RFC was performed by this reviewer.
