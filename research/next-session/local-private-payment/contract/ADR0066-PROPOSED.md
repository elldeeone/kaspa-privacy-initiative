# Proposed ADR-0066: Local one-input/two-output native KAS payments

**2026-10-25 UTC. Draft for root review; not the authoritative ADR.**

The highest existing ADR at review was 0065. Root owns the final shared ADR and
architecture/RFC/threat-model synchronization. This draft changes no old source,
pool, parameters, trial or result.

## Problem

An ordinary payment currently recruits live owners for 3-input/6-output MPC.
Its disclosed stable NFs and known changing cohorts permit the recorded bounded
abort/retry attribution. Fair delivery alone cannot prevent a competing exit
from consuming the exact reserve head. One funded note is also insufficient for
a local 3-input self-spend. Research needs an independently constructible payment,
original-seed recovery, repeated spending and permissionless full-note exit.

## Proposed decision

Select the new [local contract](SPEC.md) and its
[prospective privacy/acceptance scope](PRIVACY-AND-ACCEPTANCE.md): one genuine
owned input, two real outputs, local owner authorization and an authenticated
public recipient invoice. No live co-owner/MPC or public roster is needed.

Select financial domain
`b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c`,
the SHA256 of the fixed context in SPEC, with no newline. Select the exact
`KPXA` tags, header `(1,1,2,0)` with reserved-zero roster bytes, and
core3756/body3884/projection4077. Retain the existing note/recipient/tree/
value-commitment algorithms and range rules, refresh all Spend/Output/Exit
circuits and keys for compiled D and statement tags, and select new component
profile, outer guest/image and immutable native policy. No old notes or backups
migrate. Start with fresh unfunded trial identities and owner-held seeds.

Keep complete accepted-state/effects/outpoint binding, exact invoice/output/
change consent, integer value conservation and all security invariants. Payment
fees match native reserve reduction. Direct full-note exits use the new domain
and Exit VK, never require another owner/MPC/shared outer prover, and support
terminal zero reserve. Original-seed scanning uses complete authenticated public
history and encrypted receipt indices; no private map/attempt journal is required.

## Privacy and trust boundary

Accept explicit public one-NF/two-output grouping for this bounded research
profile. The intended ledger confidentiality concerns consumed-CM/NF linkage,
note values and recipient descriptors under established proof/encryption
assumptions. A known submitting origin reveals its NF owner. Select the
[established Tor adapter](../SOURCES.md): explicit SOCKS5h with remote DNS,
fresh isolation credentials, verified TLS, no identifying application metadata,
redirects, direct fallback or automatic rebroadcast. Its independent read-only
probe is not integrated payment evidence or global-timing anonymity. Invoice authentication is supplied by
an independently authenticated recipient channel; sealing a receipt does not
authenticate that channel. Stable delivery keys link invoices seen by an
observer. Timing, ancestry, native amounts, counterparties and repeated NFs may
still disclose ownership. No general financial-privacy qualification follows.

Fresh D requires fresh setup/key artifacts; correctness/trust of those artifacts
and selected software remains explicit. Public history/software availability is
required. Same-host processes do not establish separate administration. Shared
head conflicts and reorgs require safe reconciliation/reproof; no permanent
unpublished note lock, privileged exit delay or operator withdrawal is added.

## Alternatives

- Local 3/6: retain shape in principle, but needs three eligible owned notes and
  does not create three-party anonymity; reject as the first-note payment path.
- Fair hidden MPC: established alternatives remain research candidates, but add
  secret tree/hash/proof verification/consent/fair-release obligations and still
  do not guarantee chain settlement; defer for this milestone.
- Historical anchors/reusable intents/direct combined relation: defer pending
  separate authorization/circuit/setup/cost review; do not reinterpret the
  existing exact-effects field or silently optimize the financial statement.
- New token/vProgs migration/mainnet/admin exits: no demonstrated requirement and
  outside the authorized native-KAS research scope.

## Acceptance and consequences

Source/design acceptance precedes financial implementation. Require independent
byte/state agreement, malformed/replay/boundary controls, genuine selected
component/outer/native execution, original-seed received/change recovery,
repeated spends, service-loss independent exits and complete fresh testnet
rehearsal with terminal confirmed payouts. Passing controls do not prove
cryptographic soundness or production safety.

Keep old frozen62 plus continuation4 and their observer results unchanged. The
old 1/6 output criterion does not pass under two public outputs. Preserve the
matched six useful payments/21-KAS volume and nine exits; all-in 2% stays FAIL
until actual matched measurement. Record fee, privacy, lifecycle and availability
verdicts separately, retaining failed attempts without retuning the baseline.
