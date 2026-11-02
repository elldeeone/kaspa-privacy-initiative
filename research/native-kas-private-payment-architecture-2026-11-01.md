# Minimal native-KAS private-payment architecture assessment

**Date:** 2026-11-01
**Status:** source review and architecture recommendation only. No production
architecture is selected; no protocol code, proof, MPC run, funding, broadcast,
or Testnet action was performed.

## Answer

Use **wallet-local private proofs with replaceable public processing/proving** as
the minimum credible reference architecture. It best matches the owner's stated
north star with the fewest additional trust and availability dependencies:

```text
wallet constructs and proves an authorized private state transition
-> any replaceable processor/prover packages public effects
-> Kaspa verifies the pinned proof and exact native effects
-> recipient scans authenticated public data locally
-> either user can later spend privately or prove a direct native-KAS exit
```

This route can credibly target hidden historical-note ownership, hidden note
values and hidden recipient descriptors. It **does not hide the public grouping
of one spend marker with that payment's output set**, nor endpoint, timing,
contact, entry or exit correlations. Public grouping alone does not identify the
human sender, recipient or amount; those identifications require auxiliary
information.

Fixed MPC is **not justified as a baseline requirement by current evidence**.
It is an optional research route for the stronger requirement: hide each
payment's input/output partition from both the ledger and the constructor while
allowing owners to go offline after submitting an intent. That offline-progress
requirement came from the research design, not the owner's stated recovery/exit
goal. Even for that stronger goal, the preferred architecture remains
undetermined: the fixed-service design has an unresolved abort/retry attack and
an incomplete/leaking aggregate implementation.

## Verified source state

Read-only checks on 2026-11-01 found these current default heads:

| Source | Head | Relevant fact |
| --- | --- | --- |
| [Olaf Weller KPI](https://github.com/olafweller/kaspa-privacy-initiative/tree/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1) | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | The wallet [creates Groth16 proofs locally](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-wallet/src/wallet.rs#L155-L189); the public guest [verifies proofs and applies effects](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-chain/common/src/lib.rs#L189-L241); and the outer prover package [receives public fixtures, not wallet secrets](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-proof/README.md#L20-L26). The [published TN10 lifecycle](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/tn10-live/README.md#conclusion-and-remaining-limitations) remained operator-controlled and did not establish independent custody or production privacy. |
| [Kaspa docs](https://github.com/kaspanet/docs/tree/0ac77d043a802fc8196abfd5812ac2afbd97a2b9) | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` | Toccata is documented as [mainnet-active](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/index.mdx#L6-L8). [Inline ZK](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx) supports one covenant transition with off-chain proving; [the decision guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx) points shared mutable state and batching toward a based app. |
| [Rusty Kaspa](https://github.com/kaspanet/rusty-kaspa/tree/4edcbbccb449f84832afb1ca157904b35f37d006) | `4edcbbccb449f84832afb1ca157904b35f37d006` | The current [ZK dispatch](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs) exposes BN254 Groth16 and RISC Zero Succinct verification. These verify proofs; they do not supply private construction, consent, recovery data or inclusion. |
| [KIPs](https://github.com/kaspanet/kips/tree/e4ae2332117b5cb68bd6188e065ef885b6d17939) | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | [KIP-20](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md) supplies covenant lineage and transaction introspection, not shielded accounting by itself. |
| [vProgs](https://github.com/kaspanet/vprogs/tree/f9b84a863a7c7c20586a9cf947550475e894f72e) | `f9b84a863a7c7c20586a9cf947550475e894f72e` | The README still describes early/prototype infrastructure. It is a possible shared-state execution/proving runtime, not a private-intent or anonymous-ingress protocol. |
| [Kaspa research](https://github.com/kaspanet/research/tree/c923faca11a49148fa7d912d27ce00197a5c5a4a) | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | vProgs remains a draft architecture reference, not evidence that it is required or dispensable here. |

The primary checkout is exactly Olaf's current `main`. The paused research
checkout was verified read-only at `4d54dc026098506dd56dc568b20cab269be2b447`
on `research/shielded-kas-feasibility`; its only modified tracked file was the
handoff's deliberately retained rejected vendor patch. It was not touched.

## Evidence classification

- **Verified facts:** the source heads and contracts above; Olaf's bounded
  wallet-proof/native lifecycle; the `c41e733e` two-shuffle observation; the
  clear W1 constructor map; and the bounded changed-cohort wire failure.
- **Inference:** wallet-local construction has fewer privacy/availability trust
  dependencies for the owner's stated goal; fixed MPC follows only after adding
  hidden-partition plus post-submission-offline requirements.
- **Proposal:** treat route 1 as the minimum reference and run the frozen offline
  comparison below before selecting any successor architecture.
- **Unknowns:** effective anonymity with realistic auxiliary data, production
  proof/circuit security, costs and contention, independent off-host recovery,
  whether a based app is required, and whether any joint route can preserve both
  retry privacy and useful liveness.

## One observer model for all routes

Use the same observers instead of changing the privacy claim per candidate:

1. **Ledger observer:** all mempool, accepted and reorg history; deposits,
   exits, NFs, commitments/ciphertexts, fees, shapes, order and timing.
2. **Service observer:** the ledger view plus request endpoints, sessions,
   arrival/order/timing, retries, failures and all data legitimately received by
   the processor/coordinator. For joint routes, add one colluding wallet and one
   corrupt MPC party/server.
3. **Excluded stronger observers:** broken cryptography, compromised honest
   wallets, two corrupt servers in a 2-of-3 privacy design, or a global network
   observer. These must remain explicit unknowns, not silent exclusions.

Target properties must be kept separate:

- **Historical-note unlinkability:** a public NF does not reveal which earlier
  note commitment it consumes.
- **Payment-group hiding:** observers cannot map each input NF to its payment and
  change outputs inside a larger public set.
- **Identity/amount anonymity:** auxiliary entry, exit, contact, amount, order,
  timing and endpoint data do not identify the parties or value.

The first property does not imply the second or third. A visible `1 NF -> 2
outputs` group reveals transaction structure, but not by itself the owner,
recipient, plaintext amount, or historical input note.

## Candidate comparison

| Route | What can be reused | Custody and exit authority | Additional privacy trust | Censorship / availability | Data availability and recovery |
| --- | --- | --- | --- | --- | --- |
| **1. Wallet-local proofs; replaceable public services** | Olaf's local Spend/Output proof pattern, exact-effects binding, local scanning, direct AuthExit; Orchard-style local building; Toccata inline verification or a proved public wrapper | Wallet keys authorize spends/exits. Processor/prover has no withdrawal authority if it receives only public inputs and bound owner proofs. | No service privacy trust for private witnesses if proofs stay local. Anonymous ingress is separately required to hide sender network origin. Ledger still sees each payment group. | Services may delay or censor but are replaceable/self-hostable. Shared-head movement can stale a proof; reconciliation must not weaken state binding. | Requires complete authenticated public commitments/ciphertexts, accepted history, parameters/software and user seed. A root alone is insufficient. |
| **2. Interactive construction among participating wallets** | The ADR-0065 two-shuffle construction and existing Spend/Output proofs; ephemeral MASCOT roles can be participants or replaceable helpers | No participant or coordinator should gain custody. A failed round leaves the original notes directly exitable. | Requires the declared corruption threshold, at least two honest unknown payers after colluder subtraction, and a real private runtime boundary. Participants/coordinator still see cohort and network metadata. | Every selected owner must be online for construction/final authorization. Any participant can abort. No permanent service group is required. | Accepted outputs recover from seed plus public data; failed rounds need no private service state for exit. Retry privacy remains unresolved. |
| **3. Dedicated asynchronous MPC service** | Restricted owner intents, hidden-partition aggregate relation, public R0/native wrapper, direct exit; MP-SPDZ/collaborative-proof families are research building blocks | Servers must never obtain unrestricted spend or withdrawal authority. Sound intent proofs/native verification, not server signatures, protect funds. | Adds a fixed threshold assumption (proposed: privacy with at most one corrupt server of three), private input admission, collaborative proving, non-rollback disclosure history and service-affinity policy. All-server or trusted-host access breaks confidentiality. | Owners may leave after input, but private progress depends on the fixed service and its durable history. Loss/collusion can censor or force direct exits. Moving services can itself violate retry privacy. | Accepted notes can still recover from seed/public data. Unaccepted intents and disclosure history are service state; accepted chain state cannot reconstruct them. |

### What current evidence actually demonstrates

- The wallet-local line completed a bounded native test-KAS lifecycle with local
  wallet proofs and native settlement, but the published run used one trusted
  operator for the logical recipient. It does not demonstrate independent user
  custody, network anonymity or production privacy.
- Commit `c41e733e88c0e1b60cf6113b2ac90728fe6c57f6` executed one fresh
  three-owner ADR-0065 construction with two genuine MASCOT shuffles, three
  Spend checks, six Output checks and CPU guest execution. The declared
  coordinator had 540 structurally possible complete maps; coordinator plus one
  wallet had six. This is real bounded evidence that joint computation can hide
  the direct map under its assumptions.
- The same result does not protect against the trusted host, two colluding
  wallets, network/timing correlation or active retry intersection. It does not
  validate the ADR-0074 aggregate path.
- ADR-0074/W1 still builds the owner/input/two-output map in plaintext before
  serialization. Removing files from an observer's input is not an enforced
  private runtime boundary. The registered relation/admission authority remains
  absent, so the intended fixed-service financial path is incomplete.

## Why fixed MPC appeared

The chain of requirements was:

1. **Owner requirement:** shield native KAS, pay privately, let the recipient
   spend or exit, and preserve user-controlled recovery if services disappear.
2. **Research privacy target:** additionally hide each owner's input/output
   partition from both the public ledger and the constructor.
3. **Research liveness assumption:** allow owners to submit once and go offline
   before cohort selection, head refresh, construction and proving finish.
4. **Implementation choice:** store private intents with a fixed threshold MPC
   service and produce the hidden-partition proof collaboratively.

Only step 1 is the stated north star. Step 2 is a valuable stronger privacy
goal. Step 3 is not yet shown to be necessary. Step 4 follows conditionally from
steps 2 and 3; it is not a consequence of ZK itself. A wallet can generate a ZK
proof locally, and a replaceable service can process or prove public composition.

## Strongest unresolved attack

The strongest demonstrated joint-route failure is **pre-confirmation egress plus
changed-cohort retry intersection**:

1. Honest A and B join colluder C. A valid ABC transaction leaves the private
   constructor, publishing three stable NFs and the batch timing/cohort before
   confirmation.
2. C races an independent direct exit. The exit consumes C's note or the shared
   reserve head; the ABC transaction becomes stale and correctly fails.
3. A and B remain unspent. The dispatcher retries with known changed cohorts,
   for example A+D+E. Stable NF-set intersections and the colluder's own NF can
   identify A.
4. Fixed **server** membership does not fix changed **wallet** cohorts. Fair MPC,
   a valid SNARK, Tor, fresh aliases and later file deletion do not revoke the
   already released observation.

The bounded wire diagnostic recorded 3/3 eligible-owner matches for a changed
cohort and 0/2 for its same-cohort control. It was synthetic wire evidence, not
financial settlement or a general anonymity proof.

The same realistic auxiliary channels must accompany any comparison:

- a transparent deposit may expose owner, amount and time;
- authenticated invoice/contact exchange tells the recipient who paid and how
  much, and can reveal a stable delivery address to observers of that exchange;
- submission order and endpoint can label a wallet-local NF immediately;
- public fees, reserve movement and unequal payment/change arithmetic can narrow
  output assignments;
- retries repeat stable NFs;
- a transparent exit reveals destination, amount and time and can correlate
  earlier hidden activity.

These channels can turn public grouping into identification, but grouping alone
does not establish it.

## Reuse boundary

Reuse concepts and existing reviewed code where their predicates remain exact:

- **Orchard:** local bundle construction, separate authorization/nullifier/value
  binding and historical anchors. Do not treat this as a simple port to Kaspa.
- **RAILGUN:** signed complete-effects binding, membership, nullifiers and
  conservation. Public per-transaction arrays still preserve grouping.
- **Aztec:** client-side private execution/proving and the separation of private
  inputs from public effects. Node queries and note delivery remain metadata/DA
  concerns.
- **Monero:** separation of deterministic spend markers, authorization and
  confidential balance. Its ring/native-asset model does not supply a Kaspa
  reserve exit.
- **MWEB:** aggregation and client-side recovery lessons. A merger or network
  observer that saw pre-merge transactions can retain their map.
- **Kaspa/Toccata:** exact proof verification, covenant lineage/effects and
  native settlement. These primitives do not provide private construction,
  anonymous ingress, complete recovery data or guaranteed inclusion.

vProgs remains conditional. It may be useful if measured shared-state contention,
batch verification cost or lane-ordered execution requires a based app. It is
not required merely to generate private wallet proofs, and it does not by itself
solve private admission or constructor-map privacy.

## Smallest decisive next experiment

Run one **offline finite information-flow comparison**, not another proof/MPC or
Testnet build. Freeze it before generating transcripts.

### Workload

- Wallets A/B are honest, C colludes, D/E are alternate honest cohort members.
- Structural control: every input is `2,000,000,000` sompi; payment
  `100,000,000`, change `1,890,000,000`, fee `10,000,000`; fixed-size records and
  distinct stable NFs.
- Auxiliary cell: prospectively fix unequal transparent deposits, payment/change,
  invoice-contact facts, ingress endpoints, arrival order/times and later exit
  destinations/amounts. Do not choose them after seeing results.
- Compare the same payment intent under route 1, an interactive ABC round, and
  an asynchronous fixed-service ABC round. Force C's exit race, then offer the
  frozen changed-cohort retries including A+D+E and a same-cohort control.
- Remove every service after modeled acceptance and after modeled failure.

### Observations and queries

Give each scorer exactly the ledger or service view defined above. Keep hidden
truth separate until scoring. Enumerate all assignments consistent with each
view and ask:

1. Which historical commitment did each NF spend?
2. Which owner supplied each NF?
3. Which two outputs are that owner's payment/change?
4. Who is the recipient and what is the amount?
5. Which attempts and later exit belong to the same owner/payment?

### Frozen success criteria

- **All routes:** exact authorization/conservation/single-spend/native-effect
  controls; seed plus authenticated public data recovers accepted notes and a
  direct exit without any service secret, partition map or pending journal.
- **Route 1 claim:** ledger view cannot identify the historical input note,
  plaintext recipient or values under the declared cryptographic boundary.
  Record public 1-to-2 grouping and service-origin linkage as known disclosures,
  not failures hidden by redefining the claim.
- **Stronger grouping claim for routes 2/3:** after colluder subtraction, at
  least two complete honest owner/partition assignments remain under both
  declared views for the accepted batch and every retry trace.
- **Service-loss test:** loss may halt private progress but must not authorize
  theft, erase liabilities or block a valid independent exit.
- **Stop:** fail a candidate on any clear-map materialization, unique claimed
  assignment, rollback-dependent disclosure history, unauthorized financial
  discretion or service-dependent exit. Preserve the expected retry failure.

This experiment decides the real architecture fork cheaply: if the owner accepts
wallet-local ledger confidentiality with explicit per-payment grouping, fixed
MPC is unnecessary. If hiding grouping from the constructor is mandatory but
owners may coordinate during payment, test the interactive route first. Only if
both grouping privacy **and** post-submission owner absence are mandatory is the
fixed-service route justified for further research—and its active-retry/privacy-
liveness failure must still be resolved.

## Plain-language recommendation

Start with wallets making their own private proofs and keep every processor,
prover and relay replaceable. Those services may compute or delay a payment, but
must never hold the user's keys, decide where value goes, or control withdrawal.

The concrete evidence gap is not “can three servers shuffle data?”—one bounded
run already showed that they can improve direct-map ambiguity. The gap is whether
users actually require hiding each payment's public input/output group strongly
enough to accept a fixed privacy committee and its availability/history risks,
and whether any joint design can survive realistic failed-settlement retries
without either identifying users or permanently halting private payments.

## Local evidence reviewed

- `SECURITY-INVARIANTS.md`; `docs/shielded-kas-next.md`.
- ADR-0065/0066/0068/0074 and RFC-0028/0029/0030.
- `ASYNC-HIDDEN-PARTITION-DESIGN-01.md` and
  `PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md`.
- `THREE-OWNER-CONSTRUCTOR-PRIVACY-OBSERVATION-2026-11-01.md` and the immutable
  `c41e733e` scorer/source.
- `RETAINED-W1-OWNER-MAP-OBSERVATION-2026-11-01.md` and
  `REGISTERED-RELATION-ADMISSION-BLOCKER.md`.
- `RETRY-PRIVACY-OPTIONS.md` and the final paused-session handoff at `4d54dc0`.
