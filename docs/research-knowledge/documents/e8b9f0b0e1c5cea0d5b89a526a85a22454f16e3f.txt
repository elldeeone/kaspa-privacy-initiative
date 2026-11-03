# RFC-0019: Fees and independent exit obligations

**Status:** Proposed architecture; bounded offline experiments selected by
[ADR-0039](../adr/0039-exit-liability-and-native-claim-experiments.md).
**Date:** 2026-10-23 Australia/Sydney. Baseline: `8d7d719`.

## Problem

The useful result remains native test-KAS deposit → private claim → private,
value-conserving transfer → double-spend prevention → owner-authorized exit →
confirmed native payout. All [invariants](../../SECURITY-INVARIANTS.md) and
[RFC-0012 requirements](0012-useful-privacy-requirements.md) are unchanged.
The previous [checkpoint](../../research/next-session/RESULTS.md) does not
complete that lifecycle.

One fresh native Groth16 verification has a necessary fee floor above the
smallest supported claim at the 500-sompi/mass scenario. An unamortized ADMIT
and fresh exit also exceed the reference-rate complete-lifecycle budget at
10 tKAS before private payment costs. These are bounds on those routes, not
on every native hash/signature/covenant program. Merely moving authorization
earlier does not remove its fee or make an unaccepted note independently
redeemable. See the [conditional calculation](../../research/next-session/fee-frontier/README.md).

Current primary research includes upstream [fee liveness #23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23),
[permissionless exits #8](https://github.com/olafweller/kaspa-privacy-initiative/issues/8),
[recovery #10](https://github.com/olafweller/kaspa-privacy-initiative/issues/10)
and [accounting #6](https://github.com/olafweller/kaspa-privacy-initiative/issues/6).
These are open questions; this RFC does not close them.

## Distinct states and liabilities

1. **Unconsumed private note:** the owner can privately spend it. An exit must
   authenticate ownership, value and the same current nullifier consumed by a
   competing private spend. A historic membership path alone is insufficient.
2. **Accepted unpaid exit entitlement:** accepted settlement atomically consumes
   the note's nullifier and creates a fully backed, destination-bound exit
   liability. A terminal claim may use a separate stable entitlement ID: the old
   note is already unspendable. The liability remains until payment.
3. **Owner-controlled native output:** payment has already occurred. A P2PK
   output created by settlement is a completed native withdrawal, not another
   unpaid protocol entitlement or a free second protocol exit.

A ticket issued alongside a still-spendable note needs atomic cross-path
exclusion. A detached native ticket cannot remain redeemable after the private
note transfers. A ticket created only by accepted withdrawal settlement does not
solve service loss before that settlement. Claims must retain stable identities
across root extension, ordering, partial batches and reorg observations.

## Candidate routes

| Route | What could be cheaper | Remaining independent-exit obligation |
| --- | --- | --- |
| Existing fresh-proof note exit | No claimed improvement to the retained proof tariff | The solitary owner must produce and pay for a valid fresh acceptance; current minimum-claim economics fail at 500. |
| Accepted settlement, then native claim | Established authenticated-root hash/covenant redemption can omit a fresh SNARK | Earlier authorization, backing, fees and public witnesses must already exist. A user whose note is not yet authorized still needs a path. |
| Deliberately revealing future-format note exit | Native hash/signature checks might avoid the SNARK tariff | A separately versioned note relation must bind destination and the exact same NF without revealing ordinary spending authority; full fee, privacy and state safety remain open. |

The current v6 note opening is sender-constructible; it is not ownership proof.
Its HMAC nullifier uses reusable `wallet.spending`, while its native payout key
is not committed in that note. Existing covenants do not acquire a reveal branch
from this RFC. A future design exposing the sole credential sufficient for
private SPEND permits a private-spend race even if the reveal branch fixes the
payout. Distinct, undisclosed private-spend authority and correctly bound native
exit authority are necessary design questions, not an adopted construction.

## Existing work and reuse

The [pinned comparison](../../research/next-session/native-kas-singleton-fee-alternatives-2026-10-22.md)
reviews current Kaspa/Toccata, vProgs, Kaspa research, Orchard, Aztec, RAILGUN,
Monero and MWEB. This work reuses standard native introspection, hashing,
signatures, Merkle proofs and official transaction validation, not new
cryptographic primitives.

Current vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e` exposes an existing
permission-claim script and delegate funding. It is a useful source for a
native capability/cost experiment. Its accepted permission must not be confused
with an unaccepted private note, and its permission rent must not be confused
with claim principal or free fee funding. Its public runtime is prototype
infrastructure, not a reviewed private-exit implementation. Aztec's accepted
Outbox and StarkEx's revealing frozen-state exit are comparison points, with
different authorization, state and replay rules. The new
[source note](../../research/next-session/exit-fee/PRIMARY-SOURCE-OPTIONS.md)
will record exact files, assumptions and reuse boundaries.

## Selected first experiments

### Finite liability and service-loss model

Build an executable, exhaustively explored abstract state machine, independent
of production wallet/proof code. Three origin notes each have owner A/B and
value 2/3 abstract units. Explore both shared-root entitlements and native P2PK
delivery: 128 initial accounting configurations. Each note can transfer once
to one replacement, then be settled or hypothetically revealed. All batches
consume one to three currently unspent resources atomically. Terminal claims,
service loss, unavailable data, stale state and cross-domain/forged requests
are explicit actions. No arbitrary search-depth truncation may be reported as
complete exploration.

Check conservation against an independent per-origin ledger, native backing
including unpaid entitlements, exact recipients and at-most-once release.
Authenticated relation verification is an explicit ideal oracle, not a proof
implementation. Existing-format revealing authorization remains unresolved.
Hypothetical reveal results are conditional on a future correct authority
relation. Post-settlement owner-only claim reachability and pre-settlement
service-loss counterexamples must be reported separately. Reachability is not
a guarantee under arbitrary contention, censorship or missing all data copies.
Chain-state rollback must not undo observer knowledge from an orphaned or merely
published reveal, service shutdown or loss of all data copies. Publish-before-
acceptance and copied single-credential private-spend races are separate controls.

Exercise fee quotes 1/2 abstract units and settlement fees 0/1 as separately
labeled economic cases. A backed but fee-exhausted entitlement is a liveness
failure; it must not become an accounting pass or disappear. These units are
not sompi or a qualification of the actual fee envelope.

Mutation controls must exhibit counterexamples when current NF consumption,
pending liabilities, stable entitlement identity, current paid-state or exact
recipient binding is removed. Include service dependence of accepted claims
and copied revealed credentials as negative models. Preserve all failed
variants rather than repairing their output labels.

### Existing native permission capability and full cost

Prefer the exact upstream permission emitter and delegate script over a
reimplemented toy. Freeze source/dependency identities and every adaptation
before building. Use only public synthetic supplied UTXOs and official native
Full validation. Distinguish ScriptEngine acceptance from Full acceptance,
consensus validation from relay/inclusion and source-derived bounds from actual
transaction masses.

Measure complete transaction compute/storage/mining mass and exact positive
fees at 100/200/500. Separate claim principal, permission rent, delegate change
and external fee inputs. Test the supported 60M-sompi claim retaining at least
10M payout without pretending another input or rent refund is a self-funded
claim. An unchanged script that forbids fee withholding must retain that
negative result; a zero-fee fixture does not solve the fee blocker. Small reserve
remainders can independently create storage-mass limits even without a SNARK.

Check genuine destination/value/current-root rejection behavior before any
candidate is described as usable. A source concern about remaining entitlements
must be reviewed rather than hidden behind a successful first claim. No native
claim probe establishes earlier accepted private authorization or secure
end-to-end state reproduction.

The first source-preserving probe uses the standard minimum-depth, single-leaf,
full terminal claim, with no remaining entitlement or continuation. The source
review identified a missing old/new path-binding concern for continuing roots;
those multi-claim paths are excluded from qualification and are not repaired or
exercised adversarially by this first cost probe.

## Decision still needed

Do not select a new private-note format, change the proof relation, replace the
adopted fee/privacy targets or change production reserve rules based on the first
cost probe. A further candidate needs a precise authority/fee contract, source
comparison, adversarial review and an explicit subsequent decision. The previously
tool-rejected S7 owner CLI/replay/DRAIN workflow remains parked; these experiments
do not recreate it, restore its PK or conduct funded/broadcast work.

## Candidate C: public-only authorization and native-cost experiment

[ADR-0040](../adr/0040-public-revealing-exit-feasibility.md) selects only a
separate public synthetic feasibility probe, not a private protocol or migration.
The [architecture review](../../research/next-session/exit-fee/ARCHITECTURE-OPTIONS.md)
and [adversarial review](../../research/next-session/exit-fee/EXIT-OBLIGATIONS-REVIEW.md)
identify why two independent secrets and committed native authority are needed.

Use new domain-separated SHA256/HMAC tags, never old v6/S7 encodings:

```text
O  = SHA256(OWNER_TAG || D || private_owner_secret_s || incoming)
K  = SHA256(KEY_TAG || D || note_local_NF_key_k)
CM = SHA256(NOTE_TAG || D || O || incoming || u64LE(V) || rho || K || native_PK)
NF = HMAC-SHA256(k, NF_TAG || D || CM || u32LE(position))
```

The private-side reference predicate requires both `s` and `k`; it is not a
SNARK or proof of knowledge. Native exit reveals `k` and the opening, never `s`
or the native signing secret. It verifies K/CM, current CM membership and a
position below the current count, the exact NF, current NF nonmembership and
insertion, an exact SIG_HASH_ALL signature under the CM-bound native key, and
whole-note accounting `V = payout + fee`, `R' = R - V`. Native payout uses that
key's canonical P2PK script. One input, no sponsor or treasury path.

The new synthetic state uses CM depth16 and indexed NF depth17, with a sentinel,
explicit unsigned counts, one real NF per consumed note, and no old even-count
rule. The reveal path authenticates against the **current** CM root; the owner
must refresh its public path rather than submit a caller-asserted historic root.
The same authenticated sibling/index path updates the NF predecessor; the
empty append path must authenticate the resulting intermediate root before the
new NF leaf is inserted. Range-check both indices and all amounts. Successor
must preserve domain, policy and CM state and change only the authorized NF
state/reserve. A terminal spend creates no zero-valued reserve output.

Freeze at least terminal singleton and continuing two-note/near-capacity cases,
native signatures, canonical wire fields and rejection controls before running.
Price at100/200/500, including storage mass and small reserve remainders. The
60M claim must retain10M with at most50M fees and no other input to pass the
rate500 singleton discriminator. Economic failure is retained, not repaired by
retrospectively changing fees, amounts, supported claims or acceptance criteria.

The private/native union policy is not implemented. Therefore record the actual
probe script size separately and test explicit padded size envelopes where
practical; any mass conclusion for a future combined script is conditional on
that envelope and identical fast-branch behavior. Padding is not an implemented
private branch. No actual future private proof, recipient scanning, accepted
backing, data survival, privacy qualification or confirmed chain payout follows.
Recipient derivation/validation of K and native PK, key/descriptor reuse and
reveal disclosure remain open format obligations. Existing notes stay unchanged.
