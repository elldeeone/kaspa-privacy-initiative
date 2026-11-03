# Candidate: two privately authorized P0 actions, one new settlement

**Proposed next prototype, not an implemented settlement or fee/privacy pass.**
The public two-action checker accepts the retained ordered transcript and rejects
genuine but conflicting/private-valid-native-invalid alternatives. Its financial
equation also rejects replacing2000 exact authorized inner fees with1000 while
keeping all native effects. This falsifies a drop-in aggregation interpretation.

The smallest candidate worth testing is a **fresh native wrapper policy** with
two local-owner compact P0 proofs, a public semantic execution proof and a direct
private owner fallback. Root must record the selected design in an ADR before
new cryptographic/native implementation. Current funded programs and published
packets cannot upgrade to this wrapper or inherit a new withdrawal authority.

## What remains and what changes

Each owner keeps their own note openings and makes their own compact proof.
The inner relation may retain its existing equations: exact Auth528 SHA binding,
owner/CM membership, original positioned realNF, two-input padding, two output
commitments and input=sum(outputs)+fee. No other owner supplies their note
witness to an aggregator. A one-invoice payment plus sender change is a local
wallet preparation policy; both output commitments remain publicly grouped.

The **new policy**, explicitly selected by a fresh client/profile, authorizes
virtual intermediate bodies rather than individually settling each one on L1.
Therefore it must independently prove all public checks now performed by native
code: exact old/new state/reserve, indexed NF absence/insertion and counts,
ordered CM/CF binding, empty aligned CM append and exact effects. Neither
ordinary proof validity nor old accepted/Full report booleans substitute for
these checks. Aggregation/recursion is an established proof-system mechanism;
the settlement predicate remains a new application specification.

For a financial experiment use a fresh domain, keys, wrapper identity, client
selection and owner Auths. Existing public proofs can calibrate semantic code
only. Do not silently reuse an old statement after changing its fee, root,
outpoint, output commitments or meaning.

## Exact two-action public interface

The wallet exports only its selected public case and proof, not a `Candidate`
object containing private inputs/openings:

```text
trusted installed profile: domain, compact VK, child-template tail,
                          outer program/image, exact public code/parameter identities
external starting head:    actual wrapper outpoint Q0, state S0, reserve R0
public child[i]:           canonical {transaction, entries}; Auth528 and proof128
                          embedded in its payload/private frame, as in current wire
allocated fee[i]:          positive integer Fi, fixed before owner proof
```

1. Child0 Auth.previousPoint is actual Q0; its old state/reserve are S0/R0.
   Each child is compact mode2, P0, destination36zero. Derive its full next state
   from the public two-NF/CM witnesses and verify its genuine inner proof under
   the installed compact VK. Every virtual body has one continuing pool output.
2. Later child Auth.previousPoint is `ID(previous canonical virtual body):0`;
   state/reserve equal that body's derived successor. V1 IDs are official
   keyed-BLAKE3 IDs and include all public payload/effects. Proof randomness in
   signatureScript is excluded, allowing proving to overlap after exact bodies
   are fixed. Invalid/missing earlier proofs cannot become an accepted prefix.
3. A virtual body's SPK belongs to the independently selected **child template**.
   It is not the actual wrapper UTXO's SPK. The outer/native layer separately
   authenticates the actual wrapper program, Q0/S0/R0, and explicitly authorizes
   this projection. Do not describe the virtual context as actual accepted backing.
4. The new actual L1 body consumes Q0 once and creates exactly one continuation
   holding final state S2 and reserve R2 under the same new wrapper. It has no
   native payout list in this first P0-only prototype. Native and outer journal
   must bind this exact actual body, not merely a list of proof hashes.
5. The next batch starts from its actual new wrapper outpoint Q1. No successor
   state commits its own future transaction ID; virtual points remain acyclic.

An outer public journal must unambiguously bind profile/domain/VK/image,
Q0/S0/R0, ordered complete public children/update data, final S2/R2, exact final
native body/effects and the fee allocation. A hash commitment authenticates the
selected bytes, not retrievable data or currentness. Missing delivery bytes
halt recovery; they never become a fabricated zero balance.

## Exact fee allocation, without an implicit rebate

Quote the complete actual outer body at the declared rate first. Allocate
positive integer F0,F1 such that **F0+F1=actual native outer fee F**. Each owner
then fixes output values/CMs/CFs, virtual body and exact Auth before proving.
If the final exact quote changes, regenerate affected private preparation and
proofs; a shape estimate cannot override the actual conservation equation.

```text
for each child: private inputs = private outputs + Fi
virtual reserve: Ri+1 = Ri - Fi
actual settlement: R0 = R2 + F, with F = F0 + F1
```

No unused fee surplus is reassigned to an aggregator, hidden output or new
liability. A future rebate route needs separately authorized recipient/effect
semantics. Fees allocated this way are explicitly shared-settlement fees in the
new profile; they are not silently reinterpreted old individually settled fees.

## Unilateral fallback and stopping conditions

The wrapper must retain a direct private compact owner branch using the **same
original realNF and public roots** as the aggregate branch. A client can refresh
its own proof against current accepted state from one original backup and public
data if a coordinator disappears, with no other owner's witness or future arrival.
An unaccepted aggregate cannot consume a note. An accepted one must publish the
complete data needed for recipient/change recovery and fresh direct spending.

Existing direct compact exits are bounded by available CM append capacity.
Full-capacity private fallback requires the separate no-append exit work; do
not call this general unilateral recovery until that gate passes. Price the
actual enlarged wrapper/fallback and low-demand N1 separately. R0Succinct's
fixed250000-gram tag may worsen N1; proof compression alone establishes no2%
fee result. Revealing fallback remains an explicitly consented disclosure
alternative and cannot qualify a private lifecycle.

Stop or revise if the outer predicate needs another owner's private witness,
if exact fee allocation cannot close, if the native output/current-head binding
is incomplete, or if operator loss/full capacity prevents the declared private
fallback. Compare a Based App against these same obligations; neither require
nor reject it by assumption. No aggregate or virtual body is accepted-chain
evidence until a separately selected native implementation and fresh trial pass.
