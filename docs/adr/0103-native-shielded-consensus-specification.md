# ADR-0103: Native shielded-value consensus specification

**Status:** Accepted for draft specification and conformance research only.
**Date:** 4 November 2026 (Australia/Sydney).
**Origin:** [RFC-0004](../rfc/0004-native-kas-private-payment-boundary.md).

## Problem and constraints

The owner requested a concrete native transaction, state, header, bootstrap,
portable-key and accounting specification after the complete local Orchard V2
interoperability result. Its experimental packet authenticates no real funding
or state. Current Kaspa transaction hashing/signing does not include new native
fields, header version 2 is already used, and pruning does not import the new
state automatically. Independent review/invariant adoption and network
activation remain separate from writing this proposal.

## Draft decisions

1. Specify proposed transaction version **2** and header version **3**, with
   explicit activation manifest and exact canonical hash preimages. These are
   draft allocations, not network-assigned versions. Use actual UTXO values,
   complete modeled effects, all-signing authorization and no witness-selected
   key. First-profile ordinary funding/payout scripts are standard P2PK and
   P2PK-ECDSA, without covenant bindings; arbitrary legacy contracts do not
   silently acquire new shielded-balance/signature semantics.
2. Preserve the complete repaired Orchard V2 construction and two Actions.
   Use a canonical portable capsule of the actual mathematical verifier and
   parameters, including its fixed compatibility transcript scalar. Do not
   replace the old proof transcript input with the capsule hash. Retain the
   upstream Debug-based derivation as provenance, not a portable format.
3. Keep spentness global to the immutable pool across commitment-tree rollover.
   A forest of depth-32 trees preserves old anchors and spending when one tree
   fills. Unchanged Orchard bundles spend under one anchor; consolidating notes
   from different trees needs separate authorized transitions. Current native
   effects apply serially and atomically in Kaspa accepted order, with complete
   undo. Candidate-block qualification and mergeset conflict filtering differ.
4. Commit explicit state into the version-3 header at its existing **past-state**
   point. Do not overload UTXO MuHash or KIP-21. Retain complete native events,
   spentness and witnesses; first bootstrap is full validation replay. An
   authenticated snapshot accelerates an already qualified state, not an
   unreviewed fresh-node/pruning shortcut.
5. State exact integer boundary/backing/supply rules and proposed I-1/I-2
   wording separately. SECURITY-INVARIANTS.md stays unchanged. Resource charges
   have explicit integer formulas and activation-bound coefficients; no
   unmeasured number is represented as an approved deployment price.

The [specification](../spec/native-shielded/README.md) owns byte layouts,
algorithms, conformance evidence and remaining gates.

## Alternatives and objections

| Alternative | Disposition |
| --- | --- |
| Copy the interoperability packet into Kaspa | Reject: synthetic input values, temporary digest/key identity, wider modeled compute/covenant fields and no native authentication. |
| Reuse existing ID/signature hashes unchanged | Reject: new effects and mass/profile fields would not be completely authorized. |
| Support arbitrary old covenant/script inputs immediately | Defer: old contracts may assume old fee/boundary/signature semantics. Standard key-authorized native KAS is the bounded first profile. |
| Single depth-32 append tree | Reject as the permanent native state: full capacity would prevent even exits appending their required padding outputs. |
| New nullifier namespace per tree/verifier | Reject: could give an existing note another spend identity. |
| Source hash or Rust Debug hash as portable key | Reject: neither is a mathematical key encoding. Export fixed public data and preserve exact transcript compatibility. |
| Snapshot authenticated only by provider/hash | Reject: matching self-supplied roots is not chain qualification or history availability. |

Full retention, permanent spentness/anchor growth and one-anchor bundles have
unmeasured costs. Automatic rollover avoids the immediate depth-32 lockup, not
all finite-counter or economic liveness limits. The new format and limited
ordinary-script scope require Kaspa consensus/wallet review. Portable data does
not establish verifier soundness or implementation compatibility by itself.

## Outcome and reconsideration

This accepts the work of specifying and testing a **proposal**. It adopts no
production architecture, invariant amendment, real transaction, consensus patch,
activation, funded trial or MPC/provider restart. Keep RFC-0004 Open. Reconsider
the draft after independent cryptography/Kaspa review, native integration or
cost/recovery evidence; preserve old results and the unfunded packet unchanged.
