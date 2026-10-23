# When a whole-note terminal output is justified

This is a conditional invariant argument for the public synthetic candidate C
probe, not evidence of accepted backing or a verified future private relation.
Independent adversarial review checked the argument before terminal fixtures
were selected. Existing v6/S7 code and covenants are unchanged.

Let L be **all** nonnegative current user liabilities in the spending domain,
including private notes, unpaid exit claims and refundable user credits. Let R
be the actual native reserve input. Assume the exact prior state is valid and
preserves [I-1](../../../SECURITY-INVARIANTS.md): `L <= R`. A correctly
authenticated, currently unspent whole note of value V is one of those
liabilities, so `V <= L`.

If the actual input satisfies `R = V`, then:

```text
V <= L <= R = V  =>  L = V
consume that note: L' = L - V = 0
native accounting: payout P + authorized miner fee F = V
                  R' = R - V = 0
```

There is no remaining positive liability and no need to create a zero-valued
reserve output. The transaction must pay exactly the authorized owner, bind its
fee and all outputs under the CM-committed key's exact SIG_HASH_ALL signature,
check ranges/current NF exclusion and permit no other reserve release. Old
spent CM/NF leaves need not disappear: historical leaves are not live liabilities.
No separate total-liability field or fresh exhaustion SNARK is needed for this
deduction **if the prior invariant and membership/nullifier premises hold**.

The conditional native fixture therefore can test a terminal `R = V` body and
continuing `R > V` bodies using the same note/authority rules. The probe does
not establish those prior-state premises. A supplied root containing another
unspent positive note W when `R = V` would give `L >= V + W > R`; it is an
invalid underbacked context, not a counterexample to the deduction. Native
validation alone cannot diagnose all such invalid hidden initial states. The
future admission/private proof relation must preserve I-1 inductively before
this could be a real protocol exit. Unavailable witnesses and economical fees
remain separate liveness requirements.

The distinction prevents two overclaims: rejecting every terminal case merely
because no public L field exists, and claiming that one successful supplied-
context terminal transaction establishes backing or a complete exit lifecycle.
