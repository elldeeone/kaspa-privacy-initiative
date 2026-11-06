# Real-wallet common-set integration: fixed offline selection

Date: 5 November 2026. Authority: owner request to test with the actual private
payment system and assess useful cost without consensus changes; ADR-0108.

## Workload and comparison

Use the actual `poc/private-note-wallet` depth-four local profile, not a new
note/nullifier design. Fresh Alice/Bob/Carol wallets and fresh native keys:
credit Alice 30 KAS; Alice privately pays Bob 20 with 10 change; Bob discovers
and privately spends that received note, paying Carol 10 with 10 change.
All three finally hold exactly one 10-KAS note. Useful payments total 30 KAS;
count change and withdrawals as costs, never extra useful payment value.
One KAS is 100,000,000 integer sompi. Native fees are separate sponsor allowances.

Compare original actual wallet proofs and direct EXIT statements with an
isolated complete-statement-digest packing of the same relation and common-set
EXIT semantics. Use the same wallets, notes, encrypted deliveries and native
recipient keys in both worlds. Keep old code/proofs/pins untouched. New keys
are experimental one-party setups. Originals and optimized proofs must genuinely
verify. Do not serialize secrets, note openings, setup/proving keys or blinding
factors. Keep synthetic owner-output truth separate until predictions are sealed.

## Required gates

1. All original circuit checks survive except public-input packing. Record exact
   transformation, constraint counts and differential valid/invalid witnesses.
2. Actual Ledger.apply verifies credit, transfer and recipient re-spend; encrypted
   discovery succeeds; duplicate/wrong-root/corrupt proof controls reject
   atomically. Same three eligible exit nullifiers in both worlds.
3. Real blind issuance accepts wallet EXIT eligibility proofs bound to its exact
   blinded request. No final destination/randomizer reaches identified issuance.
4. Native scripts verify genuine full-wallet withdrawal authorizations, exact
   actual effects/current outpoint/root/claim set, principal/fees and successor.
   Each owner can withdraw alone with no coordinator. Wrong destination,
   duplicate/spent NF, wrong root/domain/context/proof, stolen authorization,
   principal/successor substitution and replay must reject at their intended layer.
5. Each owner checks complete actual entitlement before positive proving.
   Native supplied state/global local spentness is not accepted-chain ancestry.

## Observations, truth and privacy decision

Each observer receives all actual public wallet operations, coordinator messages
and native data in its own view. RSA blindness, Groth16 zero knowledge and
recipient-encryption confidentiality are assumptions, not tested cryptanalysis.
Count complete assignments from known input owners to distinct actual payout
keys. Preserve truth in every view. Direct EXIT control must give one assignment;
candidate must retain more than one, including with one legitimate participant.
All-but-one disclosures, full owner maps, old destinations, leaked origin and
issuance randomizers must collapse ambiguity. Unknown metadata must refuse.
No network anonymity, honest real-user cohort or complete payment-privacy pass.
Full mapped drainage still reveals final balances and conservation facts.

## Cost decision and stop rule

Measure exact script units and three-owner withdrawal component masses. Compare
the original fourteen-input and candidate two-input verification floors from
the pinned current L1 schedule. Six necessary owner proofs in this selected
direct-verification route: credit, two payments, three exits. Report the summed
verification-only lower bound before funding, transaction bytes, state rent,
relay/prover services or retries. It cannot qualify a complete route.

Keep historical 100 sompi/mass as the declared comparison price. Show 1 and 10
as price sensitivity, never evidence those prices will confirm. Keep the adopted
2% complete-route target and 30-KAS useful denominator. Compute exact fee-rate
and payment-size break-even frontiers. If the floor already exceeds 2%, stop
claiming this layout is cheap at that size/price; retain the negative result.
Larger payments/lower prices may pass only the floor, not full cost qualification.

No consensus changes, funds, RPCs, broadcasts, provider work, general recursive
aggregation, privileged spending key or resumed paused MPC. Ordinary build/ABI
errors may be fixed; never hide metadata or change thresholds after failure.
