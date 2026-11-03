# Retained preparation failures

No native VM/Full ran in these attempts. Both failures occurred while assembling
signed control bodies; neither changes the covenant, cryptographic relation,
expected rejection or fee thresholds.

1. `control-prepared-01` / `control-preparation-01.log`: lowering supplied R for
   the below-floor continuation initially retained the old output amount, making
   actual fee negative. Native mass preparation rejected the body. Attempt02
   also lowered the proposed reserve output to59,999,999, retaining a positive
   actual fee and isolating the intended reserve-floor guard.
2. `control-prepared-02` / `control-preparation-02.log`: after the deliberately
   impossible NF equality, the ordinary producer selected that duplicate's
   self-link as slot1 predecessor and rejected its interval. Attempt03 computes
   the following slot's remaining strict interval on the counterfactual tree.
   The native expectation remains rejection of slot0's CURRENT authenticated
   equality before any slot1 operation or proof verification.

`control-prepared-03` completed61 signed cases. The separately prepared
`capacity-prepared-01` completed the constructive17th-bit context and its exact
path-corruption companion. Native evaluation remains separately reviewed/frozen.
