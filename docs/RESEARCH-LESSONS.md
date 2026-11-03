# Research lessons and authoritative corrections

Use [project status](PROJECT-STATUS.md) for current work. The evidence below
retains its original profile and scope. A failed experiment can close a
hypothesis without qualifying a payment system.

## Privacy findings to carry forward

| Finding | Result to use | Consequence |
| --- | --- | --- |
| Immediate full-payment exits expose amounts | [Wallet-local measured result](../research/wallet-local-payment-privacy-2026-11-01/RESULT.md) | All three corrected offline trials exposed the payment amount at direct exit. Neutral local service tokens did not demonstrate network anonymity. |
| Continued private spending helps before cashout | [Continued-spend result](../research/wallet-local-private-spend-2026-11-01/RESULT.md) | Receiving and re-spending increased bounded ambiguity; later exits could collapse it. Do not extend the pre-cashout result to complete lifecycle privacy. |
| Hidden labels are not payment privacy | [Role-conditioned correction](../research/wallet-local-shared-history-2026-11-01/CORRECTION-V2.md) | Score the observable withdrawing role. Keep commitment/position uncertainty separate from known payment facts. |
| Private change helps only while it remains private | [Private-change result](../research/wallet-local-private-change-2026-11-01/RESULT.md) | A self-transfer plus whole-note exit improved interim amount ambiguity; later remainder exit reconstructed the original equation. This is not atomic exit-with-change. |
| A unique wrong prediction is not reconstruction | [Live truth-consistency correction](../research/full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md) | The original strong observer assumed the wrong contact edge. Require a complete candidate history retaining execution truth; marginal fact retention is insufficient. |
| A common reserve removes one link, not the balance attack | [Actual-transaction analysis](../research/full-drainage-executed-lifecycle-2026-11-01/NEXT-PRIVACY-RESULT.md) | The offline mitigation changed funding-origin candidates from one to two, but payment histories stayed two. It was rejected and not implemented. |

The first wallet-local analyzer inserted already-known assignments/counts rather
than measuring them. Its [explicit correction](../research/wallet-local-payment-privacy-2026-11-01/CORRECTION.md)
must accompany that historical assessment. Original SCORE files and reports
remain available for reproduction; they do not override their corrections.

For the successful native run, the corrected limited known-owner model retains
two gross histories. Both reveal B's 20,000,000-sompi payment to M; A's payment
to M remains 30,000,000 or 40,000,000 sompi. The observer assumes supplied owner
mappings, a finite amount grid and a possible-contact graph. This is neither
general anonymity nor a theorem that every gross payment history is disclosed.

## Earlier negative results remain binding evidence

The following files live on the archived feasibility history. The links pin
their exact committed version rather than depend on a moving branch.

- [Working-balance/partial-withdrawal screen][working]: one overlapping cell
  improved; sparse cells missed the frozen gate and receipt-correlated payouts
  exposed more amounts. Retain the mechanism without adopting the failed policy.
- [Price-prior calibration][price]: 512 fresh ledgers found the chosen heuristic
  worse than price guessing. This bounds that heuristic, not all available
  transaction information. The known approximately 21.10% prior also exceeds
  the unchanged 20% absolute target; that requirements tension remains explicit.
- [Participant-disclosure screen][participant] and [address reuse][address]:
  counterparty knowledge and ordinary script reuse can disclose facts even when
  proof, encryption and nullifier primitives are assumed to work.
- [Owner-paused handoff][handoff]: the ADR-0065 constructor had 540 public maps
  and six under one owner's legitimate knowledge in one bounded run. The
  ADR-0074/W1 constructor still learned the clear map and its registered path
  remained disabled. Filtering output files cannot remove prior knowledge.

## Reusable engineering

| Component or result | Evidence | Keep its limitation |
| --- | --- | --- |
| RTX 3070 proof reproduction | [Four outer receipts][reproduction], 627.3 seconds total with smaller segmentation | Reused inner proofs and fixed local inputs; not native-chain acceptance. |
| Direct self-funded fees and independent exits | [Self-funded trial][self-funded] | A small fixed profile, one node and experimental setup; no useful anonymity measurement. |
| Compact state, reusable authorization, conflict retry and scanning | [Independent research journal][journal] | Bind each result to its version. Historical-anchor disclosure, shared-state contention, fees and data retention remain material. |
| Native proof compression | [Paired verification/compression][compression] | Native bare-predicate success is not a backed continuing pool or accepted ancestry. |
| Authenticated parameter loading | [Uncompressed-cache measurement][cache] | Loading fell to roughly six seconds, but one run still exceeded the wallet memory/proof-time targets; no universal cold-cache claim. |
| Favorable specialized fee layout | [Offline two-useful-recipient integration][integration] | Approximately 1.85% in that supplied-UTXO layout; one useful recipient plus change failed, and later matched lifecycle costs still failed. |
| Owner-signed reveal exit | [Native exit feasibility][reveal] | No fresh SNARK in that branch, but it reveals a note opening and retains failing fee/tail profiles. |
| Smaller circuit candidate | [Selected HMAC synthesis][hmac] | A 31.20% constraint reduction is a sizing result; the full proof/native/negative qualification was not completed in that packet. |
| Strict proof decoding and arity | [Arkworks differential][encoding] | Raw 0.5/0.6 APIs differ. The strict caller/native checks rejected the tested malformed cases; preserve those checks during reuse. |
| Recovery-data availability | [Historical P10 investigation][availability] | A verification key or replacement setup cannot substitute for exact missing public proving parameters of an existing instance. |

The [27 October checkpoint][checkpoint] records six payments, nine payouts,
zero final reserve and 12.5793% all-in fees against a 2% target. Removing payment
fees alone would still miss the lifecycle budget. Faster proving, a cheaper
tail exit and an estimated fee quote do not establish lower paid lifecycle cost.

## Evidence discipline

Keep hypotheses, admitted observer information and thresholds fixed before
fresh scoring. Use exact integer sompi and complete joint truth retention.
Report source review, constraint checks, local proof verification, native Full
validation, historical chain observations and actual independent recovery as
different evidence levels. Their boundaries are part of the result.

[working]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/WORKING-BALANCE-PRIVACY.md
[price]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/PRICE-LEAKAGE.md
[participant]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/PARTICIPANT-PRIVACY.md
[address]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/poc/shared-pool/ADDRESS-REUSE.md
[handoff]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/research/next-session/local-private-payment/SESSION-HANDOFF-2026-11-01.md
[reproduction]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/a0ef8fb82263fd6604d1a10a546ebd8ce2fc735f/poc/upstream-reproduction/README.md
[self-funded]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/poc/self-funded/README.md
[journal]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/ec6aa15d586bcc8a90f7232b433fd48d8c73d509/docs/RESEARCH-JOURNAL.md
[compression]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/85e39398fd97ff0299e07fad8899cd3f4cc454ac/poc/two-v6-binding/RESULTS.md
[cache]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/research/next-session/private-integration/uncompressed-cache/RESULTS.md
[integration]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/research/next-session/private-integration/RESULTS.md
[reveal]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/research/next-session/exit-fee/RESULTS.md
[hmac]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/research/next-session/selected-hmac-cost/RESULTS.md
[encoding]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/poc/arkworks-public-differential/PUBLIC-ENCODING-DIFFERENTIAL.md
[availability]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/e86e2a277ad53b28fc3bfc4aea40c24d858259fb/research/p10-recovery/REPORT.md
[checkpoint]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/docs/checkpoints/2026-10-27.md
