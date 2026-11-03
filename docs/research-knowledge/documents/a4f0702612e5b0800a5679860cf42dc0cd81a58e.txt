# Independent static review of sticky owner basket 01

Verdict: **no blocker within this unselected ideal finite control**. The expected failures and strong history/durability assumptions remain visible. This is not a native or cryptographic solution, and it changes no baseline result.

Guarded source pins:

- `run_sticky.py`: `5e6748d6fc774b8072a977c6ff45c80fd9bdcc9d70d4a556397920f5335a2405`.
- `INPUTS-01.json`: `17962b28f7c3035fb20e4799b869604b40a460099a10d9ba722b7390307bc223`.
- `MODEL-FREEZE-01.md`: `799d74faf6633b2cfef57c5eb8f1ebb997cbdd1112a631a5d4fdc41e525a880f`.
- `SOURCE-MANIFEST-01.json`: `f5f7862d5cd23714e89bf17d5734ada0fb67c0926fc29d88ddfe597508a1eefb`.

The reviewer and independent child performed text-only review: no import, compilation, AST parsing, model execution, tests, private-content read or network operation. Counts below are manual. Root's separately authorized run is not a reviewer rerun.

## Manual count check

The unchanged enumerator treats each NF/complete-output appearance signature as public. In ABC→AB, C's NF and two outputs have the first-only signature; A/B share the repeated signature. Public egress therefore permits `3! × C(4,2) = 36` worlds. Knowing C and the cohorts leaves `2! × C(4,2) = 12` coordinator worlds. A retains two NF candidates and six pair candidates. The final-current-confirmed AB snapshot has two owners and four outputs, also `2! × C(4,2) = 12` worlds, for a different observation set.

ABC→ABC gives the baseline `540 / 12 / 540`. ABC→AB→ABC still gives `36 / 12` to history-retaining observers because C retains a distinct appearance signature; its final currently accepted ABC snapshot gives 540.

ABC→AC after honest B exits gives `36 / 1 / 12`: the coordinator knows C, so A is the only honest unknown owner and its NF and pair are unique. The code does not substitute an honesty test for owner count.

Each of the four ABC→ADE history/durability/bypass failures gives the original `4,320 / 12` history-retaining worlds, with A uniquely identified despite D/E's remaining ambiguity. A final ADE snapshot alone gives 540. The sum is `60 + 1,092 + 588 + 49 + 4 × 4,872 = 21,277`, across eight cases and three observers: 24 views.

These are consistency counts, not probabilities. Different observation sets and owner universes must not be compared as a scalar privacy ranking. Complete-output linkage is retained alongside NF linkage, and a larger global count does not hide a unique A.

## Observer and authorization boundaries

The extension explicitly distinguishes all-candidate public egress, the coordinator with named cohorts/C's material, and a final-current-confirmed-only snapshot. The last receives only the final currently accepted private batch and current exits in these traces. It is not an archive or mempool observer and does not inherit orphaned disclosures. Independent case histories are not combined into one artificial trace.

`IdealStickyBasket` retains every eligible original intent, forbids omission/replacement/addition, prunes only an accepted-consumed original NF, and retains its original archive and disclosure history across rollback. The returned egress record follows the modeled durable append. It accepts identical requests idempotently but rejects altered recipient/CF/fee/nonce or a new intent for the same owner. No honesty flag affects these decisions.

The financial cases use the unchanged baseline consent/accounting oracle, including the explicit failure cases. Financial validity does not enforce the sticky policy or establish privacy. Private output pruning, accepted-state authenticity, share opacity, owner consent and publication ordering remain assumed functionalities.

## Essential limits and liveness

The global restriction is strong: `open_other_session` rejects **every** new basket while any original intent remains eligible, even one with disjoint NFs. It is not merely pending-NF overlap detection. Only after the original basket is fully consumed does it allow another session, explicitly without claiming general cross-session privacy.

Global disclosure history must survive crashes, pruning and reorg, be committed before publication, and be consulted by every admission/restore route. A centralized Python object standing for that service does not demonstrate malicious-secure storage, atomic publication or enforcement across independent services/provers. Original backup authority does not reconstruct forgotten unconfirmed disclosure history. Bypassing that oracle deliberately restores the baseline failure.

Pruning exposes the departed member's original NF/output pair by set difference. The positive AB statement protects the two remaining honest owners when the departed member is C; it is not privacy for every former member. Honest B's departure while C remains is correctly a privacy failure. A single eligible owner would also expose its pair if published. Refusing publication instead loses private-batch progress; no minimum-count remedy or new policy is selected.

Frozen intents can also block a requested fee or destination change. The after-upload controls need no new owner attendance; availability of the durable threshold service remains assumed. Independent exits remain a separate assumed route; the model does not create a native lock or privileged exit delay. No actual recovery, native, cryptographic, durable-storage, fairness, network or fee validation follows. The previous 21-KAS 2% failure and original baseline pins/results remain unchanged.
