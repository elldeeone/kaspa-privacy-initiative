# Terminal capture v2 source protocol

Status: **UNQUALIFIED_SOURCE_ONLY / CONFIGURED0_NETWORK_DISABLED**.

This protocol defines the parent-owned order for one terminal-history stream. It
does not perform a network request, create an actual capture receipt, authorize
a trial, or supply privacy-measurement facts.

It also does **not** satisfy the terminal Exit/payout privacy gate. That gate is
a separate nine-exit lifecycle experiment: each independent exit must retain
its observed candidate, R0, NativeFull, one-shot submit, exact accepted payout
UTXO, durable settlement and reorg/failure history, followed by ordered
financial-service loss and recovery/cold-scan contacts. The isolated private
scorer must then compare the frozen transparent and hidden arms. The 15 source
controls for this one payment-terminal stream are not lifecycle execution or a
privacy result.

## Success order

The parent may advance the move-only capture stages only after the corresponding
real operation returns:

1. candidate constructed, bound to the exact CASE and selected projection;
2. selected R0 receipt verified against that projection;
3. NativeFull verified against the same CASE and projection;
4. FINAL durably bound;
5. exact hidden 3-NF/6-output control group and any cross-round observation
   retained;
6. one Testnet submission attempted with the deterministic candidate txid;
7. that same submission acknowledged;
8. the exact CASE/txid acquired in an accepted head;
9. settlement durably resolved;
10. trial closed, then terminal FD END/close.

There is no untyped close API. NativeFull, FINAL, submit acknowledgement, or an
accepted CASE alone cannot emit `trial-closed`.

## Non-success order

- An unknown write result records the candidate/txid, writes END, and consumes
  the only submission attempt. It exposes no retransmission or trial-close
  transition.
- Rejected, orphaned, and reorged observations are written before END and the
  API then refuses. This preserves failure evidence without resolving the
  durable attempt.
- Wrong CASE, projection, txid, stage order, duplicate submission, or premature
  close refuses before the claimed event is emitted.

END/EOF on unknown or failure is only evidence-preserving stream completion. A
future outer authority must treat it as failed-trial evidence, never successful
capture or measurement authority. Successful authority additionally requires
the outer parent to observe the fixed FD END+EOF, child wait status, exact
source/build/runtime identity, and `after_trial_closed(ResolvedSettlementV2&&)`.

## Privacy boundary

CONFIGURED0 metadata and group/link rows carry
`privacy_measurement_usable:false`. The v1 capture model explicitly refuses this
v2 schema. The control values are caller-supplied fixtures and cannot enter the
actual observer/scorer. A future selected bridge must derive the 3-NF/6-output
group from the exact retained public projection and cross-round links from real
terminal observation; JSON or capture sequencing tokens cannot mint that
authority.

Controls are in `test_privacy_terminal_capture_v2.py`. They execute no network
operation and create no receipt.
