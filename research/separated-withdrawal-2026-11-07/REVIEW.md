# Adversarial second pass

This review concerns the deployment/observer experiment, not a cryptographic audit.

- **Minting/double spending:** no economic or proof relation is replaced. Genuine
  credit/transfer/eligibility/approval proofs pass existing verifiers. The shared
  kernel rechecks current nullifiers, roots, liabilities and exact effects. The
  adversarial issuer's credential is never authority to release native funds.
- **Unauthorized payout:** owners still inspect the complete payout set. The
  kernel must accept exact three-owner approvals and reject an altered intent.
  A privacy leak can coexist with fully authorized value-conserving payouts.
- **Wrong/stale state:** the supplied deposit and native predecessor are offline
  fixtures. This experiment does not establish chain ancestry, new native Full
  acceptance or reorg recovery. It must not be reported as another TN10 trial.
- **Private information:** wallet, issuer, blinding and Tor secrets remain under
  ignored local paths. The service container has no wallet mount/Docker socket.
  A separate observer has only wire/public inputs. Truth enters scoring after
  sealing its predictions. Public replay does not independently prove the retained
  private owner-to-key scoring truth; state that limit.
- **Configuration trust:** the honest arm assumes one actual common configuration.
  The active arm deliberately tests a service that violates this coordination
  assumption. It does not attack RSA blindness for a common message context.
  Keeping one issuer key is insufficient if the later message carries a unique
  per-wallet round tag. Do not assume an authenticated common bulletin exists.
- **Timing/amounts:** preserve full service timestamps, peer ports, wire fields and
  the fixed rank guess. One small sample cannot establish a timing classifier's
  success rate, a probability distribution over allocations, confidential amounts
  or global-traffic resistance. Two colluding participants leave the third known.
- **Dependency failure:** each container owns its Tor process. No direct fallback
  exists in the protected arms. The labelled direct route is a separate control.
  A service/prover outage can delay work; this test introduces no recovery authority.
- **Host trust:** unprivileged namespaces and omitted mounts separate ordinary
  roles, not the host administrator or kernel. The same physical host, common
  Internet uplink and experimental parameter setup remain limitations.

If tagging succeeds, a future privacy repair must establish agreement on the
same round/configuration **before anonymous payout keys are sent**. Comparing
configuration only when signing the final withdrawal is too late to retract a
key already disclosed with its tag. Retain this distinction when designing the
smallest client-side/shared-transcript check. No such fix is assumed by this test.
