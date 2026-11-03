# Local payment: prospective privacy scope and acceptance

**2026-10-25 UTC. Status: proposed before implementation; root ADR selection is required.**

The selected research question is whether one wallet can pay another from one
owned native-KAS-backed note, recover received notes/change from its original
seed, spend repeatedly, and exit independently, without recruiting live co-owners.
[SPEC.md](SPEC.md) defines the candidate. This document is a prospective contract,
not evidence of execution, security, privacy qualification or testnet readiness.

## Observer and assumptions

| Observer | Available information | Claim/limit |
| --- | --- | --- |
| Public ledger observer | Complete accepted/reorg public history; funding and exit amounts/destinations; one NF, two output tuples, CM/NF roots/counts, reserve/fee movement, action IDs, sizes and timing; public software/parameters | Candidate cryptographic confidentiality hides consumed CM, note values and recipient descriptors under existing proof/encryption assumptions. NF-to-two-output grouping is explicitly public. Public ancestry/amount/timing inference remains measurable leakage. |
| Submission endpoint/coordinator | The ledger view plus request origin/authentication, transport metadata and submission timing | A request identifies the owner of its single NF when origin is known. Local construction does not satisfy sender-origin anonymity against this observer. |
| Counterparty or colluding owner | Ledger view plus its own keys, invoices, note openings, receipts and interactions, voluntarily shared with the observer | Its own payment/value/outputs and invoice association may be known. No claim hides a payment from its counterparty or prevents external-data inference. |
| History/proof service | Public projections, proofs and full authenticated history | No owner secrets, openings, scan indices, view keys or owner-labelled authorization packets are required. Complete-history fetching can still expose network/timing information. |
| Host administrator/global traffic observer | Process memory, local files or correlated traffic | Outside the bounded confidentiality claim. Separate processes/namespaces do not establish independent administration. |

Assume reviewed existing primitives hold; selected proof setup/keys/parameters and
software are correct; wallets retain seed custody; the invoice authenticates the
intended recipient; and complete public history/software remain available. These
are assumptions, not results of tests. A missing prover/service can delay progress
but cannot create a valid theft, inflation or unauthorized-exit transition.

The [source/ingress record](../SOURCES.md) selects established Tor SOCKS5h with
proxy-side DNS, fresh isolation credentials, verified TLS and no identifying
remote authentication, redirects or direct fallback. It records a separate real
read-only Tor probe; application payment integration remains a separate gate.
This is a bounded defense against direct endpoint-origin association, not a
global-observer or application-fingerprint anonymity result. Any ingress claim
must name endpoint, timing/padding, admission/collusion and global-observer
assumptions and pass a separate prospective evaluation. Fresh
action IDs and omitted roster labels do not hide endpoints by themselves. Stable delivery PKs
can link invoices to an observer who sees them. Confidential invoice exchange is
an explicit requirement outside the public ledger transcript.

## Claims that may be accepted

1. **Independent local construction:** one owner produces and authorizes a complete
   real 1-to-2 payment using its own note/seed and an authenticated public invoice.
   Another owner's secret, MPC slot, approval or online participation is never
   required. Receiving can be offline.
2. **Bounded ledger confidentiality:** no direct plaintext owner, note opening,
   value, recipient descriptor, invoice index/stable delivery key or spent-CM
   selector is added to a public payment transcript. The entire NF/two-output
   transaction grouping, fees, reserve movement and timing remain visible.
   Proof/encryption validity and negative disclosure controls support this
   implementation boundary; they do not prove general anonymity.
3. **Recoverable spendability:** original-seed restoration from authenticated
   public history discovers both received payment and change and derives ordinary
   repeated-spend/independent-exit authority without a private coordinator record.

Each claim receives a separate verdict. Neither correctness nor a genuine proof
qualifies complete financial privacy. A sparse-state, amount/timing or informed
counterparty observer may identify ownership despite cryptographic confidentiality;
record that finding without changing the observer or thresholds after seeing it.

## Old results remain separate

- Keep the old frozen 62-item baseline and four continuation results unchanged.
  The changed-cohort diagnostic remains 3/3 owner-verified unique predictions,
  with 0/2 in its same-cohort control, under its pre-settlement synthetic-wire
  observer. It remains a negative result for that old channel; not a financial,
  native, testnet or global-anonymity result.
- The old six-output NF-to-payment score and its 1/6 criterion do not pass under
  a transaction with two public output candidates. Do not translate them into a
  new success. This candidate studies a different boundary: consumed-CM/NF
  confidentiality and removal of compulsory multi-owner coordination.
- Keep the matched useful-payment volume **21 KAS = 2_100_000_000 sompi**,
  six useful payments, matched deposits/repeated spends and nine exits. Change,
  reserve turnover and self-transfers never increase useful volume. The old
  **2% all-in target remains FAIL** until the complete matched candidate workload
  has actual measured all-in cost. A quote, smaller proof or singleton timing
  estimate cannot replace paid fees or claim savings.

## Acceptance checklist and evidence order

1. **Source/design:** root accepts ADR-0066 and pins SPEC, exact D/tags/profile,
   public source closure and genuine fresh key/image/tail identities. Keep old
   assets untouched. Archive the same-day mature-protocol source review and each
   reused/adapted/rejected component. No direct combined-relation optimization
   or new authorization semantics enter this baseline.
2. **Independent public serialization/state controls:** Python/reference/native
   reconstructions agree byte-for-byte on core3756/body3884/projection4077,
   complete effects, journal, counts/roots and integer conservation. Reject
   truncation/trailing records, bool/float/overflow, floor/range/capacity failures,
   zero/duplicate NFs/CMs and `CM_EMPTY` output CMs, invalid scalar/point/subgroup encodings, bad proofs,
   altered CF/outputs/fees/destination/outpoint, wrong domain/profile/image/tail,
   wrong/stale paths/roots and cross-state/pool/lane replay. Controlled competing
   transitions and supplied reorg history accept at most one current successor;
   reconcile remaining unspent liability safely. This is a correctness control,
   not a new active deanonymization experiment.
3. **Genuine execution:** fresh selected Spend, two Output and outer proofs pass
   their independent verifiers and actual native Full/all-input context checks.
   Direct fresh-domain Exit proofs pass native continuing and terminal branches.
   Placeholders, host booleans, component-only tests and supplied contexts do not
   count as actual accepted chain state or paid payouts.
4. **Owner lifecycle:** separate owner processes create new trial seeds locally;
   payer sends an authenticated-invoice payment with no co-owner interaction;
   recipient restores its original seed from only public accepted history and
   spends the received note; payer restores and spends change; repeated received
   and change spending succeed. Restored owners independently exit all remaining
   claims, reconcile every liability and reach zero reserve. Remove original
   coordinator/outer services for recovery and direct exits. Do not call this
   off-host or independently administered recovery without actual evidence.
5. **Privacy/cost:** inspect only allowed public artifacts for direct disclosure;
   retained owner-side checks report per-observer attribution without exporting
   hidden truth. Record public grouping and repeat-NF leakage. Capture cycles,
   wall time, RAM/VRAM, component/outer proof bytes, actual native mass and paid
   fees for the exact matched 21-KAS workload, including setup/deposit/payment/
   recovery/exit transactions and failed-attempt paid costs. Publish fee and
   privacy verdicts separately. No old metric or denominator is rewritten.
   Verify proxy-side hostname framing, per-unrelated-session isolation, correct
   TLS/redirect rejection and failure with no direct connection. The integrated
   public transaction path must use the selected transport; a fake proxy or an
   unrelated Tor probe is not evidence that a payment used it.
6. **Testnet rehearsal:** after local acceptance, use only fresh testnet identity,
   test KAS, selected sources/parameters and an explicit complete run. Require
   real terminal broadcast, confirmed payout(s), independent accepted-history
   replay and zero terminal reserve before claiming readiness. Any failed funded
   attempt is retained; retry through a fresh identity without weakening checks.

Stop the affected acceptance step on safety/control disagreement, dependence on
other owners/private journals for spendability, unverifiable state, unauthorized
exit authority or source/parameter mismatch. Resource exhaustion is incomplete
execution, not a privacy failure/pass by itself. Fix operational resource limits
generously while preserving financial/evidence-integrity checks. Review findings
from inflation, duplicate spends, reserve release, privacy disclosure, stale
state/reorg, dependency loss and hidden trust assumptions before trial claims.

## Current verdict

**DESIGN PROPOSED. IMPLEMENTATION / GENUINE PROOFS / SEED RECOVERY / NATIVE
ACCEPTANCE / TESTNET PAYOUTS: NOT EXECUTED BY THIS CONTRACT REVIEW.**
**NETWORK ORIGIN / GENERAL FINANCIAL PRIVACY: UNQUALIFIED.**
**OLD MATCHED ALL-IN 2% FEE TARGET: FAIL, unchanged.**
