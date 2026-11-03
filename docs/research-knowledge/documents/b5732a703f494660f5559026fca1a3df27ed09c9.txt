# Four-wallet lifecycle, privacy construction and recovery availability

2026-10-24 UTC. Research/testnet scope. Worktree `continuation`, branch
`research/shielded-kas-feasibility`, starting commit
`b7b41ab066807d7859499b3491a663ab110fedf9`.

## Verified result and remaining gates

| Track | Result |
| --- | --- |
| Four separate owners | **Actual TN10 lifecycle complete:** accepted two-owner GN2, two genuine private payments, real combined R0 proof, four original-backup withdrawals with confirmed native payouts, four final recovery scans and zero reserve. |
| Privacy construction | ADR0061 actual APIs and curve controls reject the builder/shuffle/per-owner-blinding shortcuts. ValueShuffle supplies a concrete construction reference. ADR0062 passed four actual existing-engine exact-field sums, wrong-field/participant-loss controls and a real binding consumer; full tuple anonymity, authorization/retry composition and KAS relations remain open. |
| Independent recovery storage | Retrieval/retention failure controls and issuer-loss fixture complete. Actual separately administered storage and retention are **not established**; destination/access is still missing. |

The selected financial profile is
`41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a`,
distinct from earlier known-public benchmark profiles. Fresh identity creation
is independent of setup and takes less than a second in the measured run.
The development setup, selected software/host and public RPC remain trust
assumptions. Passing these experiments is no cryptographic or privacy proof.

## Actual accepted TN10 lifecycle

GN2 `a12e0be8c67b356eced979c350b4f3209ede349bfbeb8ae7381c4770482fd1d7`
reserved 40 KAS from two independently controlled funding keys. Two original
owners generated genuine sender proofs; both recipients independently checked
their pending receipt without a proving key. The actual guest executed
108,385,504 cycles. A fresh genuine GPU receipt took 412.527 seconds, followed
by 4.484-second compression, separate CPU verification and native128 conversion.
The [live proof packet](profile/live-outer-public-01/MANIFEST.json) preserves
the new claim and receipts. Native Full and five unchanged-proof rejection
controls passed before settlement
`d07c5d240f8d78c43d4e3ee9b470203bfb64d1bb15631aab3d1897d30c393d65`
was submitted once and confirmed through complete accepted-prefix replay.

With the outer proving jobs stopped, all four original backups made separate
private withdrawals. The first used opaque-restored public software and a
copied complete 1.308-GB proving key; seven original host paths were absent
inside its worker. Each exit used its own attempt journal and one RPC attempt,
independently of the shared campaign journal. All four native payouts are
confirmed. Terminal transaction
`297c3e71d4ccfe97ac192b4eae7003b5173ea8fee286b95fccc942d4093e3785`
leaves reserve zero, n=6 and m=13. Four fresh parallel recovery scans without
PK/private proving workers found six historical claims spent, zero unspent,
one controlled payout key per owner and zero unresolved records. Only sorted
count projections are public; raw owner-to-claim/payout maps remain private.

The [independent seven-case integer check](ROOT-LIVE-RESULT-CHECK-01.json)
verifies every physical input point, reserve and script link and derives:

| Actual fee | Integer sompi |
| --- | ---: |
| Ordinary acquisition | 1,925,000 |
| Two-owner GN2 | 1,949,400 |
| Shared settlement | 18,508,000 |
| Four independent exits | 68,050,500 |
| **Complete total** | **90,432,900** |

The 4,662,340,004-sompi mined source equals 460,415,004 acquisition change,
198,050,600 GN2 change, 3,913,441,500 native payouts and 90,432,900 fees,
exactly. Complete fees are **0.904329 KAS / 20 useful net KAS = 4.521645%**
at the unchanged reference rate 100. The **2% target fails**. Excluding
acquisition, pool-lifecycle fees are 88,507,900 sompi (4.425395%); that smaller
figure is not the headline total. The terminal 42,300-sompi fee-credit refund
does not increase useful requested payment value.

Both contributors have a common visible funding ancestor. Current grouped
action proofs also remain a privacy limitation. This establishes the tested
native lifecycle under the stated host/setup/RPC assumptions; it does not
qualify financial privacy, independent consensus or long-term availability.
The [next construction gate](../private-construction/full-tuple/NEXT-CONSTRUCTION.md)
records the open split-relation decision, including exact effects, global
balance, late signed-body settlement and fresh-attempt disclosure rules.

## Genuine local preparation

Two isolated original owners signed the strict GN2 after their own receipt
checks. The **input outpoints are nonexistent supplied contexts**. Their
ordinary signatures and both native engines pass, but this does not establish
backing or acceptance. Each sender then generated a genuine compact proof
after whole-PK/VK authentication and READY, without sharing its backup.
Both recipients independently decrypted and checked their pending receipt
without a PK or proving worker; pending receipts were not treated as settled.

The new guest executed 108,433,490 cycles against the exact 8,301-byte public
projection and 424-byte journal. Actual GPU proving took 414.8 seconds, with
6,096 MiB peak sampled owned GPU memory. Same-claim compression took 4.8
seconds; separate CPU verification and canonical native128 conversion passed.
All proof units were stopped and their owned processes disappeared.
The [neutral outer packet](profile/outer-public-01/MANIFEST.json) retains
receipts, global body/proof joins and measured resources. Internal actor
correspondence is preserved privately; the
[publication review](profile/outer-public-review-01.json) checks that the
selected public evidence adds no owner-to-hidden-input/payout map.

The genuine actual W passed native Full and its engine. Keeping the genuine
proof unchanged, changed ciphertext and child-proof bytes rejected with
`ZkIntegrity`; changed input reserve, current point and an added unauthorized
payout rejected with `VerifyError`. Official body normalization, SDK roundtrip
and independent Python/native projection/journal encoding agreed. Proof-slot
replacement preserved the transaction ID, mass and all financial effects.

Four further isolated original-backup owners generated fresh private
withdrawal proofs, each in about 13 seconds, using complete public history.
Both senders recovered private change; both recipients recovered their payment.
Every withdrawal passed fresh native Full. Final state is n=6, m=13, reserve=0.
Four fresh recognition scans, without PK/proving workers, found all historical
claims spent, zero remaining claims and one controlled payout key per owner.
Raw owner-to-note/payout correspondence stays outside publication.

## Complete local supplied-context fees

The [independent integer-only check](ROOT-LOCAL-RESULT-CHECK-01.json) derives
these amounts from the signed GN2 and all five physical W cases:

| Accounting item | Integer sompi |
| --- | ---: |
| Supplied ordinary inputs | 6,000,000,000 |
| Ordinary returned change | 1,999,533,900 |
| Native withdrawal payouts | 3,913,441,500 |
| GN2 fee | 466,100 |
| Combined settlement fee | 18,508,000 |
| Four private withdrawal fees | 68,050,500 |
| Total fees | 87,024,600 |
| Final reserve | 0 |
| Useful requested payment value | 2,000,000,000 |

Sources equal returned change plus withdrawals plus fees, exactly. The terminal
42,300-sompi credit refund and sender principal/change are not extra useful
payments. Fees are **0.870246 KAS / 20 useful KAS = 4.35123%**. The unchanged
2% complete-fee target **fails**. Earlier two-owner or larger-batch results
remain separate workloads; they do not discount these four independent exits.

## Live and availability dependencies

The separate [fresh funding identity](bootstrap/funding-identity-01/PUBLIC.json)
has two ordinary TN10 wallets, A and C. Normal faucet frontdoors returned browser
challenges. We instead [mined free TN10 KAS](funding/mining-feasibility-01/MINING-RESULTS.md):
16 unique block submissions succeeded and 4,662,340,004 sompi were observed on
fresh A. The 14-worker run took 154.449 seconds; all mining workers stopped.
All 16 observed rewards subsequently reached the actual node's 1,000-DAA
maturity requirement. This trusts the selected validating RPC/template; it
does not establish independent consensus or a private pool payout.

The reviewed ordinary consolidation is now confirmed: 21 KAS each to A/C,
a 1,925,000-sompi acquisition fee and 460,415,004-sompi source-A refund.
Its transaction ID is
`3d12363871c7af51ebb1b81cc2f2ba4f90f191e5aa997bc191e0b8c2fa59e9e6`;
the observed output birth DAA is 604,894,280. One isolated original-A signer
passed Native Full/all 16 and SDK checks. Fresh maturity/source checks preceded
the durable intent and single submission; read-only reconciliation confirmed
the three outputs. This is distinct from the local 30-KAS-per-input fixture.
The [source review](live-runner/ordinary-funding-01/ROOT-REVIEW-01.json)
records the execution boundaries.
Actual GN2/W acceptance, fresh currentness, independent exits and confirmed
payouts subsequently completed as recorded above. The initial confirmed-prefix
fetch returned MISSING_FOUNDING before sufficient depth; a later read-only
fetch succeeded without source changes or resubmission.

Public storage fixtures, two same-administrator release locations and personal
Drive are not independent retention. A separately controlled destination,
configured project write access and an actual issuer-loss retrieval of the
selected full recovery objects are still required. Missing/pruned/conflicting
evidence must remain INCOMPLETE, never be treated as an empty wallet.

The [complete prepared recovery handoff](recovery-history-01/MANIFEST.json)
now has 23 public objects totaling 1,441,878,490 bytes: the full selected PK,
software/profile metadata, actual terminal descriptor/fetch, all 13 referenced
Full pages and the projected terminal reconciliation receipt. The original
seven asset identities remain unchanged. This adds the actual accepted history
to the prepared upload set; no upload, independent administration or retention
is established by its local byte-copy result.

The privacy [API/algebra result](../private-construction/RESULTS.md),
[full-tuple design](../private-construction/full-tuple/DESIGN.md) and
[review](../private-construction/full-tuple/REVIEW.md) retain the construction
negatives and disclosure-order gaps. Existing anonymity and fee thresholds
are unchanged. No experimental mainnet deployment or real funds were used.
