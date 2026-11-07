# Atomic bundle on current Testnet-10: accepted, with narrow privacy benefit

**Decision:** retain the public bundle as an optional current-L1 research
component for the shared native-KAS design. It removed the tested withdrawal
service's per-wallet reply-timing link and completed the real private-payment,
native-payout and restored-key path. It is **not** complete payout-owner
privacy, an independently operated wallet test, or a production choice. No
consensus rule changed.

## What actually happened

The [preselected trial](TESTNET-SELECTION.md) used the existing wallet relation,
proving programs, bank kernel and native Testnet-10 scripts. A fresh bank held
2.0 test KAS: 1.2 KAS private principal and 0.8 KAS fee allowance. Four wallets
made A→B 0.6, B→C 0.3 and A→D 0.3 KAS private payments. A/B/C each made a
genuine proof-backed, blind 0.3 KAS withdrawal request. The service returned
only unusable `queued` replies on its three private connections. Its single
**9,204-byte** bundle contained all three valid blinded signatures.

That exact bundle was accepted in ordinary transaction
`278eda4ff5c0ba6351f75c23b5b30aa8febec5e2e7761246b923d46bd6ca52ce`
and observed with ten confirmations. Three wallet reader processes separately
read the accepted bytes through two public TN10 RPC operators before any
redemption. All three wallets checked the complete board, unblinded their own
credentials and approved one payout set. A later D→A 0.06 KAS private payment
confirmed with those approvals unchanged. The native three-payout withdrawal
confirmed in transaction
`289f66bad68307245f983aba624d2a0c6589f468cd83b91b5baebd9da16981a8`.
The final two notes were paid out, bank reserve and private liability reached
zero, and all **five** payouts were spent on TN10 with restored owner keys.
Both public RPC operators agreed on the final relevant UTXOs. The
[finite public evidence](testnet-run/MANIFEST.json) has an independent
[public replay checker](../../poc/atomic-bundle-withdrawal/check-testnet.py); wallet
backups, issuer key, blinding secrets, source key and Tor state stay private.

The service-only observer was sealed before owner truth was read. Its six
actual issue/redeem messages gave **zero exact claim-to-payout ownership
links** and **six compatible mappings**; its one fixed order guess matched
**1/3** in this sample. The reader accepted the real body and refused canned
withholding, reorg, altered-payload, altered-output and issuer-supplied-route
controls. A real reorg or hostile RPC operator was **not** induced. One known
owner leaves two possible assignments; two known owners leave one.

## Measured cost and decision

| Cost | Prior complete TN10 rehearsal | This bundle rehearsal |
| --- | ---: | ---: |
| Native fees, including funding and five restored-key spends | 0.678204 KAS | **0.697144 KAS** |
| Extra accepted bundle transaction | — | **0.018940 KAS** |
| Other transaction fees | Same transaction shapes | Exactly unchanged |

The amount-scaled trial is **not** a cost percentage for normal users: its
principal was only 1.2 KAS because the available test wallet was small. For
the retained matched **47 useful KAS** comparison, using this accepted fee as
a same-shape proxy alongside the previous 0.992104 KAS native-fee quote raises
the native share from **2.1109% to about 2.15%**. At the same frozen
illustrative work price, the prior measured proof-and-fee subtotal rises from
**8.2123% to about 8.25%, before unpriced additions**. The actual full-value
bundle may differ slightly in size and fee. Three separate local board checks
took 0.0294 wall seconds total;
Tor, public RPC, idle capacity, retention and operator margin are not fully
priced. These are neither current dollar offers nor a complete service bill.

The owner's willingness to consider roughly 3% does not make this 47-KAS
workload cheap enough as a default. Larger-value, warm, well-utilized service
operation might amortize fixed proof work, but that is a separate bounded
cost study. Keep this improvement optional and continue collaborating on
Olaf's shared direction; do not start a competing runtime or seek consensus
changes because this single observer improved.

## Limits and failures retained

All completed roles ran on **one physical host**. The wallets used two
independently operated public RPC endpoints, with one route per wallet; they
did not validate chain headers themselves or demonstrate independent human
users. A malicious operator, selective network delivery, pruning and future
data availability need stronger checks. The ordinary test-coin source was
refilled by co-spending already paid outputs from an earlier rehearsal, so
this funding history cannot establish global deposit privacy. The service can
withhold the whole bundle and stop this optional path. Public payout amounts, fee funding,
known-owner/Sybil claims and later disclosures still threaten ownership
privacy. Passing native Full and wallet checks is implementation evidence,
not a cryptographic audit or mainnet-readiness claim.

Two funded trial identities stopped before bundle publication: one hit a Tor
descriptor failure before sending a claim; the next exposed a sequential
claim/service wait deadlock. The first bank was later drained only through
four owner-authorized Testnet exits, then its already paid outputs were swept
as ordinary test coins to fund a fresh identity. A third **unfunded** identity
stopped before broadcast on an obsolete fixed fee-estimate cap. None was
rebroadcast. The successful trial added safe pre-send Tor retries, concurrent
claims, an onion reachability check before funding and a wait for the signed
fee rate, without weakening proof or reserve checks. The second stopped bank
remains recoverable with its retained private owner backups; it is not counted
as a successful privacy run.
