# Local native KAS payment: candidate contract

**2026-10-25 UTC. Status: proposed for root design review; final authority is the accepted ADR-0066.**

This is new research documentation. It does not select or modify an old pool,
financial source, key, backup, frozen trial or result. No original wallet secrets,
private plans, event records, view seals, truth or logs were inspected. All
`SECURITY-INVARIANTS.md` invariants remain in force. Native test KAS is the only
asset; no real funds, mainnet, token or privileged withdrawal path.

## Source gate and decision

Apply [RFC-0029](../../../../docs/rfc/0029-local-native-kas-private-transfer.md),
its [same-day pinned source gate](../../sender-private-lifecycle/SOURCES.md), and
the [retry options review](../../sender-private-lifecycle/review/RETRY-PRIVACY-OPTIONS.md).
The [new source/ingress record](../SOURCES.md) adds the independent current-head
refresh and established Tor transport selection.
Those sources distinguish established note/proof/encryption mechanisms from
cohort membership, submission origin and chain settlement. This review inspected
their public source references locally; it does not claim a new live upstream
refresh beyond the recorded 2026-10-25 pins.

Select a local, one-owned-input/two-real-output payment. The payer constructs and
checks the entire action, then generates its Spend proof. The recipient supplies
an authenticated public invoice and need not be online. No peer owner, MPC,
cohort roster or coordinator authorization is required. An outer proof is still
required for the payment branch; direct full-note exits remain independent of it.

| Existing work | Reuse/adaptation | Limit retained |
| --- | --- | --- |
| Kaspa/Toccata/KIP-16/20 | Existing native proof verification, exact current UTXO, immutable successor policy and actual effects checks | Proof validity alone is neither settlement nor current backing; txid alone omits relevant context |
| Orchard | Local construction from owned notes, paths and authenticated recipient addresses; hidden ownership/public NF distinction | No curve, circuit, setup, historical-anchor or security guarantee port |
| Aztec | Owner-local complete history scanning and encrypted discovery | Remote leaf queries/view keys expose access information; no runtime import |
| RAILGUN | Separate verified effects, spentness and state roots | No relayer-privacy, deployed-key or administrator-path assumption |
| Monero | Treat recipient privacy, confidential amounts and spentness as separate obligations | No ring-signature or asset-model change |
| MWEB | Noninteractive receiving; separate scan and spend authority | No stealth-receiving claim about ingress; no view-key filtering service |
| Existing Receipt216/Note168/CF264 adapter | Seed-derived indexed keys and encrypted index support receiving and change recovery | Encryption does not authenticate an invoice or accepted backing |

## Identity and fresh parameters

The proposed financial domain is SHA256 of the exact UTF-8 bytes below, with no
newline, NUL or prefix:

```text
KaspaPrivacyInitiative/local-native-kas-payment/1x2/v1/2026-10-25
```

```text
D = b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c
```

Use these exact eight-byte ASCII tags:

| Use | Tag |
| --- | --- |
| State112 | `KPXAST01` |
| Payment body | `KPXAPB01` |
| Native projection prefix | `KPXAFX01` |
| Effects digest prefix, payment and exit | `KPXAEF01` |
| Outer journal104 | `KPXAJR01` |
| Spend200 statement | `KPXASP01` |
| Output168 statement | `KPXAOU01` |
| Exit body1632 | `KPXAXB01` |
| Exit152 statement | `KPXAEX01` |
| Native immutable metadata marker | `KPXAWN01` |

Retain established `KPX1` owner/key/note/NF/tree algorithms and tags, supported
curve/value generators, fixed integer semantics and recipient adapter. D remains
part of the existing note/key/NF computations. D and statement tags are compiled
constants: regenerate **Spend, Output and Exit** circuit/key/manifests. Select a
new strict component profile, outer guest/image/proof selection and native tail.
Changing only JSON is invalid. Reject old domains/tags/3-to-6 shapes in the new
profile and new identities in the old one. No migration of old notes or backups.

Suggested profile identities for root selection are
`kpxa-local-private-component-profile/v1` and
`TN10_RESEARCH_ONLY_ADR0066`; selected file hashes, VKs and image are outputs of
the fresh build, never placeholders accepted as financial authority.

## Exact codec

All intervals below are zero-based, end-exclusive. Integers use existing unsigned
little-endian widths. Exactly one NF32/CV64, two Output520 tuples, one indexed-NF
witness1160, two append paths512, and one final Spend128 occur. No dummy records,
trailing bytes or ambiguous integer/field encodings are allowed.

| Payment body bytes | Content |
| --- | --- |
| 0:8 | `KPXAPB01` |
| 8:16 | Four u16 values `(1, 1, 2, 0)` |
| 16:48 | D |
| 48:80 | Fresh nonzero action ID32; no MPC-session semantics |
| 80:112 | Reserved zero32; no participant roster |
| 112:148 | Exact current reserve outpoint36 |
| 148:260 | Old State112 |
| 260:268 | Old reserve u64 sompi |
| 268:380 | New State112 |
| 380:388 | New reserve u64 sompi |
| 388:396 | Explicit fee u64 sompi |
| 396:404 | Native payout u64, exactly zero |
| 404:436 | Canonical subgroup scalar Delta32 |
| 436:532 | NF32 then CV64 |
| 532:1572 | Two complete Output520 tuples |
| 1572:2732 | One indexed-NF insertion witness1160 |
| 2732:3756 | Two ordered CM append paths512 |
| 3756:3884 | One genuine Spend128 proof |

Each Output520 is `CM32 || CV64 || CF264 || SHA256(CF)32 || OutputProof128`.
State112 is `KPXAST01 || D32 || CMroot32 || CMcount_u32 || NFroot32 || NFcount_u32`.
The native prefix retains its existing **193-byte** exact P0 layout, using
`KPXAFX01` and payload length3884. Thus `core=3756`, `body=3884`,
`projection=4077`. Two real outputs have no public PAYMENT/CHANGE role labels.
Public append order determines their positions; a wallet must find each exact
expected tuple once and must not infer ownership from position.

Effects are `SHA256(KPXAEF01 || prefix193 || body[0:3756])`.
Exclude only the final Spend128 bytes. Output proofs and both full ciphertext
tuples are included. The Spend200 contains D, accepted old CM root, own NF/CV
and this digest. The Output168 binds D, CM, CV and exact CF hash. The outer guest
independently reconstructs all bytes and verifies one Spend plus two Outputs.
Journal104 is `KPXAJR01 || D32 || selected_component_profile_sha25632 ||
SHA256(full_projection4077)32`; the native branch binds the selected new image,
journal and actual transaction context, including witness/budget checks.

## Financial and state rules

1. Amounts are integer sompi only. Reject bool/float, overflow, negative and
   out-of-range values before conversion. Keep `NOTE_FLOOR=60_000_000`,
   `PAYOUT_FLOOR=10_000_000`, `MAX=2_870_000_000_000_000_000` sompi.
2. Require `input = payment + change + fee`, each output within
   `[NOTE_FLOOR, MAX]`, fee within `[1, MAX]`, and
   `CVin - CV0 - CV1 - fee*V = Delta*R` with canonical subgroup encodings.
   The identical fee leaves the reserve: `new_reserve + fee = old_reserve`.
   Reserve amounts remain within `[NOTE_FLOOR, MAX]`. No native payment occurs.
3. Require one nonzero previously absent NF, valid indexed predecessor
   replacement and empty append; `new_NFcount = old_NFcount + 1`. Require two
   distinct CMs, each unequal to ZERO32 and to
   `CM_EMPTY = SHA256(b'KPX1CME\0')`, and complete distinct tuples, valid ordered empty-slot
   append paths; `new_CMcount = old_CMcount + 2`. Authenticate genesis and the
   occupied-prefix invariant before accepting a prior state. Keep CM depth16 and
   NF depth17; pre-transition counts are `1..65534` and `1..131071` respectively.
4. Consume exactly the selected current reserve UTXO and produce exactly one
   continuing output with unchanged selected immutable tail and new State112.
   No signatures/host flags or component-only success substitute for native
   financial checks. Complete effects, domain, image, profile and exact old/new
   state bind every authorization. Shared-head conflicts safely reject.

The two-output minimum requires `input >= 2*NOTE_FLOOR + fee`. No zero change or
smaller floor is introduced. Full-note redemption uses the exit branch.

## Consent, recovery, retry and exit

Before Spend generation the payer independently replays accepted public history,
confirms its note/position/unspent NF, current outpoint/reserve, selected successor
tail and fee; constructs both complete output tuples; checks the exact recipient
invoice and own change by local decryption; verifies proofs/paths/conservation;
then authorizes the exact reconstructed effects. Never sign an opaque digest.

Invoice208 must come from the intended recipient over an independently
authenticated channel. For a public-fixture/local harness, pre-agreed full
invoice bytes/digest are an explicit fixture authenticity assumption. Substituted
invoices fail that check. This does not implement Internet invoice identity or
contact discovery. No new signature primitive is selected.

For public history/transaction transport, select the established Tor adapter in
[SOURCES](../SOURCES.md): explicit loopback SOCKS5h, proxy-side DNS, fresh SOCKS
isolation credentials, verified TLS HTTPS/WSS only, no destination credentials,
redirects, cookies, identifying authentication/labels, view keys, scan indices or
private proving witnesses. No direct fallback or automatic rebroadcast. A probe
through Tor is separate from payment integration and does not qualify sender
anonymity against endpoint fingerprints, counterparties or global timing.

A fresh original seed plus authenticated complete accepted output history,
selected public software/parameters and public proof/state data must suffice to
decrypt Receipt216, recover the encrypted index, validate the receiver descriptor,
domain, CM/Output proof/accepted position and spent NF, then derive Spend/Exit
authority. Scan locally without a roster, attempt journal, invoice lookahead,
private owner map, live counterparty or remote view/index queries. A change label
never determines spendability. Seed keys and any private proving witness remain
inside the owner process; a shared outer prover receives public components only.

A competing action/exit or reorg can stale a proof. Reconcile against accepted
history, confirm whether the NF was spent, and rebuild against the new head if
unspent. A disclosed NF can persist across attempts and link them; no anonymity
claim or permanent unpublished note lock follows. Use a new trial identity for
each funded testnet retry; never rebroadcast a used trial identity.

Retain direct full-note Exit152 and ExitBody1632 semantics with the selected new
tags/D/VK, one NF insertion, unchanged CM root/count, exact public destination,
payout and fee, and exact current reserve. The continuing native exit prefix is
240 bytes and terminal prefix192. Remaining reserve is zero or at least the note
floor; `remaining+payout+fee=old_reserve`. Terminal reserve zero is preserved.
Exit generation and native validation require neither MPC, another owner nor
the shared outer prover. Public software/history availability and actual
independent administration remain explicit dependencies.

See [privacy and acceptance](PRIVACY-AND-ACCEPTANCE.md) for claim boundaries and
the frozen acceptance checklist.
