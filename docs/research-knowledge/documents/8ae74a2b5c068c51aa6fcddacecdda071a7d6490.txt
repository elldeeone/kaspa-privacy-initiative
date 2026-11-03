# Coherent v6 lifecycle: source and reuse review

Reviewed 2026-10-20 for [RFC-0013](../docs/rfc/0013-coherent-v6-lifecycle.md).
Local baseline: `a869d164e72e78628814d62aafbaceb3babc8503`.
The task is to connect existing v6 deposit, payment/change, withdrawal and
recovery mechanisms to independently held wallets and authenticated public data.
It does not require a new note scheme, proof relation or operator service.

This is source inspection and an integration recommendation, not implementation
qualification, deployment verification or proof of cryptographic security.
Research/testnet only; no real funds or live trial was used for this review.

## Current upstream work

Read-only `git ls-remote` rechecked these initiative refs on 2026-10-20.
Referenced source files were fetched at the full commits below.

| Ref | Verified commit | Relevant state |
| --- | --- | --- |
| `main` | `52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33` | Merged PR58, six-batch local recovery proof work. |
| [PR59][pr59] | `585558091cc7d326e28d10f9c04e709952c85cf5` | Open Linux wallet onboarding work. |
| [PR60][pr60] | `f02e98d5918af3f53985b77809c7e930d888231f` | Open six-stage TN10 recovery integration/preparation. |

Open [deposit issue #7][issue7], [recovery issue #10][issue10],
[delivery/scanning issue #12][issue12] and [exit-fee issue #23][issue23] remain
relevant requirements. Their open status does not mean the corresponding
mechanisms are absent: inspect current code and bounded evidence together.
Issue #10 specifically requires a clean independent rebuild and valid exit;
an authenticated root or safe halt alone does not establish recoverability.

| Inspected source | Reuse/adapt | Do not import or overclaim |
| --- | --- | --- |
| [Merged wallet CLI][wallet] | Own-key initialization, public receive data, local scan/exit, ordered rebuild and independently supplied expected roots. Preserve private files and reject overwrites. | Its relation, roots, parameters and backup encoding differ from v6. Replay does not establish checkpoint freshness. |
| [PR59 client][client] and [scope][clientreadme] | Public-field allowlisting, package integrity, fresh local key creation, private permissions and preserving partial initialization. | This is onboarding, not a general funded wallet. Its fixed Alice/Bob wrapper and distribution package are not prerequisites for M2. |
| [PR60 wallet integration][tnwallet] | Prove locally from own backup, exact public parameters and an independently expected accepted state. Derive the exit destination from the claimant's own key. | It still fixes Alice/Bob roles and 10/4/6-KAS workload amounts. Its four-proof local qualification uses synthetic native context. |
| [PR60 initialization][tnmain] | Import only explicitly allowed public receive fields; keep user secrets out of the public trial and prover inputs. | The public trial includes a participant list. That is not the participant-independent descriptor sought for the direct pool. |
| [Upstream ADR-0011][adr11] and [ADR-0017][adr17] | Recipient validation, public/private separation, native enforcement and liabilities retained until actual payout. | Their application kernel, permission rents, outer proof runtime and settlement identities are a separate architecture. |

[PR60's current report][tnreadme] explicitly distinguishes preparation and
local qualification from a new live trial. Its wallet/control boundaries are
useful; neither the service nor its published image establishes v6 recovery.
Do not duplicate its staged GPU service to implement direct-pool wallet commands.

## Reuse within this branch

| Existing component | Keep | Adapt for the integrated lifecycle |
| --- | --- | --- |
| [v6 relation and settlement](../poc/shared-pool/src/two_input/mod.rs), [circuit](../poc/shared-pool/src/two_input/circuit.rs) and [covenant](../poc/shared-pool/src/two_input/covenant.rs) | Existing ADMIT/SPEND/DRAIN semantics, two-input authorization, private change, current nullifiers and historical anchors. | Expose these mechanisms through wallet inputs without replacing proof or covenant checks. |
| [Shared wallet primitives](../poc/shared-pool/src/protocol.rs) | Existing spend/view/native keys, receive data, encryption/decryption and payout derivation. | Add versioned wallet/public envelopes; validate recipient ownership, commitment, value and accepted membership before reporting spendability. |
| [H7 recovery implementation](../poc/shared-pool/src/compact/recovery.rs) and [ADR-0020](../docs/adr/0020-independent-wallet-recovery.md) | A backup authenticates the descriptor; parameters are pinned; public history rebuilds state; scanning and first exit proving stay local. | Port to v6 trees, padding, admissions and multiple notes. H7's three-wallet result is not inherited evidence. |
| [v6 live adapter](../poc/shared-pool/src/two_input/live.rs) | Exact native transaction reconstruction, reserve lineage, proof extraction, integer accounting and unchanged saved authorizations. | Remove four-wallet/amount/source-list assumptions from the new integration path; preserve the historical fixture path and evidence. |
| [Public chain transport](../poc/shared-pool/chain.mjs) and [H7 public sources](../poc/shared-pool/recovery-common.mjs) | Accepted-history discovery, exact current UTXO checks, replaceable public files and parameter verification. | Use v6's actual reserve termination rule. H7's commitment/nullifier-count shortcut does not apply to v6 padding. |

H7's initial depositor keeps its original note opening because the bootstrap
commitment cannot reconstruct randomness from keys. Preserve that requirement
unless a separately specified deposit-delivery mechanism replaces it. Ordinary
recipients should discover later encrypted payments from a backup that predates
them, without receiving another wallet's secrets or plaintext note export.

The [same-day primary-source review](shielded-kas-privacy-requirements-2026-10-20.md)
already pins Toccata/KIPs, Rusty Kaspa, vProgs/research, Orchard, Aztec, RAILGUN,
Monero and MWEB. Reuse its recipient-validation, current-spentness, private-scan,
historical-data and observer-transcript requirements. No new cryptographic
choice requires duplicating that review. Its source and unread-paper limits
continue to apply; reviewed designs do not transfer their security to this code.

## Funding authenticity and public parser scope

The present v6 descriptor predeclares four funding sources. Its replay resolves
admissions only against that list. The study's
[`verify_raw`](../poc/shared-pool/src/two_input/harness/study.rs) instead constructs
funding UTXO context from authorization fields and labels the result synthetic.
Neither supplies general evidence that an arbitrary native funding output exists.

For an admission, resolve the referenced accepted parent transaction and exact
output index. Recompute/check identity and compare the actual output's amount,
script and supported metadata with the authorization. Verify the signed
admission with that resolved context. For submission, separately check that the
funding output and reserve are currently spendable in the accepted node view.
A transaction body alone proves neither acceptance nor current unspentness.
An already consumed historical input cannot be required to remain unspent.

A funding parent can predate the descriptor's discovery start block. A scan
starting there may include its admission but omit the parent body. Support
authenticated retained earlier history or an explicitly checked parent-source
path; otherwise report missing funding evidence and stop. Never fill the gap
with the authorization's own amount/script or treat absence from that scan as
proof the funding is invalid. Pruning can make this an availability failure.

The existing [native parser/builder](../poc/shared-pool/src/native.rs) is narrow:
the parser accepts canonical version-1 native transactions with zero gas and
lock time and no explicit covenant bindings; the ordinary builder spends one
non-coinbase P2PK input under SIGHASH_ALL and retains positive change.
These are implementation limits, not a description of every valid Kaspa
transaction. A supported funding output can have a parent using another ordinary
transaction format. State exactly which parent formats the integration accepts.

Extending public-parent decoding to a supported ordinary format is not a new
private relation. It still needs exact version-specific hashing, signature/input
metadata and canonical handling. Keep reserve-transition validation strict;
do not broaden all protocol envelopes merely to inspect funding parents.
Reject unsupported coinbase, script or covenant cases explicitly. Do not infer
metadata by setting every imported output to ordinary/non-coinbase.

## Integration conclusion and evidence gate

Retain one v6 circuit/covenant/parameter identity. Add independently initialized
wallets, an authenticated participant-independent pool descriptor, actual funding
resolution, public replay and wallet scanning/proving. A generalized descriptor
does not authenticate itself; users need a trusted pool identity in their backup
or an explicitly authenticated onboarding step.

The useful trace admits an unknown participant after genesis, receives another
payment while offline, restores a pre-operation backup without original private
directories, spends recovered value with change, and exits all supported claims.
Require exact native accounting and recipient spendability throughout. Reject
substituted pools/parameters/parents, changed amounts/scripts, reused funding,
missing history, false heads and cross-version state without weakening checks.

This gate first establishes a local integrated lifecycle. Live acceptance,
independent source survival, broader reorg/pruning recovery, contention, fee
adequacy and useful privacy remain separately evidenced obligations.

[pr59]: https://github.com/olafweller/kaspa-privacy-initiative/pull/59
[pr60]: https://github.com/olafweller/kaspa-privacy-initiative/pull/60
[issue7]: https://github.com/olafweller/kaspa-privacy-initiative/issues/7
[issue10]: https://github.com/olafweller/kaspa-privacy-initiative/issues/10
[issue12]: https://github.com/olafweller/kaspa-privacy-initiative/issues/12
[issue23]: https://github.com/olafweller/kaspa-privacy-initiative/issues/23
[wallet]: https://github.com/olafweller/kaspa-privacy-initiative/blob/52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33/poc/recovery-native/host/src/bin/wallet.rs
[client]: https://github.com/olafweller/kaspa-privacy-initiative/blob/585558091cc7d326e28d10f9c04e709952c85cf5/poc/recovery-client/client.py
[clientreadme]: https://github.com/olafweller/kaspa-privacy-initiative/blob/585558091cc7d326e28d10f9c04e709952c85cf5/poc/recovery-client/README.md
[tnwallet]: https://github.com/olafweller/kaspa-privacy-initiative/blob/f02e98d5918af3f53985b77809c7e930d888231f/poc/recovery-tn10/src/wallet.rs
[tnmain]: https://github.com/olafweller/kaspa-privacy-initiative/blob/f02e98d5918af3f53985b77809c7e930d888231f/poc/recovery-tn10/src/main.rs
[tnreadme]: https://github.com/olafweller/kaspa-privacy-initiative/blob/f02e98d5918af3f53985b77809c7e930d888231f/poc/recovery-tn10/README.md
[adr11]: https://github.com/olafweller/kaspa-privacy-initiative/blob/52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33/docs/adr/0011-local-private-note-wallet.md
[adr17]: https://github.com/olafweller/kaspa-privacy-initiative/blob/52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33/docs/adr/0017-integrated-recovery-native-guest.md
