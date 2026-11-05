# Joint withdrawals: source-level feasibility

**Reviewed:** 5 November 2026, Australia/Sydney. **Scope:** source inspection of
current L1 and the retained KPI implementation. No proof, native validation,
network trial, MPC run or blind-registration protocol was executed for this note.
The owner authorized this bounded feasibility check and a comparison only if a
concrete candidate is feasible; consensus changes are excluded.

## Source conclusion

**The existing withdrawal path cannot conceal its request-to-payout assignment
by batching or shuffling alone.** Its public operation names the destination
and value before payment, and subsequent permission/payout records preserve the
link. Ordinary post-exit CoinJoin could obscure ownership of *later* outputs,
but cannot retract the already exposed withdrawal facts. [K1–K5]

This is **not an impossibility result for current Kaspa L1**. Current proof
verification and output-introspection primitives provide a plausible seam for
a different application protocol with whole-set authorizations. That protocol,
its anonymous output registration, independent fallback and full economic/native
bindings are not implemented or qualified by the inspected path. Deleting its
currently public destination fields from an observer would not demonstrate
feasibility or privacy. [L1–L4]

Human ownership and request identity are separate: the public `Statement` does
not itself encode a person's identity. Turning its destination link into an
owner link requires actual service-origin or auxiliary owner information. Such
information must be declared and retained when available. [K1, K3, H1]

## Fresh upstream identities

Heads were resolved through official GitHub APIs during this check; decisive
files were read at these exact revisions. A source head is not a running-node
or current-mainnet qualification.

| Repository | Inspected head |
| --- | --- |
| `kaspanet/rusty-kaspa` | `4863866fce8439d0305b410fc4d802e7261d54d0` |
| `kaspanet/docs` | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| `kaspanet/vprogs` | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| `kaspanet/research` | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |
| `WalletWasabi/WabiSabi` | `1e6deb989f58bc6edce91bc300252d2bed18db30` |
| KPI fork inspected implementation | `00018b9898ae2f09c9bca59ede632aee54c940ec` |

The older `zkSNACKs/WabiSabi` repository redirects to
`WalletWasabi/WabiSabi`; the inspected commit is unchanged. vProgs' README still
describes prototype infrastructure. The research repository's vProgs paper
discusses proof verification/introspection and bridge architecture; it does not
supply the missing KPI anonymous-registration implementation. [W1, L5, L6]

## The public assignment is present before the payout

1. `Statement` contains `exit_destination` and `exit_value`. `bytes()` encodes
   both, and `inputs()` converts those bytes into proof public inputs. The
   operation ID is also derived from those statement bytes. Reusing the same
   proofs while hiding these fields changes the observation model, not the
   protocol. [K1]
2. The owner wallet sets that destination from its native recipient key and
   exports the key plus the complete operation payload. The lane parser reads
   that payload and requires the recipient key to match the statement. It
   records `exit_keys[operation_id]` and the selected reserve. [K2, K3]
3. The retained application permits only one unpaid exit at a time. Its
   permission and payout payloads carry the exit ID. The permission script
   requires input index zero, three inputs, one selected reserve and a fixed
   output layout. Its committed leaf contains the destination and amount. A
   multi-permission transaction is therefore not a drop-in layout change. [K3–K5]
4. Reconciliation requires the actual permission/reserve outpoints and output
   zero's registered recipient script and sufficient amount; changing the
   output order or recipient while retaining the old authorization rejects.
   Those checks protect funds and must not be weakened for the experiment. [K4]

The general upstream permission-tree helper can commit several `(destination,
amount)` leaves. Its spend implementation still checks a particular withdrawal
against output zero and updates remaining permission state; a multi-leaf root is
not evidence of a private simultaneous multi-recipient payout. [L3]

## Candidate separation

| Candidate | Source assessment | Permitted conclusion |
| --- | --- | --- |
| Shuffle or jointly redeem the existing public EXIT requests | Original request destinations remain observable; retained scripts/application also constrain one pending exit and single-exit shapes. | Reject as a concealment bolt-on. Preserve those public fields in any negative control. |
| Ordinary jointly signed transaction after individual payouts | Ordinary outputs and input references are public. A separate cooperative transaction can have a different output ownership ambiguity. | Possible downstream unlinking hypothesis; earlier request/withdrawal information stays exposed. Not a repair of prior payment disclosure. |
| New common-set authorization and payout protocol | Supported proof tags and native output inspection can express relevant checks. Individual public destination authorizations would have to be replaced, not merely filtered. | Plausible application redesign; source-level expressibility does not establish an implemented, native-verified withdrawal path or coordinator privacy. |

For the third candidate, each owner could authorize the **same complete output
set**, checking locally that the full sum of all its expected payouts is
included. A private input-to-output bijection need not be invented: a user may
authorize a complete transaction, as in cooperative transaction construction.
Authorization of somebody else's complete set without checking one's own full
entitlement would be unsafe. [W1; design inference]

An implementation would still have to bind the prior state and actual reserve
inputs, all current spentness checks, exact output count/values/scripts, fees,
successor and liabilities. Fixed output introspection is already demonstrated
in A1 source, and A0 connects exact economics to the supported Groth16 hook.
Both original harnesses have different input/authorization assumptions and do
not implement this joint protocol. [L1, L2, K6]

The service mapping remains a separate obligation. Sending an identified
owner's desired destination to the coordinator reveals the map even if a later
proof publishes only an aggregate. Anonymous registration requires a concrete
message/transport design with collusion, timing and retry analysis. Owner-local
proofs avoid giving a prover spend secrets but do not prove network-origin
anonymity. A custodial issuer or operator signature must not acquire reserve
withdrawal authority. [W1; SECURITY-INVARIANTS I-3, I-7–I-10]

## Established designs reused or rejected

- **WabiSabi:** reuse the separation between input participation, unlinkable
  output registration and participant approval of the complete transaction.
  Its specification leaves transaction-structure privacy as a separate problem
  and assumes network privacy; it discusses Sybil, timing and abort risks.
  No Bitcoin message format or credential implementation is treated as a Kaspa
  port, and no new blind-signature primitive is proposed. [W1]
- **Orchard, Aztec and RAILGUN:** retain wallet-held authorization, authenticated
  state, spentness/conservation and discovery obligations from the existing
  five-protocol source review. Their consensus/native verifier or EVM custody
  interfaces are not imported as Kaspa capabilities. [H2]
- **Monero and Litecoin MWEB:** retain the distinction between ownership/value
  confidentiality and transparent boundary observations. Their consensus
  confidential-value representations are outside the allowed architecture. [H2]
- **Paused KPI MPC construction:** its bounded constructor-map result is not
  evidence that the current withdrawal service or terminal payout is private;
  no paused work was resumed. [H3]

## Guard against an invalid favorable comparison

Keep every existing request, permission, native output and already observed
intermediate payout in the baseline and bolt-on observations. Keep known-owner
facts separate from chain facts, but do not erase legitimate owner knowledge.
Full drainage with known owner totals retains the original arithmetic attack.
At least two independently controlled honest participants are necessary for
ordinary participant ambiguity; one honest participant among fully known
colluders is identified by elimination. Equal-looking outputs are not evidence
that such peers exist. [H1, W1; logical inference]

A source/projection audit can falsify the unchanged-path hypothesis. A favorable
comparison for a redesigned protocol must wait for its concrete observation
surface and authorization path; neither an ideal anonymous-registration oracle
nor assumed zero-knowledge opacity closes that implementation gap. This note
does not change old thresholds, qualify privacy or accept an architecture.

## Sources

[K1]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/private-note-wallet/src/protocol.rs#L145-L217
[K2]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/recovery-native/host/src/bin/wallet.rs#L145-L172
[K3]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/recovery-native/common/src/lib.rs#L423-L465
[K4]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/recovery-native/common/src/lib.rs#L230-L299
[K5]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/recovery-native/common/src/restricted.rs#L35-L107
[K6]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/a1/src/script.rs#L57-L80
[L1]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[L2]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/crypto/txscript/src/zk_precompiles/tags.rs#L5-L21
[L3]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_tree.rs#L37-L78
[L4]: https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/consensus/core/src/tx.rs#L176-L190
[L5]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L1-L7
[L6]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex
[W1]: https://github.com/WalletWasabi/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md
[H1]: ../full-drainage-executed-lifecycle-2026-11-01/NEXT-PRIVACY-RESULT.md
[H2]: ../native-kas-shielded-value-sources-2026-11-03.md
[H3]: ../../docs/research-knowledge/documents/8afbd3d859a68dc4d80194cbdc3f0cc36e5e9961.txt

The upstream permission spend details are in
[permission_script.rs](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L250-L288)
and its
[output checks](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L408-L468).
A0's retained exact-output/proof boundary is in
[main.rs](https://github.com/elldeeone/kaspa-privacy-initiative/blob/00018b9898ae2f09c9bca59ede632aee54c940ec/poc/a0/src/main.rs#L101-L189).
