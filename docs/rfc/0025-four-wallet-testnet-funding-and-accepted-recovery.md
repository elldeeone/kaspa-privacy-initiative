# RFC-0025: Four-wallet testnet funding and accepted recovery

**Status:** Open. Bounded implementation contract selected by ADR-0060;
accepted-chain, privacy and availability outcomes remain separate.
**Date:** 2026-10-24 UTC. Baseline `b7b41ab066807d7859499b3491a663ab110fedf9`.

## Problem and evidence

The [previous result](../../research/next-session/independent-payments/RESULTS.md)
has genuine two-owner shared settlement, original-backup private drainage and
zero reserve in supplied contexts. It has no strict accepted GN2 entry or
current-W network adapter. Cross-paying actors combine incoming value and their
own change in one exit; that does not price independent payer/recipient sets.
The owner now requests A pays B and C pays D, including recovery and confirmed
native payouts for all four wallets. Only free TN10 KAS is permitted.

This continues [P07](https://github.com/olafweller/kaspa-privacy-initiative/issues/7),
[P08](https://github.com/olafweller/kaspa-privacy-initiative/issues/8),
[P11](https://github.com/olafweller/kaspa-privacy-initiative/issues/11)
and RFC-0024. Their current public issue statements were retrieved again on
2026-10-24. The existing source-reviewed
[readiness design](../../research/next-session/independent-payments/testnet-next/DESIGN-READINESS.md)
and the new bootstrap/chain/profile/lifecycle design notes are implementation
inputs, not execution results.

## Alternatives and selected bounded direction

Reusing the public benchmark would inherit explicit DO_NOT_FUND identities.
Keeping a single depositor would omit the newly required independent funding
boundary. Adding an entry branch to W would unnecessarily change the native
spending policy: ordinary funding inputs execute their own scripts, and W is
executed when its output is spent. Adopt a separately versioned strict GN2
client contract and fresh financial assets, retaining the established private
relation and exactly-two-action settlement semantics.

GN2 creates two initial notes, one for A and one for C. B and D receive the
two private payments. A/C positive sender change and B/D incoming payments
remain four distinct owners' liabilities. Price four independent private exits;
no private witness aggregation, manufactured payment ring or working-balance
requirement substitutes for complete drainage. A zero-change wallet policy is
not selected by this work.

## Required boundaries

- Ordinary funding validation and W entry validation are distinct. Each owner
  independently validates its allocation, immutable original note record and
  receipt recovery before signing only its own ordinary input with ALL.
- The final financial-profile digest excludes all trial data, and is not
  compiled into its own guest. Software inventory is independently selected;
  including it in a profile that the inventory contains would create a cycle.
- Follow actual accepted physical outpoints, complete public deliveries and
  fresh native UTXO contexts. Virtual child IDs are never live W heads.
- Missing, stale, pruned, conflicting or reorged history is INCOMPLETE. Neither
  an RPC success nor a local Full result proves accepted/current backing.
- One original backup remains local to each owner. Proof generation validates
  whole PK/VK and READY before reading it; recognition and ordinary funding
  approval authenticate software/profile/history without a proving-key burden.
- One-time financial setup is separate from one-command fresh trial creation.
  Failed trials use fresh identities; failure alone does not require new setup.

## Completion criteria

The lifecycle gate requires accepted funding, accepted shared settlement, loss
of coordinator/proving service, four independent original-backup recoveries,
every confirmed native payout and zero reserve. Integer sompi must close:

```text
ordinary sources = ordinary change + entry fee + settlement fee
                 + all private exit fees + all native payouts
```

The first live run is a rehearsal. No ready claim precedes actual confirmation
of all terminal payouts. Preserve any failed attempt and start a fresh identity;
never weaken a financial check or rebroadcast a used transaction.

## Separate research questions

The strong privacy observer and original failed thresholds remain unchanged.
An established owner-private construction must survive both public and assembler
knowledge before a new privacy relation is selected. Confirmed payments cannot
repair current public component partitions or sparse funding ancestry.

Public storage must be tested against a real separately controlled destination,
with explicit retention and provider-loss retrieval. Same-owner GitHub/Drive,
same-host copies or one successful download are not that evidence. No such
destination is currently configured; the user has been asked for it while a
finite authenticated retrieval harness is prepared.

## Outcome and reconsideration

[ADR-0060](../adr/0060-four-wallet-gn2-testnet-rehearsal.md) records the bounded
funding/history decision. Reconsider on failed initial recoverability, ownership,
body/fee binding, accepted-prefix reconstruction or independent fallback. No
cryptographic soundness, financial privacy, mainnet or production claim follows.
