# ADR-0029: Integrate own-key admission and backup recovery

**Status:** Accepted — bounded offline integration scope, not protocol adoption.

**Date:** 2026-10-20

**Related RFC:** [RFC-0013](../rfc/0013-coherent-v6-lifecycle.md)

## Decision

After the public replay component at `fa1dcf1`, the owner directed continuing
milestone 2 with new-participant admission and backup recovery. Add a thin
current-version wallet interface around the existing v6 relation, public replay,
wallet keys, authenticated note encryption and native transaction validation.
Do not introduce a new circuit, setup, covenant, token or privileged role.

An independently initialized wallet keeps its spending, viewing and native keys
in a versioned private backup. Bind that backup to the authenticated public
descriptor and exact proving-parameter hash/size; the descriptor already pins
the verification key. Only the founder additionally needs the original note
opening, because its commitment is not an encrypted receipt. A later participant
must not need an updated backup after admission, incoming payments or change.
Do not store recovered notes or saved exit proofs as recovery prerequisites.

Use the existing public replay inputs and a separately supplied expected endpoint
to rebuild state. The endpoint must match transaction count and final full hash.
It detects disagreement with that expected history, not whether the endpoint
itself is accepted or fresh. Authentication and chain acceptance remain external;
offline results continue to report that chain acceptance is unverified.

Scan both ADMIT and SPEND outputs, advancing two commitment positions even for
padding. Check decrypted note ownership, commitment, v6 amount floor/range,
membership and the existing position-bound nullifier before selecting a note.
Do not copy the older recovery scanner's SPEND-only behavior or use the older
position-independent nullifier. DRAIN adds no note outputs.

The proof binds ciphertext bytes but does not prove correct encryption. A valid
public transition can therefore contain unusable delivery. Reject credit for
that receipt while continuing to scan and spend unrelated valid notes; otherwise
any sender knowing a public receiving key could disable the victim's wallet.
Public history, proof, membership or state inconsistencies still stop processing.

Build admission from an actual supported parent output, require the wallet's
funding signature and create an encrypted self-receipt. Build ordinary payment
and change from one or two owned unspent notes. Build a fresh exit to the native
destination derived from the recovering wallet's own key. Validate requests,
parameter integrity/VK correspondence, generated proofs and complete native
transactions. Retain the current 0.4-tKAS fee for this mechanics test; it does
not meet all milestone 1 targets.

Private files use restrictive permissions and exclusive creation. Public exports
contain receive data or complete transactions, never spending/viewing/native
secrets, plaintext notes or private circuit witnesses. No new funded trial is
part of this step.

Selected note positions, amounts, inspection results and native derivation indices
are sensitive local wallet information. In particular, an exit index derived
from a consumed position must not appear in the public transaction wrapper.
Sharing a shielded receive envelope must not also expose a native funding address.

## Alternatives

Extending the old four-wallet controller would leave participation dependent on
its private fixture. Importing older H7 or upstream recovery wholesale would mix
different state/proof/backup identities. A new proof relation would combine a
cryptographic change with the integration question. Reusing the existing relation
and exposing the missing client interfaces gives a smaller falsifiable test.

## Decisive offline trace

1. Founder A creates a synthetic-native-context 20-tKAS reserve and bootstraps
   19.6 tKAS to itself. Only then initialize B with independent keys and seal B's
   backup; the public descriptor is unchanged.
2. B admits 12 tKAS, receiving an encrypted 11.6-tKAS note. Stop B's active
   wallet. A pays B 19.2 tKAS while B is offline, leaving A no private liability.
3. Restore B from its original pre-admission backup and public data. It must
   discover both the admission and incoming-payment notes, without A's secrets,
   a plaintext-note export or a saved proof.
4. B spends both recovered notes into a 10-tKAS payment to independently
   initialized C and 20.4-tKAS private change. C scans and exits 9.6 tKAS.
5. Restore/scan B again from the same original backup. The old notes must be
   spent, the change recoverable, and a fresh 20-tKAS exit must drain the reserve.

The six pool operations cost 2.4 tKAS: 32 entering the reserve =
29.6 payouts + 2.4 fees + zero remaining. Ordinary funding costs are separate.
Use the retained v6 parameters and fresh local proofs. Synthetic parent ancestry
is explicit and cannot be presented as new testnet acceptance.

Success requires the complete trace, unchanged descriptor/parameter identity,
native validation and exact accounting, plus rejection controls for wrong
backup/pool/parameters/head, missing or altered history/funding, unauthorized
selection, duplicate/spent notes, malformed delivery, range/floor errors and
replayed or damaged transactions. A clean recovery process receives only the
backup, public data, parameters and software; state that process isolation's
actual limits. Safe rejection alone is not successful recovery.

## Remaining obligations

This is local integration evidence. Live arbitrary admission and payout,
independent public-data survival, reorg/pruning recovery, sustained contention,
review of the single-party setup/relation, privacy and cost/performance remain
separate obligations. Do not silently mark those passed when the local trace
passes. Preserve the old runners and all earlier evidence.
