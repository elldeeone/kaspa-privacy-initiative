# ADR-0049: Receiver-driven recovery from accepted public records

**Status:** Accepted for research implementation and bounded testnet validation.
**Date:** 2026-10-23 UTC.

## Problem and source basis

The confirmed six-body trial restores recipients from old seed-only backups,
but its caller supplies a complete archive, snapshots, operation list and intended
amounts. This does not demonstrate discovery after the preferred operator is
lost. The prior source comparison and refreshed official Kaspa/Orchard/Aztec/
RAILGUN/Monero/MWEB inspection motivate local scanning and incremental witness
reconstruction from retained public data.

## Decision

Build separate fetch, public replay, receiver and native signing modules. Preserve
all closed sources and the funded trial. The receiver provides its own backup
and authenticates a minimal public instance descriptor: TN10 network/genesis,
domain, canonical founding outpoint, pre-founding scan anchor, initial redeem,
VK328 and derived immutable-policy hash. Canonical sorted JSON determines its
digest. The selected founding outpoint is an explicit instance-identity trust
anchor; a coherent domain/VK does not choose among deliberately cloned pools.

The application bundles a source/compiler-pinned state-free policy template.
Only canonical domain32 and VK328 pushes may be substituted, at declared parsed
offsets. Compare the complete resulting policy, not merely D/VK substrings in an
arbitrary script. Check conformance against the already accepted fresh-domain
script. Development setup honesty and the selected VK remain explicit assumptions.

Fetch raw accepted FullV2 records from independently contacted validating nodes,
starting at the birth anchor and reaching a frozen confirmed frontier. Preserve
pagination, exact headers, actual input contexts and removals. Endpoint failover
restarts from a verified anchor; it does not splice unverified partial views.
Replay follows the exact reserve outpoint graph and reconstructs CM records,
ciphertexts, physical indexed nullifiers, roots, backing and current head. It
accepts no operator snapshots, owner labels, six-ID list or expected-payment map.
Missing/pruned prefixes, broken links, conflicting successors or an absent head
without a verified terminal transition are incomplete, never zero balance.

Query current head/payout outpoints and reconcile subsequent accepted activity.
An approved generic native validator can locally check actual signatures and
Groth16 using only the public VK; it never needs a proving key. Report hash replay,
local script/proof verification and selected-node acceptance as distinct evidence.

Only a separate network-isolated owner process reads one backup and decrypts
receipts. It constructs fresh current witnesses and, after explicit revealing-exit
consent, can build a new native exit from the authenticated actual redeem. Use
official Schnorr SIG_HASH_ALL, mass and Full validation. No operator signature,
payer/other-recipient seed, PK, prover or precomputed exit is required.

## Trust and limits

Multiple RPCs improve availability and corroboration; they do not establish
independent consensus. Retained data remain necessary. If every source prunes
required ciphertexts/witness records, a root alone cannot recover them. Correct
receiver encryption is not proved by the current circuit: recognized claims and
recipient acceptance require decryptable, descriptor-consistent delivery. A failed
decryption is not proof that no conceivable owned liability exists. Preserve
previously recognized claims and all global backing. A valid terminal zero
reserve is a stronger, separately checked statement.

The first live positive reconstructs the completed trial without its operator
archive. It cannot establish a new unspent recovery/exit by itself. Synthetic
large-history cost and fault controls remain separate from accepted network
evidence. A later fresh test-KAS trial may test service loss before exit; no used
identity is rebroadcast. Native KAS, all invariants, unchanged requirements and
no-mainnet/no-real-funds constraints remain in force.

The first implementation supports the old Auth484/KPX2 program. Auth528 private
cashouts and terminal transitions that do not append CMs require a separate
approved template and replay adapter before these recovery results apply to
that new program. Generic native signing support is insufficient by itself.
