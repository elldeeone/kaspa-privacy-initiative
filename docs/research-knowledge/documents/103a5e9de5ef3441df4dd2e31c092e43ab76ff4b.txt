# ADR 0067: Authenticated local prefix reuse

Date: 2026-10-26

Status: Accepted for a bounded research/testnet implementation. Activation
requires independent controls and an actual cached replay. This is not a
consensus, privacy, or production qualification.

## Problem and evidence

The first ADR-0066 payment is accepted on TN10, transaction
`52759a70882cf763de38a289fb2683f5d8eb109b8f35c08d4bbaef6778b3a5c8`.
Its accepted whole CASE is
`a92f4c84cab943fbcc4b134512d36dd7566b69dd04ea27aa971b9fdf73b2c70a`.
The full confirmation took 1,185 seconds, including approximately 953 seconds
of acquisition. It retained 37 gzip pages, about 229 MB, covering two pool
transactions and hundreds of thousands of unrelated accepted transaction rows.
Repeating acquisition from the founding anchor after every proof makes the
remaining workload grow in both time and disk use.

The initial admitted full-verification handoff is SHA256
`73ee6f11fed5864ea7d6b692ab8b01d9831eb018dd3e52a966e5e69fe4d85ba5`;
its fetch selector is
`7af4dff3f8e998f485cd099902ac1e5f7474a7f7014347156f8cfd3a0f5605e8`.
These identify this actual run, not a general externally trusted checkpoint.

## Decision

Reuse a controller's own previously fully verified prefix and acquire a fresh
delta to a fixed frontier. Reuse the existing retained-page authentication,
pool-lineage discovery, fixed-frontier scan, post-query delta, reorg checks and
live UTXO queries. Keep the old full path available for initial verification,
external imports and safe fallback.

1. The fast path is explicit. Its admission binds the exact full-verified
   handoff, retained bytes, network/genesis, domain, founding descriptor,
   financial profile, SDK and verifier/runtime source identities. The controller
   obtains later cache selectors only from its own protected STATE after a
   successful confirmation. Network responses and public-directory discovery
   cannot select or grant admission to a cache.
2. Every retained page remains bound to its exact gzip and decoded identities.
   Tampering, wrong identity, unknown admission or source disagreement stops
   that fast path. A public JSON `PASS` is not an attestation. An external or
   otherwise untrusted cache must undergo full verification before admission.
3. Historical SDK/header/input-scan work may be reused only for the admitted,
   byte-identical prefix. Every new header, input edge and relevant transaction
   is verified. All selected pool transactions still undergo native Full,
   genuine founding-proof and complete financial/history replay.
4. A retained final RPC page can extend beyond its old fixed frontier. Stitch
   only the authenticated processed prefix, or explicitly verify and extend
   the retained tail. Reject overlap, gaps, incompatible request cursors and
   ambiguous coverage; never silently concatenate complete page files.
5. Preserve the fresh fixed-frontier delta, post-query coverage, removed-chain
   and anchor/reorg checks, and final live reserve/payout UTXO queries. A stale
   or reorged cache safely falls back to full acquisition/verification. Its old
   admission never makes an unverifiable current state spendable.
6. Keep every old source and evidence object immutable. Implement sibling cached
   modules and an explicit source closure. Native wire, domain, keys, image,
   authorization, integer amounts, fee budgets and once-only submission rules
   are unchanged. Do not reset consumed intent state or re-broadcast a used
   action to install the optimization.

## Trust boundary

Local controller/cache integrity is an explicit performance and evidence
assumption. It is not a new reserve-release authority or a consensus proof.
The existing bounded validating-node model remains in force. A compromised
host is outside that model; a downloaded public receipt alone confers no local
admission. Seed recovery can use the original full path without this cache or
any additional wallet secret.

## Required controls before activation

Independently test mutated page/decoded bytes, forged or absent admission,
cross-domain/profile/SDK/source reuse, wrong founding anchor, stale/removed
frontiers, mid-page tails, overlaps/gaps, changed live outpoints, and complete
delta coverage. Compare an actual cached replay with the retained full replay
and confirm identical financial history, liabilities, whole CASE and fees.
Final independent accounting must fully verify the retained ledger; it must not
inherit a financial or privacy PASS from a cache marker.

## Consequences

The native payment/exit protocol is unchanged. Network work can follow the
new delta instead of repeatedly downloading the complete history, while local
verification reuse requires a narrowly admitted controller cache. Portable
verification and independently retained history remain separate requirements.
Passing these controls does not qualify general payment anonymity, independent
administration, cryptographic correctness or the unchanged 2% fee target.

## Bounded extension: immutable public verification workers

The cached implementation still repeatedly walks protected host metadata while
authenticating the same source and page files. Both submission preflight and
confirmation replay perform this work. The following extension changes public
execution and file handling; it does not change the native payment protocol.

1. Admit a finite, externally pinned source, OS-runtime and public-input closure
   through the unchanged host helper09. Preserve its private-path, inode-alias,
   symlink, single-link and byte-identity checks. Hold admitted bytes in sealed
   descriptors. Later additive manifests must preserve every existing identity,
   target, mode, command and export rule; new source identities require fresh
   admission. A changed selector cannot inherit earlier admission.
2. Copy those bytes into ordinary single-link files in a fresh namespace with a
   read-only root. Mount no host directories, real original backups or private
   controller state. Close nonstandard descriptors before application entry.
   The offline worker has no network. Eight legacy backup pathnames contain
   synthetic empty metadata files solely because unchanged helper imports
   require their presence; they are not originals or wallet authority.
3. Permit only the selected original offline replay and preflight entrypoints.
   Preserve their absolute input/output paths and strict candidate/stdout
   binding. Stage a writable namespace-only parent while leaving the requested
   output leaf absent for the original script to create. Export only validated
   regular files in the declared result tree; refuse traversal, links and input
   overlap. Retain stdout/stderr as public diagnostics, not as financial PASS.
4. Keep Tor acquisition, fresh UTXO queries, private durable intent reservations
   and the single live submission outside this worker. The ordinary controller
   owns its public snapshot process and protected checkpoint selection. The
   process/socket grants no withdrawal authority. Its disappearance reduces
   liveness; the unchanged full verification path remains available.
5. Record new executed wrappers and OS identities in an explicit outer source
   profile. Do not disguise a wrapper as the old entry, replace interpreters or
   edit the original Source57/Runtime68 files. Retain all original financial,
   native Full, SDK, amount and once-only checks. Resume only at a stopped,
   genuinely confirmed or acknowledged boundary, using the existing private
   state; installing the worker must not reset or replay a financial action.

Actual read-only qualification used the retained second-payment prefix. Original
Source57 full SDK verification and all three native Full CASEs ran twice inside
the namespace in 79.52 and 76.20 seconds. Both runs produced byte-identical
RESULTS, HISTORY, CONTEXT, CURRENT-ENTRY and SDK reports to the original full
replay. Their reserve remained 5,961,543,200 sompi and observed prefix fees
39,132,900 sompi. The original offline full comparison took about 342 seconds;
one-time admitted-source work for this prototype totaled 268.90 seconds. These
are warm offline replay measurements, not campaign, acquisition or payout
latency. Evidence identities are comparison `4d490f04f19765d578394a765becc5368fb31f40cf8dc9a014ec2cc62ba2b307`
and independent five-file readback
`40abc99f1991e8200536335ee8f05d299855157169244bbbf5803aca39aa0344`.

The core isolation/export controls passed, including host mutation after
admission, protected stub aliases, descriptor closure and output refusal. A live
wrapper version additionally requires independent source/configuration review
and genuine cached-replay/preflight comparison with exact SDK-candidate and
financial agreement. The prototype alone does not authorize live activation.

### Known-public confirmation writer

After the third confirmed payment, the controller stopped before action four.
A known-public dummy fixture reproduced a source-consistent cause: a historical
private-inode exclusion set can reject a new public file after the filesystem
reuses an unlinked private-state inode. The actual caught exception was not
exported, so this remains a qualified diagnosis rather than a private-log claim.

A separate, explicitly pinned caller subclass removes only redundant readback
of its own known-public JSON. It uses exclusive no-follow creation, complete
writes, file/directory fsync and descriptor/path metadata checks, then returns
the digest of the exact encoded buffer. It does not clear historical exclusion
sets, edit helper09 or bypass any later financial input read. The confirmed
marker is not a later financial input; the existing private checkpoint and
qualified CASE selectors remain the continuation authority.
