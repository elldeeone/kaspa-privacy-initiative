# ADR-0082: Optional owner-origin Exit submission

Date: 2026-10-28.

Status: accepted bounded experimental design for an isolated receive/verify-only
prototype. No current workload change or measured anonymity result is claimed.

The public transport component completed a real Tor rehearsal: three one-shot
4,096-byte packets arrived byte-identically and the receiver drained cleanly.
Independent NativeFull verification of the received bytes accepted two genuine
cases and rejected the changed-destination old-proof case at Groth16 verification.
These were already public, unfunded known-seed cases. Earlier incomplete runs
remain separate evidence; they are not combined into a passing trial. No Original,
new proof, accepted chain, funding or broadcast was involved, and same-host
anonymity remains unqualified.

The owner-to-pipe boundary and combined Tor flow subsequently passed using one
already exposed, previously proved candidate. The selected network-off role
performed the existing genuine validation, wrote one frame to stdout, and a
no-Original transport consumed stdin and delivered it over Tor. The controller
handled fixed statuses and process/FD/timing metadata without opening or hashing
the candidate, frame or recipient body, or exporting a labelled content digest.
After recipient release, one independent NativeFull/all-input check accepted the
exact received bytes. No new proof, Original, note, funding or broadcast was
created. This establishes the optional transport's functionality, not anonymity;
the next privacy comparison remains source-only and unselected.

The present explicit owner release hands clear candidate bytes to an
owner-labelled controller path, and METHOD02 preserves owner order across arms.
Fresh payout keys remove invoice-address reuse, but cannot remove those facts.

Select an optional, non-custodial transport seam for this experiment: network-off owner validation
feeds a private pipe to a no-Original transport role; a fixed-size candidate is
submitted over an isolated Tor stream to one common onion dispatcher. The
dispatcher preserves actual arrivals and reuses exact current-head/proof/native
validation. It has no signing or withdrawal authority. Direct permissionless Exit
remains unchanged and requires no relay, peers, batch or delay.

Use established Tor/curl tools and the existing AuthExit/native ABI. Do not add
an anonymity primitive, asset, proof circuit or setup. Retain current frozen
counterexamples; measure a new method with all launch, pipe, arrival, timing,
amount and counterparty information. Do not claim anonymity against a host or
network observer that can correlate both ends.

The initial prototype is receive/verify-only, isolated from current source and
METHOD02. A live broadcaster and accepted-history authority remain separate.
See [RFC-0031](../rfc/0031-owner-origin-exit-submission.md) for exact source
evidence, fields, failure rules and primary references. Before any future live
submission, the real current-head, native validation and complete confirmation
path must qualify independently. I-1 through I-16 remain unchanged. No mainnet
or real funds are permitted.
