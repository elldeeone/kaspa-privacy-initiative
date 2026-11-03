# ADR-0082: Optional owner-origin Exit submission

Date: 2026-10-28.

Status: accepted bounded experimental design for an isolated receive/verify-only
prototype. No current workload change or measured anonymity result is claimed.

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
