# ADR 0073: Share one ordinary baseline across acquisition peers

Status: Accepted for a **nonlive implementation experiment only**. Actual adoption requires Root and independent review. No active profile, source selection, campaign or financial runtime is changed by this ADR.

## Problem

The selected strict fetcher prepares a complete baseline inside each peer attempt. Root measured the H14 baseline at 2,404,226,437 bytes; two copies require 4,808,452,874 bytes before new delta evidence. The projected reclaimed space was about 4.04 GB. Retaining another complete prefix for failover can therefore exhaust disk before confirmation.

## Decision

Create separate acquisition, fetcher, confirmation and caller siblings. Prepare the admitted baseline once, before any peer connection, in the fresh common bundle's `cached/` directory. Complete the existing guarded preparation and then make those new ordinary files read-only. Each peer gets its own `attempt-NNN/` directory and an independent deep copy of acquisition metadata. No symlinks, hardlinks, previous partial output or failed-peer state supplies the baseline.

Discovery reads from the common bundle. Cached page paths remain `cached/...`; primary delta paths become `attempt-NNN/delta/...`; post-query paths become `attempt-NNN/post-query/...`. Cached results require no blanket rebasing. Full fallback retains the existing `attempt-NNN/full-fallback/` mapping for both primary and post-query arrays.

Keep the existing prefix fingerprint, source lineage, admission, copied-page verification, hash checks, locator offsets, fixed-frontier, reorg, current-view, replay, whole-CASE, payout and sompi checks. The unchanged export verifier already accepts the empty prefix before `cached/...`. The new acquisition derivative is explicitly included in the outer network source closure and acquisition sidecar. Runtime68, its admission, original financial sources, guards, SDK and strict RPC implementation remain unchanged.

A preparation or permission-finalization failure is a local incomplete acquisition, with zero peer attempts. Retain its first failure and partial files; require a fresh output identity instead of resuming them. Peer failures retain separate event, delta and incomplete evidence.

## Limits and validation

This removes one retained baseline copy and repeated preparation inside the peer loop. It does not remove downstream authentication: discovery still reads selected pages, and the existing export verifier prepares its reference metadata and verifies copied gzip bytes. Read-only permissions are an accidental-write guard, not protection against a hostile host. Full fallback can still require additional history storage.

Freeze exact source deltas before the public synthetic controls specified in `research/next-session/local-private-payment/shared-prefix-01/DESIGN-01.md`. Controls must cover two-peer reuse, failed-first/successful-second isolation, both page arrays, immutable base metadata and bytes, fallback, malformed paths, tampering, source closure, and retained local preparation failure. Passing them is bounded storage/path evidence, not Native financial, privacy, recovery or release qualification. No live profile is selected here.

## Source basis

- Strict fetcher: `b3a7258ed4626f3f93d1956cd5012ced22d68feebe2931cb7f22c24d2fa04946`.
- Parallel preparation: `e63e74c320e9968ed78b34f0227c6e9ae27ec11bd955604fbfdc5af85dccfcc5`.
- Current cached acquisition: `419d0f9af4f00a02f19ba468ce2871c35270cb73d5de9da959f98c078159ff9a`.
- Cached export verifier: `16d4fd910380e44b78d60dfd7300ab0aec5ddfaebf54384a58197e92a78be8bd`.

These existing files remain unchanged. Exact derivative and dependency pins are recorded in the companion source freeze.
