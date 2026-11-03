# ADR-0014: Offline R08–R16 failure programme

Status: Accepted for the owner-authorized offline continuation, 2026-10-18.
R13's real-proof requirement and R16's independent native-payout gate stay open.

## Evidence and scope

Reuse the pinned Kaspa/vProgs/Research, Orchard, Aztec, RAILGUN, Monero and MWEB
[source comparison](../../research/recovery-source-review-2026-10-18.md), the
[recovery requirements](../shielded-recovery-test-design.md), and the existing
R01–R07 public replay/backup/session interfaces. No online source refresh,
cryptographic construction, native compatibility change or new server is needed.
Adapt complete replay for rollback, Monero's view/spend distinction for incoming
inspection, and full local scanning for query privacy. Reject root-only restore,
view-key spending, automatic retry of an unknown payment, and inferring a native
payout from a model event.

## Decisions and tested interfaces

R08 replaces the entire public history only after validating both supplied model
checkpoints and the exact common prefix. Build a replacement session first;
invalid or incomplete replacements leave the existing session untouched. Genesis
replay handles a fork crossing any earlier horizon; missing genesis data halts.
The replacement checkpoint is separately trusted, not selected by this code from
a node. Old expected-receipt metadata naming orphan notes can report incomplete
wallet data; never silently count an orphan note or manufacture its replacement.

R09 adds a protected local store: one JSON envelope containing the public export,
derived private wallet reports, revision and optional unknown-submission marker.
Single-host flock plus compare-and-swap serializes writers. fsync temporary file,
atomic replace and directory fsync publish old or new coherent state. Recompute
private reports on load. Test actual process kills at publication boundaries,
stale writers and invalid inputs. An unknown submission returns an inspect-history
instruction and never executes or automatically retries a payment. This is a
local trusted-disk experiment, not a filesystem power-loss or network submission
manager; permissions/checksums do not authenticate a malicious local checkpoint.

R10 checks each replacement archive against the caller's retained checkpoint;
only a complete matching copy is usable. R11 provides a separately versioned
incoming-only backup with no spending seed, and inspection that explicitly
declines authoritative spentness/spendability. Spending restore rejects it.
Missing proof artifacts are an explicit unavailable result, not invalidity.

R12/R13 exercise external rent funding and ordered valid/invalid/valid model
operations at the existing session boundary. No native fee market or real ZK
classifier is introduced. R14 records bounded CLI/public-output canary controls
and network audit events, without publishing private data. R15 continues to reject
unsupported statement/image/domain/backup versions; migration remains disabled.

R16 is an offline shutdown rehearsal: the producer process exits; replacement
public data plus exactly one user's backup go to each new process. Each user
constructs its own model exit/refund, a public-only process pays exact claims,
and individual restorers check final liabilities. All backing/rent reconcile.
Separate processes/directories are not independent hosts or OS sandboxing. The
actual all-users gate is reported **not passed**, with real proofs, independently
authenticated state and confirmed native payouts absent.

No invariant, asset, key derivation, statement domain, admin path or production
architecture changes. Existing archive v1–v3 and spending backups stay readable;
local-store and incoming-view formats have their own scope/version. Test the
public interfaces above and retain source hashes, results and explicit gaps.
