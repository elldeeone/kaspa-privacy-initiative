# Registered identity freshness registry

Status: **source-only, unqualified, `CONFIGURED=0`, launch forbidden**.

This component closes the in-memory/caller-JSON freshness gap for future
registered financial attempts. It does not perform owner intake, MPC, proving,
funding, broadcast, settlement, or recovery.

## Authority and event

The immutable journal header binds the exact public hashes for:

- trial registration;
- registered service;
- selected source closure;
- selected build closure; and
- the canonical sorted abort-tombstone set.

The known incomplete run
`a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab`
is a mandatory tombstone. Setup and open both refuse an authority that omits
it.

One append atomically consumes eight nonzero, mutually distinct public
identities: run, trial, attempt, cohort, direct accepted head, and three
individual owner contracts. Any identity already consumed in any field, any
abort tombstone in any field, or any omitted field refuses before append.
There is deliberately no `prior_identities` or completion-JSON input.

`ConsumedIdentity` cannot be constructed or copied by a caller. Its public
receipt exposes only authority, selection, checkpoint and aggregate consumed
set hashes. It exposes no individual owner body, key, witness, path, or private
input hash.

## Durability

`journal.bin` contains a fixed authority/storage header followed by fixed-size
hash-chained events. `latest.bin` contains a matching header and an append-only
sequence/checkpoint row for every event. The write order is:

1. append the complete journal event;
2. `fsync` the journal;
3. append the matching anchor row; and
4. `fsync` the anchor.

An interruption before both records agree makes restart refuse. An interruption
after both records are present leaves the identity consumed, even if the caller
did not receive a capability. Retrying the same identity then refuses.

Both directories must be absolute, normalized, non-symlink, owner-only `0700`
directories. Both files must be owner-only `0600`, regular, single-link files.
Open descriptors and names must retain the same device/inode. The durable
header mutually binds both directories and both files, so copy replacement is
detected across restart. Descriptors are `O_CLOEXEC`.

## Trusted-anchor boundary

The anchor is a separate monotonic trust domain, as in `epoch_journal`. The
implementation detects truncation, partial events, journal/anchor divergence,
one-sided rollback, replacement, hardlinks, symlinks and mode drift. It cannot
detect an actor that can overwrite **both existing inodes** with an older,
mutually consistent journal/anchor pair. No two replayable files can prove
their own monotonicity.

The retained coordinated-rollback control demonstrates this limitation. A
permission-separated append service, hardware monotonic counter, or equivalent
external monotonic anchor is required before configuration. Children must
never receive the registry paths or descriptors.

`docker_monotonic_anchor_service.py` and its parent-only C++ client implement a
bounded local Testnet research backend under this contract. The service runs as
UID 65532 in a network-disabled, read-only rootful-Docker container; state is a
named volume and the mutually authenticated Unix socket is omitted from party
containers. This prevents tested party-child rollback/access, but the rootful
Docker operator can still roll back the volume. It is therefore not production
monotonic security and does not permit `CONFIGURED=1`.

## Architecture-A integration requirement

A single outer supervisor must own the registry. It must:

1. collect role-bound proposals from all three MPC parties;
2. require exact agreement on all eight identities and the selected authority;
3. consume the registry exactly once;
4. return three role-bound, one-shot approvals without registry paths or file
   descriptors;
5. require each party to recheck the direct C++ `AcceptedFinancialHead` before
   durable `LOCK`; and
6. burn its approval immediately before `claim_owner_intake` creates a listener.

Trial03 predates this authority and must not be retrofitted. A future fresh,
unfunded trial must initialize the registry before any funding or private
intake, and the selected hermetic build must include the registry and supervisor
sources. Until that direct integration exists, `source_status()` keeps all
integration, configuration and launch flags false.

Only the public a864 run identity was retained in the operational abort record.
The earlier private owner bodies were intentionally not read or hashed, so no
claim is made that the registry can recognize those unknown bodies. A future
trial must generate fresh owner material and consume its public contract hashes
before intake.

## Controls

Run the standalone controls with:

```sh
python3 -m unittest -v \
  poc/local-private-payment/mpc-prover/financial/controls/test_registered_identity_registry.py
```

The controls cover restart, every omitted/reused field, cross-field reuse,
the mandatory abort, authority drift, concurrent consumption, every write
boundary, truncation, one-sided rollback, live and restarted replacement,
hardlinks, symlinks, modes, exec descriptor isolation, and the explicit
coordinated-rollback boundary. Passing controls are implementation evidence,
not cryptographic review, privacy proof, or launch readiness.
