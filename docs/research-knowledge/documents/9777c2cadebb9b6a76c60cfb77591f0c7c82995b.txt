# ADR-0062: Exercise an existing checked private field-sum API

**Status:** Accepted for a public synthetic component experiment only.
**Date:** 2026-10-24 UTC.
**Origin:** [RFC-0026](../rfc/0026-owner-private-multiparty-construction.md).

The [actual experiment](../../research/next-session/private-construction/full-tuple/sum-api/RESULTS.md)
completed four exact-field sums, wrong-prime rejection, two participant-loss
runs and a real commitment-derived binding consumer. The sealed source/results
remain unchanged. The [next decision question](../../research/next-session/private-construction/full-tuple/NEXT-CONSTRUCTION.md)
requires a split financial relation and exact-body authorization; no such
relation, setup or executable is selected by this component result.

## Problem and evidence

ADR0061 showed on the actual curve that publishing an owner's blinding
contribution can identify its output partition. The construction needs one
global sum without those individual contributions. The [source decision](../../research/next-session/private-construction/full-tuple/sum-review/DECISION.md)
and [frozen proposal](../../research/next-session/private-construction/full-tuple/sum-review/PROPOSAL-FREEZE-01.json)
identify an existing exact-prime API. Anonymous full tuples, financial
authorization and safe retry composition remain separate open obligations.

## Decision

Use MP-SPDZ v0.4.4, commit `113c4e47dd94bca9ecab029d2f0abe649bea5c52`,
with stock live MASCOT. Select the official 78,428,724-byte distribution,
SHA256 `73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760`,
and its Linux-adx MASCOT binary,
SHA256 `47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e`.
Authenticate an explicit compiler/runtime inventory before execution. The
official binary, compatible host and existing library remain trust assumptions.
No new masking, cryptographic engine, signature or KAS relation is selected.

The field is Jubjub Fr, prime
`6554484396890773809930967563523245729705921265872317281365359162392183254199`.
Three separate processes use stock secret input, addition and checked opening
(`reveal(check=True)`). Each sees only its own input/TLS key and public
certificates/program/software. They share an isolated loopback namespace,
with no host network, home, credentials, wallet backups, financial PK or KAS
interface. Session/TLS material is fresh per case; no party sees a common
plaintext-input directory. The fixture inputs are deliberately public.

| Fixed party inputs | Expected result modulo q |
| --- | --- |
| q-1, q-2, 6 | 3 |
| 0, 0, 0 | 0 |
| q-1, 1, 0 | 0 |
| 5, 11, 17 | 33 |

The boundary independently rejects noncanonical 32-byte values at or above q;
that is distinct from the engine's field reduction. Refuse a wrong runtime
prime and join actual bytecode/schedule hashes and prime to every result.
Label launcher rejection separately from rejection actually exercised inside
the engine. Feed the first actual sum into an additive real-curve consumer:
public synthetic commitments have difference 3*R, and the existing
commitment-derived RedJubjub Binding verifier must accept correct Delta and
reject changed Delta, body digest and fee. The old mock-Groth16 limitation
remains; this is no valid Sapling or KAS transaction.

Two fresh failure identities lose a party before input and after input but
before completion. Retain INCOMPLETE/abort; never accept a surviving subset
sum or issue financial authorization. Process death does not test malicious
wire shares, adaptive corruption, transcript privacy or retry unlinkability.

## Execution gates and consequences

Keep new source separate in `poc/private-sum-api-harness` and evidence additive
under `research/next-session/private-construction/full-tuple/sum-api`.
Preserve the closed ADR0061 packet and full-tuple design/review. Root reviews
the exact launcher, arithmetic program, real-curve consumer and inventory
before the first compiler/engine run. Public namespace/tool calibrations may
precede it, using no downloaded executable.

Use at most four CPU cores/four GiB, no GPU. The genuine four-wallet financial
rehearsal has priority; root schedules execution. Record owned resources and
cleanup. Retain operational failures and fix them without weakening MAC or
arithmetic checks or changing fixtures. Stop on unsupported exact-prime use,
unchecked opening, unexpected individual-input disclosure, hidden central
input collection or a need to change the engine. No global installation or
source-build fallback is selected.

This can retire an executable-API uncertainty, not prove privacy from public
fixtures. All-but-one collusion learns the remaining input from the sum;
nontrivial ambiguity requires at least two eligible honest participants.
Malicious input validity, tuple anonymity, exact context/roster agreement,
authorization/disclosure ordering, fairness and financial composition remain
open. No sum authorizes reserve KAS or replaces spend/range/conservation
proofs. Native backing, nullifiers, one-owner exits, accepted-state/reorg
checks and recovery availability remain unchanged. Existing privacy and fee
failures stand; no new privileged operator or mainnet implication is created.

## Operational isolation addendum

Installed-tool calibration found that ordinary bubblewrap already supplies
working isolated loopback TCP; a redundant interface change was unnecessary.
The host then refused a second nested user namespace. Those failures are
retained without changing the host policy or the cryptographic experiment.

Use the existing local Docker image
`sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`
for three separate read-only party containers sharing one owned `network=none`
anchor namespace. No pull, privileged mode, added capabilities, host ports,
host networking or daemon socket in a party is allowed. Run as the current
numeric UID/GID, drop all capabilities and use no-new-privileges. Each party
sees only its own input/TLS private key, public certificates, exact compiled
program and selected public runtime. Compiler/curve phases retain the single
bubblewrap namespace. The trusted controller alone uses the existing daemon;
the local image, daemon and host are additional experiment premises.

The configured total is at most 3.8 CPU cores and 3,616 MiB including controller
and anchor, within the original allocation. Verify actual filesystem/TCP
isolation with installed tools before an engine run. Retain owned-container
resources and authoritative removal/absence checks; a daemon error is UNKNOWN.
After declared party loss, observe survivors before cancellation; a sum is a
failure, natural exits are recorded, and a bounded controller cancellation is
only operational INCOMPLETE. No failed experiment is relabeled as a privacy
result or used to weaken the stock arithmetic/MAC checks.

The first real compiler invocation exposed an absent optional `gmpy2` import
and its upstream unassigned-error-variable path. Use only the task-local
official gmpy2 2.3.2 CPython314 wheel, whole SHA256
`debbece10ebf1ed74a92cf8aedbe557f6bc6365b21ee6a346944f28a24bb4d19`,
with all 17 regular members authenticated and mounted read-only for the
compiler's PYTHONPATH. No global installation or upstream patch is selected.
The stock compiler's `-F` option means usable integer workspace, which must
be at most q.bit_length()-2: select 250 while retaining **exactly the same
prime q**, full canonical field inputs including q-1, stock checked field
addition/opening and fixed expected results. The earlier proposed252 caller
option was an API misconfiguration, not a different field or qualification
threshold. Retain that source correction separately from executed failures.
