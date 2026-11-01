# ADR-0086: complete DDNNT external-owner input supply

**Status:** Accepted for the isolated unfunded MASCOT research paths. Registered
financial execution and launch remain `CONFIGURED0`.

**Date:** 2026-10-29

**Related RFC:** [RFC-0030](../rfc/0030-private-batch-construction.md)

## Context

The prior external-owner adapter exported each server's local value shares of
one MASCOT multiplication triple `(a,b,c)`. The owner reconstructed it, checked
`a*b=c`, and returned `x+a`. That three-value shortcut is present in upstream
MP-SPDZ, but it is not the complete client-input protocol analyzed in the
primary DDNNT source. A malicious server can perturb the exported components
so the owner's continue/abort behavior tests a guess about the mask. Fresh
field-sized guesses are individually unlikely to pass, but the adapter had no
applicable simulation argument covering active P1, a colluding owner C1,
failure surfaces, and retries.

An owner-additive-share design using stock `ProtocolSet<Share<Fr>>::input`
would remove the triple export. It is still only a candidate: stock MASCOT
authenticates the share P1 chooses, not the share the owner intended. P1 can add
a chosen delta and observe the later relation-validity result. Accepting that
design requires a selected immutable relation that bindingly covers every
owner column. The registered EdDSA/financial matrix is currently only a
candidate, so that prerequisite is absent.

## Constraints

- The owner and servers may reveal no owner value or MAC share beyond the
  selected client-input messages.
- One malicious computing party, including P1 colluding with owner C1, is in
  scope. Abort is possible; silent value substitution is not acceptable.
- Every field and retry uses fresh authenticated preprocessing. Failed or
  partial attempts poison the context and cannot be resumed.
- Frames are exact, fixed-width, canonical BN254-Fr encodings. All servers must
  agree on the exact owner offset.
- The 2,635,409-field financial shape cannot retain all authenticated
  preprocessing vectors simultaneously. Its exact outbound frame is
  421,665,440 bytes and is sent only after every chunk passes.
- This changes security architecture and wire identity. Old clients must fail
  closed; compatibility by silently accepting the three-value form is unsafe.

## Options considered

### Keep the three-value `x+a` shortcut

Rejected. Reusing upstream code does not supply the missing active-security
argument. Its owner accept/abort branch remains a selective-failure surface.

### Owner additive sharing plus stock computing-party input

Deferred and not selectable. It is smaller, but requires the currently absent
immutable full-record relation selection and a chosen-delta argument. Unit
tests or the candidate EdDSA matrix cannot substitute for that authority.

### Complete DDNNT five-value input supply

Selected. It reuses established authenticated MASCOT operations while matching
the protocol analyzed in DDNNT Section 3.1, Figures 1 and 2.

## Decision

For each owner field, the servers use fresh authenticated values

```text
(s, r, w, v, u), where w = s*r and u = v*r.
```

The implementation obtains `(s,r,w)` from a fresh stock multiplication triple,
obtains independent `v` from stock authenticated randomness, and computes
`u=v*r` with stock batched multiplication. It finishes pending multiplication,
MAC, and checked-broadcast work before copying any local value share to the
outbound frame. It sends only local value shares, never MAC shares.

Generation uses a fixed public 4,096-field chunk schedule. Authenticated
`r,w,v,u` chunks are wiped after checking; authenticated `s` is retained to
derive the inputs. The server accumulates one exact per-owner frame in
per-field `s,r,w,v,u` order and sends it only after every chunk passes.

The owner receives one exact `5*N` frame from each authenticated server,
strictly decodes canonical Fr residues, reconstructs all five values, and
checks both equations for every field. Only then does it send the same exact
`N`-field `d=x-s` frame to all servers. The servers first agree on length and
then on the exact bytes before decoding and deriving authenticated
`[x]=[s]+d`. Any malformed, noncanonical, inconsistent, partial, replayed, or
failed attempt poisons the context; retry requires an entirely fresh attempt
and preprocessing context.

The contract and wire domain are versioned as `DDNNT_ACTIVE_5N` with only
`KPI_OWNER_DDNNT_CONTRACT_V1` and `KPI_OWNER_DDNNT_CONTRACT_V2` accepted.
Legacy three-value and experimental additive-share identifiers are rejected.

P1 capture records the exact outbound five-value owner frame, inbound offset,
the authenticated scalar/MAC lanes for `s,r,w,v,u` and the derived input, and
one typed 32-byte local MAC-key-share lane after setup and before protocols.
This supports the bounded observer study. It does not turn capture completeness
into a privacy result.

## Security analysis

DDNNT Lemma 1 gives a simulator for the five-value delivery view and bounds an
honest client's acceptance of a changed delivered value by at most `1/p`, under
the paper's assumptions. The following uniform mask makes `d=x-s` independent
of `x` at the value level. The two equations matter together: changing `r` and
adjusting `w` to fit a guessed `s` is still checked independently by `u=v*r`.

The local implementation additionally depends on correct/fresh MP-SPDZ MASCOT
preprocessing, its OT/composition assumptions, authenticated TLS identities,
canonical encoding, one-use attempt handling, secure randomness, and complete
MAC/broadcast checks. A malicious C1 may choose its own input and abort, but
does not gain an exception to the honest-owner checks. Dishonest-majority
liveness is not promised.

This decision does not change value conservation, nullifiers, withdrawals,
reserve release, native acceptance, or any admin authority. Failure halts the
attempt. The missing registered relation selection remains a correctness and
launch blocker even though the additive-share privacy prerequisite no longer
applies to this selected input protocol.

## Privacy analysis

Under the cited DDNNT and MASCOT assumptions, the recognized joint value view
of one statically corrupted computing party is conditionally simulatable. That
is not field-by-field independence or proof about this binary. Endpoint
identity, owner/cohort membership, frame sizes, ordering, time, abort phase,
retries, TLS behavior, host memory, swap/crash dumps, caches, packetization,
and the custom Groth16 group extension remain explicit or unqualified leakage.
P1+C1's own inputs and adaptive choices are corrupt auxiliary information.

No current test establishes sender anonymity, payment privacy, native KAS
privacy, Testnet readiness, production safety, or absence of host/network side
channels. The registered driver and EdDSA/financial relation remain
unselected; `CONFIGURED0` and launch false are mandatory.

## Evidence

- Damgaard, Damgaard, Nielsen, Nordholt, and Toft,
  [*Confidential Benchmarking based on Multiparty Computation*, Section 3.1,
  Figures 1--2 and Lemma 1](https://eprint.iacr.org/2015/1006).
- [P1 MASCOT view source review](../../research/mascot-p1-view-leakage-assumptions-2026-10-29.md),
  including the selective-failure counterexample and retained composition
  assumptions.
- `owner_input_ddnnt_test` checks both equations, paired guessed/non-guessed
  corruptions, exact masking, noncanonical/truncated frames, and rejection of
  old `3*N` and additive `N` shapes.
- The selected-path control checks operation order, complete authenticated P1
  capture, exact common-offset agreement, poison behavior, and removal of the
  old adapter identifiers.
- A fresh strict build and live three-party synthetic toy completed with all
  scalar and group MAC checks and independent Arkworks verification. Separate
  invalid-assignment and MAC-tamper executions refused before proof release.
  The positive result explicitly states `payment_privacy_qualified: false`.
  Retained exact-current evidence is
  `.local/mpc-prover-build-16/BUILD-RESULT.json` and run IDs
  `a78cc3873a8ff6173a4f42b24a589415634cc2dd88f8931701513ac775353e0f`,
  `d1464a090783cfe7c773452aff2b7d0774dd1c64fe962d7d87de24e13e4bd423`, and
  `a0a49164ca68e375a3183ede3a51971a78dcb65d5b04c162bf797c1234dcce0f`
  under `.local/mpc-prover-private-completion-runs-02/`.

Passing controls are implementation evidence, not a cryptographic proof or an
audit. The full 2,635,409-field registered financial run has not been executed
with this path.

## Objections / unresolved questions

- The exact pinned SimplestOT to SoftSpoken to MASCOT composition remains an
  explicit assumption in the source review.
- The former raw auxiliary Groth16 `B1` opening is removed. `C` now uses two
  secret-scalar/G1 products from fresh MASCOT field triples, opens only their
  masked Fr/G1 differences, and finally opens `A/B2/C`. This custom
  field-to-group composition and its capture/model accounting remain outside
  the privacy claim made by this ADR.
- Physical metadata and later host compromise remain outside the static
  corruption claim.
- The real-shape memory and duration must be measured before any configured
  trial; operational tuning may not weaken atomic send-after-check semantics.
- The registered relation, mapping, setup, source, and actual-head authority
  still need a live nonforgeable selection. Candidate hashes do not qualify it.

## Revisit if

- a primary-source proof qualifies a smaller stock-input construction for this
  exact selected relation and active P1+C1 model;
- upstream provides a complete maintained five-value implementation with an
  equal or stronger reviewed contract; or
- full-shape execution shows the exact-frame design cannot meet bounded
  resources without a separately analyzed streaming commitment protocol.
