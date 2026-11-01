# DDNNT 5N external-owner input: adversarial implementation review

**Status:** source and focused-control review, 2026-10-29. No blocking
protocol-correspondence defect remains in the inspected path after the two fixes
recorded below. This is not a proof, audit, privacy result, production approval,
or registered-launch evidence. The registered driver and capture remain
`CONFIGURED0`.

## Verdict

The selected implementation follows DDNNT Section 3.1, Figures 1--2 for each
field:

```text
servers deliver local value shares of (s,r,w,v,u)
w = s*r
u = v*r
owner checks both equations
owner sends one common d = x-s
servers derive [x] = [s] + d
```

The component order is exact and field-major; each field consumes its own fresh
authenticated triple `(s,r,w)`, fresh authenticated `v`, and multiplication
`u=v*r`. The owner receives value-share lanes only, never MAC lanes. Both
equations are checked before `d` is created. The three servers agree on the
exact `d` bytes before canonical decoding and derivation. Legacy three-value
and experimental additive contracts fail closed.

This removes the old concrete selective-failure branch in which a corrupt
server changed `(a,b,c)` and learned whether the owner's single check `a*b=c`
accepted. It does not remove abort, endpoint, size, timing, ordering, retry, or
host leakage. DDNNT's theorem applies only with its stated corruption/channel
assumptions and the additional MASCOT/implementation assumptions in the
[P1-view source review](mascot-p1-view-leakage-assumptions-2026-10-29.md).

## Protocol-to-source correspondence

| Requirement | Inspected implementation | Assessment |
|---|---|---|
| Exact tuple and order | `DDNNT_S/R/W/V/U` are indices `0..4`; packing is field-major `s,r,w,v,u` | Matches Figure 1 |
| Fresh tuple per field | Every field calls stock `get_three(DATA_TRIPLE, s,r,w)` and `random_auth()`; no `r` or `v` is shared between fields | Matches, conditional on fresh stock preprocessing/RNG |
| Authenticated `u=v*r` | Each public 4,096-field chunk calls stock `multiply_batch(v,r)` | Matches |
| Complete checks before export | `check_field_pending()` precedes typed capture, packing, and owner send | Correct sequencing |
| Value shares only | Outbound frame packs `get_share()` for all five components and never `get_mac()` | Matches DDNNT delivery; local MAC lanes remain in P1's corrupt-server view |
| Exact framing | Each server sends exactly `5*N*Fr::size()` bytes; owner returns exactly `N*Fr::size()` bytes | Correct, overflow-guarded |
| Canonical decode | Decoder rejects wrong length, trailing data, and a native Montgomery residue greater than or equal to the Fr modulus | Fail closed |
| Owner equations | Owner reconstructs all five values and checks `w=s*r` and `u=v*r` for every field | Matches Figure 1 |
| Common difference | One `d=x-s` frame is sent to all three authenticated servers; servers agree first on length validity and then exact bytes | Matches Figure 2 plus fail-closed agreement |
| Authenticated result | Each server derives `[s] + public_constant(d)` and preserves the authenticated result | Matches Figure 2 |
| Failure and retry | Escaping owner-input/cohort exceptions poison the MASCOT context; roles are one-shot in the server object | Safe halt; fresh-attempt enforcement still needs end-to-end control evidence |
| Legacy refusal | Only `KPI_OWNER_DDNNT_CONTRACT_V1/V2` and `DDNNT_ACTIVE_5N` remain; old `3N` and additive widths/identities are refused | Correct domain separation |

Relevant local sources are
[`owner_input_ddnnt.hpp`](../poc/local-private-payment/mpc-prover/owner_input_ddnnt.hpp),
[`owner_input_ddnnt.cpp`](../poc/local-private-payment/mpc-prover/owner_input_ddnnt.cpp),
and
[`owner_inputs_active.cpp`](../poc/local-private-payment/mpc-prover/owner_inputs_active.cpp).
The architecture decision is
[ADR-0086](../docs/adr/0086-complete-ddnnt-external-owner-input.md).

## Findings resolved during review

1. **Typed P1 capture initially omitted authenticated `s/r/w` MAC lanes.** The
   outbound owner frame correctly contained only local value shares, but a
   corrupt P1 also holds the associated local authenticated shares and MAC
   shares. The preparation path now captures `s`, `r`, and `w` after the stock
   checks and before packing/wiping. `random_auth()` and `multiply_batch()`
   already capture `v` and `u` through their typed APIs. This records the typed
   authenticated lane; it does not capture internal OT/PRNG coins or arbitrary
   host state.
2. **Owner masks and `d` initially lacked exception-safe cleansing.** RAII
   guards now cleanse the reconstructed masks and offset frame if creation or
   any of the three sends throws. This reduces retention; it is not a proof
   against compiler behavior, swap, crash dumps, or later host compromise.
3. **The paired selective-failure control was incomplete.** Focused controls
   now alter `r` while adjusting `w` to a guessed `s`: a correct guess passes
   the first equation but fails independent `u=v*r`; a wrong guess fails
   `w=s*r`. This directly exercises why both equations are necessary.

## Evidence checked

- The C++ arithmetic/frame control covers both equations, exact masking,
  truncated/noncanonical encodings, overflow, and rejection of `3N` and `N`
  legacy widths.
- The selected-path control checks stock-operation order, typed `s/r/w`
  capture, owner-frame-before-send capture, exact common-offset agreement,
  poisoned escaping failures, accepted contract IDs, and owner/client buffer
  guards.
- Both focused Python control modules passed (6 tests on the final reviewed
  source). An independent build of the C++ helper under AddressSanitizer and
  UndefinedBehaviorSanitizer passed.
- Two fresh three-party toy executions completed all scalar/group MAC checks
  and independent Arkworks proof verification. They are positive synthetic
  implementation evidence only. Both results explicitly set
  `payment_privacy_qualified: false`.

Passing these controls does not prove DDNNT, MASCOT, the exact OT composition,
or privacy of the executable. The full 2,635,409-field registered financial
shape has not run through this path.

## Required adversarial controls before admission

These controls are still missing from the reviewed focused suite. They should
exercise the real authenticated three-party path, not only the pure owner
reconstruction helper.

1. **Malicious server delivery:** for each of P0/P1/P2 and each `s,r,w,v,u`
   component, corrupt one field share, truncate/extend the `5N` frame, reorder
   components, and substitute an old frame. Require owner refusal, no `d`,
   poisoned server state, and a fresh context for retry.
2. **Paired network selective failure:** make a malicious P1 change `r` and
   adjust `w` to (a) the true `s` and (b) a wrong guess. At the actual owner
   socket boundary, require indistinguishable refusal classes: the former is
   caught by `u=v*r`, the latter by `w=s*r`; neither may emit a partial offset.
3. **Malicious owner offset:** have C1 send different exact-width offsets to
   P0/P1/P2, a noncanonical residue, a truncation, trailing bytes, a replay, and
   an early close. Require public agreement failure or strict decode failure,
   no derived value accepted, and complete poisoning.
4. **Authenticated-mask substitution:** after generation, alter one server's
   internal `[s]` value or MAC lane before derivation. Require the stock scalar
   MAC/check path to reject; do not rely on owner equations to detect an
   internal authenticated-state change that was not exported.
5. **Fresh retry:** after every failure point, prove the old owner/server
   object, attempt identity, masks, tuples, and partial context cannot resume.
   A fresh attempt must produce different delivered preprocessing and may
   succeed. No equality of field values should be asserted because collision
   is possible; compare attempt/authority identity and retained frame digests
   as lifecycle evidence.
6. **Capture completeness:** for each owner require exactly one outgoing
   preprocessing lane and one incoming offset lane, exact `5:1` byte ratio,
   all three owner bits, typed authenticated `s/r/w/v/u` share/MAC coverage,
   and no complete footer after any partial/failed attempt. Keep internal
   OT/PRNG coins and uninstrumented host state explicitly outside this claim.

## Corruption, abort, and retry interpretation

DDNNT allows up to `n-1` malicious servers and proves the five-value delivery
view simulatable without the delivered value; an honest client accepts a
changed value with probability at most `1/p` under the paper's assumptions.
It does not guarantee liveness. A corrupt server can abort, delay, close a
connection, or make the owner refuse.

P1 colluding with C1 remains one corrupt computing party plus corrupt external
auxiliary input. C1 may choose its own record and abort. The claim for honest
owners requires P0 and P2 to remain honest, channels to be private and
authenticated, and each failed or partial attempt to destroy its masks and
preprocessing. Static corruption does not cover a later compromise of an
honest server that retained state.

Fresh retry is mandatory. Reusing `s`, `r`, `v`, a MASCOT context, input
tuple/triple, owner contract, or attempt identity after any failure would fall
outside the inspected theorem mapping and could link attempts or create an
adaptive oracle. Poisoning is the local fail-stop mechanism; the end-to-end
authority/lifecycle controls above must demonstrate that production cannot
silently construct a retry around poisoned state.

## Leakage classification

The following are safely distinguishable in a frozen leakage ledger:

- the **joint** recognized DDNNT/MASCOT cryptographic value view may be marked
  `CONDITIONAL-DDNNT`, never independently harmless field by field;
- C1's own values, choices, and frames are corrupt auxiliary information;
- intended openings and the high-level success/abort outcome are explicit
  leakage;
- owner identity/cohort, frame sizes, order, peer/fork topology, timestamps,
  duration, exception/failure phase, partial progress, and retry count remain
  `EMPIRICAL-METADATA`;
- TLS records, packetization, scheduling, cache/page behavior, swap/crash
  dumps, internal OT/PRNG coins not explicitly instrumented, and later host
  compromise remain out of scope or unqualified;
- custom authenticated G1/G2 arithmetic remains outside the DDNNT/MASCOT
  finite-field theorem. Raw auxiliary `B1` is now absent; the exact two masked
  Fr/G1 pairs and final `A/B2/C` follow the separately conditional
  [ADR-0087](../docs/adr/0087-no-raw-b1-mixed-beaver-groth16-completion.md)
  scalar/group analysis.

The exact `5N` and `N` frame sizes are deterministic functions of public input
counts, but their occurrence, timing, partial length on failure, owner ordering,
and retries are not thereby theorem-covered. A complete capture is an observer
artifact, not privacy evidence.

## Primary source

Damgaard, Damgaard, Nielsen, Nordholt, and Toft,
[*Confidential Benchmarking based on Multiparty Computation*, Section 3.1,
Figures 1--2 and Lemma 1](https://eprint.iacr.org/2015/1006).
