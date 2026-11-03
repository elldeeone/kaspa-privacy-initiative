# RFC-0028: Hide input ownership in the native KAS payment lifecycle

**Date:** 2026-10-25 UTC. **Status:** Open experiment; first construction selected
by [ADR-0065](../adr/0065-sender-private-admission.md).
**Baseline:** `2e56d8a10fde5c998dde3bac3c7070c9d36f6827`.

## Research question

Can the existing native-backed financial relation retain repeated payments,
seed-only recovery and independent exits while removing direct public and
coordinator participant-to-input attribution?

The completed [ADR-0064 result](../../research/next-session/owner-private-lifecycle/RESULTS.md)
answers financial integration, not sender anonymity. Public funding markers,
persistent roster ordering and owner-labelled admission/authorization currently
expose information outside the confidential output construction. The next batch
must address that whole path before repeating a privacy score.

## Construction and interfaces

Use the existing financial domain/profile/keys/guest/native policy under a fresh
trial and pool, with fresh owner seeds and session identities. Financial Spend,
Output and Exit statements remain unchanged. The construction session binds the
new selected MPC program/codec source and fresh round aliases; complete native
effects still bind current outpoint, old/new states and reserve, session/roster,
every input/output, fee and successor policy. No old pool or backup is modified.

Use one actual `kpx9_admission.mpc` source selected by the existing session's
`program_source_sha256`; compile stage `admit|authorize`. The prepared closure
binds the actual source/codec/session/stage and stage effects: zero at admission,
the exact final effects digest at authorization. No new financial session schema
or multi-file bundle masquerading as a source hash is selected.

The selected interface is:

| Boundary | Private owner material | Permitted public/coordinator output |
| --- | --- | --- |
| Funding/round enrolment | Wallet seed, original participant label, local alias binding | Ordinary native funding data; fresh session aliases, never the old labelled marker |
| Prepare | Selected note/opening, NF/CV, two output tuples, beta | Session/phase completion with uniform shape; no owner-associated NF/CV or tuple selector |
| Construction MPC | NF/CV + two outputs + beta from each owner | Identical shuffled 3×96-byte NF/CV list, independently shuffled 6×520-byte outputs, aggregate beta |
| Owner authorization | Own note/opening, private own-input search, exact approved projection, Spend proof | Completion only; no owner-labelled authorization proof or NF/CV |
| Authorization MPC | 224-byte NF/CV/proof row from each owner | Identical shuffled 3×224-byte rows |
| Finalizer/native verification | None | Strict bijection to frozen inputs, reconstructed statements, all valid proofs, unchanged complete-effects/native acceptance |
| Recovery | One original seed backup | Shared public history/software/parameters; aggregate outcome only, no owner scan selectors or maps |

The 96-byte row is NF32 || CV64. The 224-byte authorization row appends the
existing 128-byte proof. Pack raw bytes into 31-byte limbs with zero padding:
four limbs for an input and eight for authorization. With two 17-limb outputs
and one beta, construction input is 39 fixed-width fields (3,003 bytes);
authorization input is eight fields (616 bytes). The codec rejects aliases,
nonzero padding, incomplete lists and inconsistent checked outputs. The public
coordinator cannot inspect owner inputs, private normalized streams or raw
engine logs. Host isolation is a research boundary, not host-admin protection.

Three independent secret permutations are required: inputs, outputs and
post-effects authorizations. Do not carry a shared row index, sort key, private
receipt hash, filename association or deterministic owner tag between them.
Every successful engine result is complete and MAC checked; a failed party or
collision yields no accepted subset. Owners authorize only the exact final
input/output order and native effects that they independently validated.

## Recovery without persistent public labels

Current code equates the backup participant with a public roster member. Replace
that dependency for this client protocol. Each round uses a domain-separated
alias from the existing pinned recipient HMAC derivation: alias domain
`SHA256(KPX9AL01 || financial_domain || public_round_id)`, role `ROUNDAL\0`,
index zero. This does not export a spend/nullifier/native key. The round ID is
selected before the session; honest scheduling uses fresh IDs. Repeating an ID
repeats the alias and is not claimed private against active coordination.
Owners retain their own local party/alias binding only during that round.
Invoice exchange checks that current local context.

The public session hash and each of its three sender slots already determine
candidate invoice indices for PAYMENT and CHANGE. A restored owner first uses
the unchanged domain-stable delivery key to decrypt complete public outputs;
the receipt contains its private derivation index. Classify accepted notes
against all six public candidate indices rather than a saved public participant
position. No invoice-index lookahead or saved alias is needed. Seed-only
recovery must rediscover received payments and
change over repeated rounds without original aliases, schedules or ownership
maps. Scanning must not disclose note indices/view keys to a remote server.

## Observer model and hard limits

Measure these views separately:

1. Public chain, sessions, canonical projections, public completion metadata.
2. Coordinator view including all actual ingress/egress, party endpoints,
   ordering, sizes, timestamps and aborts; do not replace it with a hand-redacted
   synthetic view.
3. Coordinator plus one colluding participant's actual private contribution.
4. Separate amount/timing/fee-remainder/ancestry/repeated-use/network channels.

The input-attribution claim requires at least two honest eligible owners. With
three owners, a one-colluder view has two honest candidates; two colluders leave
one and permit attribution by elimination. The host administrator, global
traffic analysis and independently administered storage are not silently
included in a cryptographic shuffle claim. The study must label incomplete or
selectively aborted samples and retain negative results.

**Known active limitation:** opening stable NF/CV before authorization permits
abort/retry intersection. For example, a coordinator that knows endpoint
membership can abort an A+B+C round and retry A+B+D, use colluder B's own NF and
intersect the remaining sets to identify A. Each round still has two honest
owners. Fresh aliases and a private attempt lock do not solve this after
seed-only restoration. The first candidate's possible positive result is
restricted to passive observation/honest scheduling; the active overlapping
cohort cell must retain its expected failure. Closing this channel needs a
separately reviewed construction or membership/retry-lifecycle change, not a
post-result narrower definition of the observer.

## Experiment order and stopping rules

1. **Source/design gate.** Refresh established designs and current Kaspa sources,
   compare candidate approaches, freeze exact interfaces and assumptions, and
   review them before cryptographic implementation. [Source review](../../research/next-session/sender-private-lifecycle/SOURCES.md).
2. **Unfunded component gate.** Execute genuine selected MPC and financial
   proofs. Require exact owner inputs/output inclusion and whole-effects
   authorization; no caller-supplied permutation or coordinator-owned plaintext
   inputs. Preserve deterministic malformed/replay/state rejection controls.
3. **Frozen privacy gate.** Before candidate transcripts, record hypotheses,
   actual observer surfaces, baseline controls, cohort/workload, number of fresh
   independent protocol worlds, scoring method, statistical thresholds and stop
   rules. Seal observer predictions before owner-local scoring; publish bounded
   aggregate scores without private ownership maps. A successful direct-label
   removal is not by itself a broader financial-privacy pass.
4. **Integrated rehearsal.** Use the selected candidate with actual native test
   backing, repeated payments and recovered received-note/change spending,
   original coordinator/prover loss, original-seed recovery and all independent
   native payouts confirmed. End at zero reserve and reconcile every sompi.

The first decisive failure is any remaining direct participant-to-NF/CV path in
the public or coordinator view, including authorization file slots. If exact
effects or recovery require retaining such a path, resolve that design issue
instead of hiding the metadata in publication. No production/anonymity claim
follows from a passing finite observer experiment.

## Required safety review

Cover integer/range boundaries; malformed and duplicate rows/nullifiers;
missing/replaced input or output; proof row swaps; wrong effects, fee,
destination, root, reserve outpoint or session; cross-pool/session replay;
incomplete/MAC-failed MPC; selective abort; corrupt/missing history/software;
stale state/reorg; and original-service loss. A rejected round leaves notes and
their independent-exit rights intact. Native final validation must check actual
consumed context and whole case bytes, not only txid or host success flags.

All I-1–I-16 invariants remain unchanged. Retain separate financial, privacy,
recovery, fees, availability, host/setup and consensus verdicts.

## Parallel fee and availability work

Previous all-in fees were 2.156935 KAS / frozen 21 KAS = 10.2711190476%, failing
2%. Independent exits cost 1.713222 KAS (about 79.4% of total); optimizing only
mixed batches cannot meet the target. Compare reviewed compute/verification
changes using actual same-workload native costs, with independent exits and the
useful-payment denominator fixed. Do not manufacture a fee pass through workload
changes or counting change/refunds as demand.

Separately administered, durable public history/parameter storage and actual
off-host seed recovery remain distinct availability questions. A second download
under the same administrator does not close them.
