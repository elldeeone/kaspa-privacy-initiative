# Financial assignment qualification

`gate_main.cpp` is restricted to the fixed public, unfunded fixture. It opens
three previously initialized journals in a distinct **UNREGISTERED** epoch. It
has no journal initialization, reset, registration, settlement or funding path.
The production registered-service driver is not implemented here.

The actual path is:

1. Admit the stock compressed proving key, all matrix rows, selected trace,
   exact owner layout, native tail and independently derived prefix recipe.
2. Acquire the all-three durable LOCK before any owner listener exists. Each
   isolated owner reads only its own local auxiliary file and uses the
   authenticated TLS/V2 five-value DDNNT input-supply protocol from ADR-0086.
3. Construct the complete authenticated assignment, retain all 33,896 private
   trace assertions, and add the 276 context byte checks. The fixed fresh
   qualification validates exactly 13,127,204 residuals before PREPARED.
4. Create the whole aggregate proof, independently verify it, and complete
   all-three durable EGRESS before the release object exposes core/proof bytes.

`run_financial.py` uses one kernel-sealed public PK memfd. Standard Unix
`SCM_RIGHTS` passes references to that same inode into the three isolated
servers. Each server independently checks seals, canonical decoded hashes,
stock frames, every curve point, VK and matrix bindings. Bubblewrap 0.11.1
cannot bind an anonymous memfd with `--ro-bind-fd`; the failed public control is
retained. No plaintext PK or trace dump is needed.

The controller never opens or hashes owner input bodies, TLS private-key
bodies or raw MPC logs. It reads only selected public source/parameters and
typed public stages/results. Only the fixed known-unfunded owner paths are
accepted by this launcher. No result from this component qualifies payment
privacy, an accepted deposit, native settlement, or a production service.

## Exact public handoff

`qualify_public_release.py` consumes only a completed run's `RESULT.json`,
`released-core.bin`, `released-proof.bin`, `released-projection.bin` and pinned
public `native-tail.bin`. It
requires exact all-three typed agreement, rejoins the three artifacts byte for
byte, pins the fixed unfunded old head/state, component profile, aggregate and
Output keys, and actual admitted host binary. It derives both old and successor
reserve scripts from State112 plus the immutable tail, then directly runs `cross-check`.
It does not accept an imported host report or a caller success Boolean.
The host runs in a pinned bubblewrap namespace with no network, checkout, home,
wallet or owner roots; only the system runtime, exact host/projection and fresh
public output are mounted.

```text
python3 financial/qualify_public_release.py \
  --release-directory FRESH_FINANCIAL_RUN/public \
  --component-profile ../private-batch-public/component-profile.json \
  --outer-selection ../private-batch-public/outer-selection.json \
  --host SELECTED_PUBLIC_HOST \
  --output FRESH_PUBLIC_HANDOFF
```

The completion emits `projection.bin`, `journal.bin`, the direct host report,
`RESULT.json`, and `ARTIFACTS.json`. The last file has schema
`kpb-qualified-public-financial-artifacts/v1` and finite path/SHA/size records
for lifecycle assembly. It deliberately contains no owner partition or
owner-intake/lifecycle join.

## Baseline-only owner effects

The registered exporter also emits a pinned `OWNER-EFFECTS-RECIPE.bin`. For an
`ExplicitOwnerPublicEffectsBaseline` only, a post-EGRESS receiver first
re-authenticates all three owners and sends a fixed 459-byte pre-disclosure
challenge. Each owner proves possession of its long-lived logical wallet key;
that private logical identity is distinct from the fresh per-round TLS
certificate and never enters a public receipt. Only after all three proofs and
the exact roster capability verify may the bridge consume the live construction
and matching baseline plan, MAC-open the three 256-bit owner NF vectors plus the
6x6 authenticated output-permutation selectors, and map each owner's two
pre-shuffle rows to the six already-public EGRESS tuple hashes.
It rejects a non-Boolean/non-bijective selector, wrong set, wrong
source/layout/recipe, mixed plan/projection, replay or concurrent reuse. Raw
tuple bytes and all other witness columns stay closed. The result retains the
same one-shot plan and three move-only owner-private-effects authorities.

The same authenticated sockets remain open while the receiver consumes the
derived authorities. Each owner then verifies the same fixed 683-byte mapping
challenge from all three parties against its selected lineage and actual
NF/two 520-byte rows and sends a 40-byte acknowledgment. Every child submits
one fixed 1,524-byte private domain payload through its retained role-completion
endpoint. The parent authenticates the child PID/role/round, requires one
packet plus EOF and a zero exit, joins exactly three roles for each of two
rounds, and requires the same ordered private logical-owner roster in both
rounds while requiring distinct ordered financial-run, attempt, cohort,
capture-plan and projection identities. It then routes one one-shot private
truth input to each isolated owner scorer. On role 0 only, the baseline also
consumes a separate one-shot public-effects authority after all three final
ACKs and records exactly one observer leaf containing owner component, owner
contract identity, the already-public NF and its two already-public tuple
hashes. The fixed 693-byte leaf binds run/trial/attempt/cohort, capture plan,
projection and context. It contains no logical-owner identity, certificate,
private body, body hash or path. HiddenCandidate has no such authority or
event.

This is not an actual transparent-baseline run. The dispatcher still stops
before outbound-route/END because no genuine role-blind public handoff exists.
A typed post-EGRESS child
adapter exists, but no selected registered main, owner lifecycle or outer
score-worker launcher invokes the complete path; registered configuration and
launch remain false.
`HiddenCandidate` has no corresponding recipe, receiver or disclosure route.

This establishes the aggregate proof, all six genuine Output proofs, public
state transition and group balance for the exact released projection. It does
not establish accepted-head currentness, R0 execution/proof, a full native
candidate, settlement, or payment privacy. The current outer image remains
`selected:false`, so the handoff must stop there. Rechecking the same public
projection mints no replay or settlement authority.

The accepted-head and fixed-public-run sources are now canonically installed
after unchanged current bytes passed 8/8 public-process controls and a current
strict C++20 compile. They are source/compile eligibility only: configuration
remains off, and no selected registered main/runtime link or financial run
exists. The exact
configuration, driver sequence and controls still required are machine-readable
in `REGISTERED-DRIVER-REQUIREMENTS.json`; do not promote the fixed unregistered
history or source/compile eligibility around that blocker.

`controls/test_qualify_public_release.py` is an offline contract/mutation suite.
It uses a synthetic structural release and a hash-pinned stub host to exercise
the direct-execution and isolation contract; it is not aggregate/Output
cryptographic qualification. Only a genuine completed financial projection
checked by the pinned production host can produce that evidence.

Build with `build_financial.py --vendor-root PATH --output FRESH_DIR --jobs 2`.
The build freezes the recursive financial/history/packed/trace source closure,
the decoder and the selected standard SoftSpoken vendor artifacts. Actual
execution requires the separately coordinated RAM/CPU window.

ADR0081 selects only `KPB_OWNER_FR32V2` owner files: a 16-byte magic, owner
and count as u64 little endian, then canonical Fr32LE values. Every financial
owner file has exactly 84,333,120 bytes. The selected leaf is
`OWNER-PRIVATE-INPUT-V2.bin`; the producer receipt is version2. There is no
text fallback, compression or public private-content hash. Historical text
controls remain under `controls/historical/` and frozen evidence.

Only an isolated owner/client reads its file. The controller checks metadata.
The client requires the unchanged V2 contract and exactly 2,635,409 values,
checks Fr<P before conversion and checks the opened FD again after EOF.
Ancestor path checks assume the selected flat, read-only `/owner` mount;
they do not promise resistance to races in attacker-writable ancestors.

The owner contract itself is now `KPI_OWNER_DDNNT_CONTRACT_V2` with
`DDNNT_ACTIVE_5N`. For each private field the three servers deliver canonical
local value shares of checked `(s,r,w=s*r,v,u=v*r)`; the owner verifies both
products and returns the same canonical `d=x-s` to every server. The legacy
three-value and additive-share contract/widths are rejected. This removes the
old adapter's unqualified selective-failure surface, but it does not qualify
payment privacy or activate the registered service. The exact relation remains
unselected and configuration remains off.

The active C++ control takes two arguments: a public fixture directory and a
fresh malformed-fixture directory. Generate its fixtures with the relation's
`export_owner_fr32_public_fixture` example (same Rust writer used by
`owner_aux`), then run `owner_file_format_test PUBLIC_FIXTURES FRESH_CASES`.
Build this test with the same vendor include/defines and core link closure as
the financial client, replacing only its main translation unit. The controls
compare the retained V1 grammar to V2, check malformed files and parse all
three real-count public fixtures; they read no wallet/private record.
