# Registered trial-03 selection candidate

Status: **ADMITTED SOURCE SNAPSHOT; UNCONFIGURED; NO LAUNCH AUTHORITY**.

The exact public candidate is
`.local/registered-financial-selection-05`:

- trial: `46c16c64-2ba3-4d69-89e0-c00bd3a1277b`;
- trial selection: `77252d3ca1a4faffa3ee8e03706a93604e0909034cc274309c7ea2300c198401`;
- registration: `101b682fcd64f51ec4214ee5858f06f1adefa49f225be89b32a3318d71c8f92d`;
- trial authority: `520b0983849b7cd777c266a4d706994d804836fb1612610c5dd9ec16ab1fd672`;
- build authority: `0931de42aaa401f20725b9b48fd3f63580d00b7a96fadfcc84b8be5276e47f74`;
- configuration manifest: `6fa69b0fc3ac83b16b05e3f1f5e7cbf9a2797c82327c9adc65e8a84625a0099b`;
- snapshot receipt: `646cc10a4072c58bd079610e7c8a52bcbeb431a73bc24d80173c37665b797127`.

Admission reopens the real trial-03 journal and anchor pairs with the selected
initializer and requires sequence 0, checkpoint
`5bf83f9dc55264a7908337dafdf32c3f19c6ee74638b405b5d6d83c378818a5e`,
and `READY` for all three parties. It independently verifies the pinned CA and
the P0/P1/P2 certificate bodies, chains, and roles. It never reads a TLS
private-key body or owner input.

## Build authority

Builds 10 and 12 are independent clean `-Werror` builds of the same
unconfigured source:

- 29/29 compilation units and one link passed;
- 268 selected source files;
- 2,859 transitive compiler dependencies, including system and vendor headers;
- 29 object hashes and 76 link/runtime dependencies;
- compiler, `cc1plus`, assembler, linker, `collect2`, specs, search paths,
  sysroot result, Python build interpreter, and runtime inspector are pinned;
- both binaries are byte-identical at
  `110e46e8471b7885b34fe3259bf32135c026751c7cd54e74e34b303ec6db3eea`;
- both direct executions exit 78 with only
  `KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED` on stderr;
- object reuse through `--base-build` is forbidden.

The snapshot contains the selected source, toolchain/header/link closure, both
build receipts, both current binaries, and the prior independently reproduced
base qualifier bound by `registered_trial03_candidate.hpp`. Every file is a
single-link read-only copy.

## Exact future configuration paths

`REGISTERED-ACTUAL-HEAD-SELECTION.json` is the only current path/pin plan. A
reviewed root-owned installation must use its exact `/srv/kpi`, `/etc/kpi`, and
`/var/lib/kpi` targets for:

1. the model metadata, A/B/C rows, compressed aggregate PK, VK, and independent
   verifier;
2. the acquisition and exporter entry points, complete source/specification
   closures, interpreters, runtimes, namespace tool, and fresh work parents;
3. the registration, selected CA plus P0/P1/P2 certificates, three existing
   journals/anchors/private roots, native parameters, and immutable tail;
4. per-role private-candidate/public-result roots and the roster-pinned
   transport.

The activation header must define `KPI_REGISTERED_FINANCIAL_CONFIGURED=1` and
`KPI_REGISTERED_FINANCIAL_DRIVER_HEADER` only after all installed bytes are
reopened and rehashed. Runtime argv/environment must not replace any selection.

## Remaining launch blockers

- no concrete roster-pinned TLS `Player` build is selected;
- acquisition `SPEC.json` and the complete selected-node SDK closure are not
  selected;
- exporter `SPEC.json` and immutable signature matrix are not selected;
- model/PK/VK/verifier/native targets are not installed root-owned;
- the native outer image remains unqualified;
- durable attempt, cohort, and accepted-head replay authority is not yet owned
  by the registered journal/anchor registry;
- completion is not yet joined directly to the C++ `AcceptedFinancialHead`,
  financial proof, R0, and native receipts;
- Round1 and Round2 actual heads have not been acquired.

Source05 cannot be retagged or parameterized for either successor head. The
future path must use dynamic `RegisteredFinancialSelection::attempt_binding`
and `construct_registered` after a fresh direct accepted-head acquisition in
each round. Until the blockers above are closed, caller-supplied prior identity
lists and completion JSON are non-authority, `launch_authorized=false`, and
`KPI_REGISTERED_FINANCIAL_CONFIGURED=0` remains mandatory.
