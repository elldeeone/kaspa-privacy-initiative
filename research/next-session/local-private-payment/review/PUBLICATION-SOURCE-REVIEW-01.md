# Publication checker review

2026-10-25 UTC. Public-source and known-public-fixture review only. No protected
original backup was mounted, read, copied, hashed or scanned by this reviewer.

Source/control review: GO for the exact reviewed literal/derived checkers and
single-leaf launcher. Actual-original checker release: PENDING the exact frozen
artifact release SHA and mount-inventory correspondence check.

## Literal checker

The exact diff between old public source
`64527cadcd85df584fd3c36b945c2c263978cdd6d055376631027d616c8e6711`
and new source
`0d3d7cbed85da8288040407df8c6038fe58c14782d9af8f1ad8dcc748b1f1c52`
changes documentation, domain, the strict three-field backup schema and result
schema. Manifest authentication, full public-candidate authentication before the
single private read, raw/lower/upper-hex search and aggregate-only output are
unchanged.

This reviewer independently executed all seven known-public controls in closed
namespaces; all passed. See `LITERAL-PUBLIC-CONTROLS-INDEPENDENT-01.json`.
Literal-source review is GO. This is not derived-secret coverage and does not
authorize a private read without the selected single-leaf launcher.

## Derived checker findings

The reviewed intermediate source authenticates all public candidates and public
wallet history before one strict backup read. It rejects private-leaf aliases
among public selectors and candidates, reconstructs received/spent receipts using
the existing wallet and emits only aggregate counts/status.

Two coverage issues were returned to the author before release:

1. Native payout key indices are reconstructed from public exit head/NF history,
   rather than received-note indices. They must be included when claiming
   recoverable seed-derived native authority coverage. The wallet's new pure
   `payout_index` extraction was reviewed as behavior-preserving. Final checker
   integration and its public payout-key hit control passed.
2. Scan decoded manifest paths as well as raw manifest bytes, matching the
   literal checker. JSON escapes must not hide a disclosed derived byte string
   in a logical public filename. Final fix/control passed.

Final derived source
`e4c466cdbcb849d2249832f4c42efab97ea7d43039a55095948888710b67a489`
reuses historical payout reconciliation and the shared wallet helper. This
reviewer independently ran all thirteen known-public controls plus seven
namespace-absence checks; all passed. See
`DERIVED-PUBLIC-CONTROLS-INDEPENDENT-01.json`. No protected original was selected.

Launcher
`141076a5168db7bb6f4ac0485564b212f34d1b243fe5321b53c30c166e0f2f31`
authenticates all public candidate/source bytes before mounting one exact
metadata-selected original leaf per checker, copies public read-only snapshots,
uses closed namespaces without private parent/sibling/home/root mounts, discards
child stdout/stderr and exports only strict aggregate PASS results. Its default
is preflight. The metadata-only producer handle has six entries under the
approved new-original prefix; their content was not read or hashed by reviewer.

Unpublished invoice indices, random proving blindings and secrets not recoverable
from the seed plus selected public history remain outside this finite check.

## Public proving parameters

The exact selected fresh public PKs are eligible for source/provenance-based
noninterference treatment, rather than redundant owner-secret scanning:

- Spend: 601,785,008 bytes, `45ae6cd5110b09466c19de8c1f0cf89ec93f6c0d853f232773801e19bd0d62bd`.
- Output: 85,578,096 bytes, `887573cf53559e969007857cd50284db9948204390389fc6e85dd75644b1241d`.
- Exit: 591,206,448 bytes, `fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1`.

Reviewed `keys::setup` uses fixed public role fixtures/domain and OS RNG; it
reads no owner/wallet input. Root attests setup preceded actual original-wallet
creation. The public whole-byte verification record matches all three selected
pins and lengths. This supports absence of a data dependency on later originals;
it is not a claim that these PKs were literal/derived canary-scanned or that
arbitrary secrets are absent. It covers no modified, external or later-generated
parameter artifact. Setup trust and cryptographic correctness remain separate.
