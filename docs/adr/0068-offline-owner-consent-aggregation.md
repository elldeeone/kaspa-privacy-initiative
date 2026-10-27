# ADR-0068: Offline owner-consent aggregation

Date: 2026-10-26

Status: Accepted for the bounded offline research experiment and its evidence
gate. This selects no native protocol, migration, financial authority or
privacy-qualified design.

## Context

The native [ADR-0066](0066-local-native-kas-payment-prototype.md) prototype
publicly groups one nullifier with two outputs. Removing that grouping and
hiding the correspondence from a constructor are separate problems. Ordinary
batching can leave the constructor with every owner's input/output map.

The [source review](../../research/next-session/local-private-payment/privacy-next/COLLABORATIVE-INTENT-PROVING-SOURCE-01.md)
identifies the established RAILGUN/Circomlib pattern of an owner-local signing
secret and separate proving/nullifier material. Today's native `owner_secret`
is a consumption secret, not a shareable proving key. Changing that native
predicate would require new note/KDF/profile/Spend/Exit and recovery decisions.
The experiment instead uses two synthetic owners and an independent toy relation.

## Decision

Accept the following as an **offline authorization/correspondence evidence
gate**, preserving I-1–I-16 and every current financial rule:

1. Exercise the existing, pinned EdDSA/Poseidon authorization gadget with the
   signing secret retained in its owner process. Bind the verification key and
   separate nullifying key into the synthetic input note, and bind exact
   context, fee, anchor, nonce and complete approved output tuples into consent.
   Stop both owners before checking the exported records. Never share or
   reinterpret the current native `owner_secret`.
2. Reuse that predicate twice in one aggregate. Constrain Boolean bijections
   between two internal owner records and independently ordered public arrays
   of two NFs and four **whole 520-byte tuples**. Require within-batch NF/CM
   distinctness, exact per-owner uint64 conservation and a 65-bit aggregate fee
   sum. Keep per-owner tuple digests, messages, signatures and correspondence
   outside the public interface. The debug relation has 2,091 public inputs
   and zero public outputs; this is not a native proof ABI or fee design.
3. Require actual complete witnesses and actual ordinary-R1CS checks for the
   selected negative controls. Parser/generator rejection alone cannot count
   as a passing constraint check. The official assertion-disabled C++ witness
   generator must preserve the ordinary R1CS byte for byte; it changes witness
   generation, never the acceptance relation or checker.
4. Preserve failed attempts and their classifications. A corrected harness
   uses a separately selected run identity with unchanged fixtures and expected
   outcomes. No rekey, replacement signatures or weakened check may manufacture
   a successful result.

## Actual bounded evidence

The same public handoff was reused without regenerating owners, signing keys
or signatures:
`284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218`.

| Experiment | Actual result |
| --- | --- |
| [Authorization predicate](../../research/next-session/local-private-payment/privacy-next/signature-authority-predicate-01/OUTCOME-02.md) | 49 actual R1CS checks: 5 accepts, 44 rejects, zero generation-only results. |
| [Two-owner aggregate](../../research/next-session/local-private-payment/privacy-next/two-owner-aggregate-01/OUTCOME-02.md) | 29 actual R1CS checks: 7 accepts, 22 rejects, zero generation-only results; all 2,091 public witness fields matched each selected input. |

Result identities are respectively
`55446254fa17e454cd34406cd5e035e251486193eabfe8fde9afeff14dfd6eb9`
and `49eaeb223eb6ed128af582e4bacd49a13f198ef439ddb3b6d0cf6e47b6d90d7c`.
The aggregate's ordinary and C++ R1CS identity is
`aa806976b76b1417613d56010f41710ba735203e18cad7c04c0a15e1503131d6`.
Its public-symbol audit found no owner-input or child-output aliases into
public wires. Several rejection checks overlap; they do not establish isolated
coverage of every predicate or cryptographic correctness.

The [first predicate attempt](../../research/next-session/local-private-payment/privacy-next/signature-authority-predicate-01/OUTCOME-01.md)
remains a preserved generator-evidence failure. The
[first aggregate attempt](../../research/next-session/local-private-payment/privacy-next/two-owner-aggregate-01/OUTCOME-01.md)
stopped before any witness or R1CS check because its symbol file exceeded
Node's single-string limit. Its STOP identity remains
`77ce5f28a44e4db21e98e70d790e6f97c4715978b1ed52661bc335eef150a01b`.
The separately selected line parser passed 23 small controls before exact
artifact reuse in run02. Neither failure was reclassified as a passing run.
The outcome documents retain source, selection and execution identities;
large build/witness artifacts remain in volatile tmpfs.

## Limits and next obligations

The fixture, owner-coded tuple bytes and plaintext constructor reveal the full
map. Internal permutation wires demonstrate correspondence mechanics, **not**
anonymity, coordinator-map hiding, signature unforgeability or malicious-MPC
security. Current native 1NF→2CM grouping, note/KDF/profile, Spend/Exit rules and
financial runtime are unchanged. No setup, proving key, Groth16 proof, native
transaction/state or actual Original recovery was tested by this experiment.

P07 deliberately accepted identical same-state replay. There is no historical
spent-state database, accepted-head/reorg policy or cancellation rule. There is
no CVin, CV algebra or Delta. CV64/CF/CFH/output-proof bytes are signed, but their
cryptographic validity, encryption, recipient spendability and recoverable
change remain unimplemented. Toy integer conservation is not native backing
or fee evidence.

Before any successor protocol implementation, resolve and record separately:

1. New note/key/domain/profile semantics and authorization on **every** Spend
   and independent Exit route, with original-seed receiving/change recovery.
2. Complete output validity and authenticated historical/current-state,
   spentness, replay, reorg, actual native-effects and fee binding.
3. A reviewed private-prover construction covering malicious input admission,
   complete extended-witness validity before revealing outputs, identical
   authenticated handoff, proving randomness and every reactive opening.
4. Active known-cohort abort/retry leakage, honest departures, durable global
   disclosure history and public-data availability. Private-payment liveness
   restrictions must not become operator control over independent exits.

Use a new RFC/ADR and synchronize architecture/threat-model documentation for
such a selection. This decision supplies no migration or new reserve-release
authority. The active-retry failures and frozen 21-KAS 2% fee failure remain;
these offline checks do not qualify privacy, recovery, cost, production safety
or mainnet deployment. No new token, privileged withdrawal or real funds are
introduced.
