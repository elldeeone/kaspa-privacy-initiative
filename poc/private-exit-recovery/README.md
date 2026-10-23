# Public recovery compatibility for private native cashouts

This separate client implements the public replay rules in
[ADR0052](../../docs/adr/0052-separate-public-replay-for-private-cashouts.md).
It recognizes the entire new 24,417-byte native union, rather than inferring
authority from the State112 magic shared with the older program.

The new `kpx3-recovery-descriptor/v1` has the same nine identity fields as the
older descriptor, with its own schema and source-approved policy template.
The installed template permits exactly ten canonical domain operands, one
VK328 operand and the initial State112. A caller's matching policy self hash
does not approve arbitrary bytecode. The descriptor's founding identity/domain
and selected key remain user-authentication assumptions.

`public_adapter.replay(descriptor,bundle,native_validator=None)` currently accepts
only `kpx3-supplied-context/v1` with `context=OFFLINE_SUPPLIED_CONTEXT`. Input rows
contain complete native transactions and all supplied input contexts. Accepting
headers, confirmation claims and network-fetch schemas are rejected. Public
amounts use integer sompi. The adapter reconstructs both sequential NF updates,
continuing CM appends, exact reserve/payout topology and terminal no-append
state. Public private-payout records contain only actual P/SPK/outpoint; they do
not invent consumed-note commitments, positions or hidden-key comparisons.

The client explicitly imports hash-pinned old sparse-tree, amount, public-note,
frame and native-case serialization code. No existing module is patched or
monkeypatched. Genesis, admission and explicit revealing fallback retain their
public checks. Every supplied input, including external admission funding,
participates in duplicate-spend detection and known-parent output linking.

For this finite experiment, `ExistingNativeResults` authenticates installed-code
SHA-pinned evidence from the previously reviewed seven-operation native run.
It compares **entire transaction/witness and every supplied input context** via
the existing native-case serializer. Transaction IDs alone omit version1 proof
and signature witnesses and are insufficient. A descriptor/bundle cannot choose
a report, evidence manifest, executable or callback. This is reuse of exact
previous native results, not fresh cryptographic verification or acceptance of
arbitrary fetched proofs. The native source identity and closed mainline result
are pinned too. Public checks execute before evidence lookup, so malformed
semantic controls test the decoder rather than merely failing a cache hash.

With no trusted validator, the output explicitly labels crypto unchecked.
Even with selected offline evidence, output is always `complete:false`,
`accepted_chain_backing:false`, no current UTXO observation and no network or
wallet support. Old fetchers and wallets remain unchanged and reject this
descriptor schema. No seed, private circuit witness, proving key, prover,
funding, setup, transaction signing or broadcast is used.

`prepare.py` produces public fixtures and source-derived template/evidence pins
without replay or VM execution. `run_checks.py` executes the separately frozen
public decoder/control packet once. The positive path uses seven existing
bodies: one ordinary funding ancestor, founding, admission and four private
actions. No successful native VM/proof workload is repeated.

This adapts retained-data public reconstruction and client-selected instance
identity from the existing recovery design. The reviewed
[primary comparison](../../research/next-session/privacy-recovery/SOURCES.md)
reuses Orchard/RAILGUN-style public-event reconstruction, Monero/MWEB local
ownership boundaries and Aztec destination/accepted-state separation. No mature
protocol's cryptography, archive availability or consensus guarantees are
inherited. This package introduces no cryptographic primitive.
