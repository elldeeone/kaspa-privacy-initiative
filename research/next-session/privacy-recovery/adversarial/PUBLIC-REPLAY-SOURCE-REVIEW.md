# Auth528 public replay: independent source and artifact review

Scope: ADR-0052's new `poc/private-exit-recovery` package only. The reviewer
reads source, public fixtures and hashes, without running decoder tests,
native validation, proving, RPC or private-key/witness access. The earlier
closed private-exit review remains unchanged at SHA256
`3b257a2e0c95d929bf2ee605725342d45e36414f07408f659ec1a82012f14004`.

## Source and prospective inputs

ADR-0052's explicit separate descriptor/package, immutable legacy public
utilities, changed Auth528 semantics and incomplete supplied-context boundary
received design ACK. Source/fixture freeze SHA256 is
`fbbb30891179f79cb9375f3f42e7394aad58856a41e3a2b5eeca2ea8eb616af6`.
All44 pinned source/public-artifact members matched before execution and at
artifact closure. No old module/global is changed. Reused old parser/state/tree,
amount/context/framing and native-case conversion sources are hash-pinned.

The stateless new policy template SHA256 is
`731eb10da7a96a3f1f67b3c3fb0da6d45294820c8c610dc9d7d0d0fd1dd10556`.
It is parsed from the independently reviewed pinned native program, has exactly
ten canonical domain32 and one VK328 push, and reconstructs the whole24417-byte
new program after State112. The reviewer reassembled it against the actual new
mainline program. A caller's adjacent hash or D/VK substrings are not authority.

The installed evidence manifest is code-hash-pinned, never caller-selected.
It checks source identity and previously closed accepted native reports and
binds the entire native transaction, including proof/signature witnesses,
plus every supplied input context. V1 transaction ID alone is insufficient.
The reviewer checked all seven public rows map exactly to the earlier accepted
native cases. No private circuit fixture, seed, PK, signer or native executable
is required by this run. These finite trusted-client cached results are not a
new verifier for arbitrary unseen proofs.

Public transition checks run before evidence lookup. The adapter authenticates
current outpoint/state/reserve, P/R'/fee, full destination/output topology,
metadata, both sequential NF insertions, ciphertext binding and immutable
successors. Continuing CM appends and terminal all-zero/carry semantics differ
explicitly. It tracks every consumed input, including external funding, and
rejects duplicate/competing spends. Private payout records contain public P/SPK;
they do not fabricate hidden noteCM/position or payout-key inequality checks.
Those private properties rely on G16/native evidence.

Controls assert specific public error families with zero evidence lookups;
coherent changed destinations and same-v1-ID proof/context mutations reach the
installed evidence boundary. Missing middle links reject, unordered rows do not
choose authority, and a truncated terminal leaves nonzero/incomplete state.

## Artifact closure

Final result SHA256:
`b68676dc3446f78df2f320fe29e7ec0757ecf6bb2e92c04061650cc191f6d0f0`.
Raw40-control result SHA256:
`519a01376d7664d52973b141017fece22e402ac59eecbeb4e12bd4bcbe4e378a`.
All40 exact predictions match:37 semantic guards fire before any evidence
lookup; three coherent destination/proof-witness/context changes fail the
installed exact-case evidence boundary. All linked result/source/input hashes
matched. Replayed-state SHA256:
`1c03d3aecc75854e960383273633eb8c8c1e22f0ff93f81647b9ba5227347c73`.

The positive trace reconstructs CM8/NF9/R0, six pool operations plus one ordinary
funding ancestor, and payouts200000000/762000200/981042400 sompi. Seven earlier
Full results are reused; zero new native/proof executions. Unordered rows derive
the same head; truncating the last transition leaves1B/nonterminal/incomplete.

Active cgroup sample SHA256:
`11cb89622764a1d4e7e60c6cd447a0c65b49bc3dc1612063b11d0987094d17ff`
confirms2 CPU/2 GiB/swap0. Inner resource SHA256:
`cc42c9e67589a6b4007463398d4f816b8bf27c97d401061bf6bcb5abfbf973bc`
records0.33s and exit0. Cleanup SHA256:
`078a32e62dfcdd95f71b1dc5a1c48294285da3d3c3523abcc1266718c880805f`
records inactive/dead/PID0 and no captured PID/cgroup remaining. The reviewer
repeated no decoder/native/proof run.

## Remaining boundary

`complete:false`, `accepted_chain_backing:false`, no current-network observation,
no independent consensus/DA and no network-fetch/wallet support remain explicit.
SDK transaction-ID validation is also false. The old fetcher/wallet still reject
the new descriptor. Hidden ownership/conservation require real validated proofs;
correct delivery and recipient spendability remain separate obligations.
This closes finite offline public replay compatibility, not a complete new-program
network recovery or private-owner withdrawal lifecycle, privacy qualification
or a security audit.
