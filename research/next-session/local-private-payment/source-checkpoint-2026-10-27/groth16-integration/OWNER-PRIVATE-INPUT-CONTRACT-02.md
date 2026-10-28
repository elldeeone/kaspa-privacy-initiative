# External owner inputs for a MASCOT Groth16 backend

2026-10-27. Source contract only; no client, server, compiler, setup, proof,
private witness, wallet, Original or financial job was executed for this plan.
The current 489-file publication candidate is unchanged.

**Use the established external-client masked-input protocol. Do not put a real
owner's witness in party0's `Input-P0` or call `get_input_from(0)` on it.** That
would give one prover the plaintext before MPC. The completed Fr scalar gate
used deliberately public numbers and does not establish an owner-input path.

## Concrete upstream route and data flow

At MP-SPDZ `113c4e47dd94bca9ecab029d2f0abe649bea5c52`:

| Side | Existing source/API | Exact operation to preserve |
| --- | --- | --- |
| Owner client | `ExternalIO/Client.hpp::send_private_inputs<T>` | Connects to all servers, receives value components of preprocessed triples, reconstructs `(a,b,c)`, checks `a*b=c`, and sends `m=x+a` to every server. |
| Server VM | `Compiler/types.py::sint.receive_from_client`, lines2751–2776 | In active mode obtains authenticated triples, uses `write_shares_to_socket`, reads masked clear `m`, and returns `m-[a]` as authenticated server shares. |
| Server low-level port | `Share<Fr>::constant(m, party, alpha_i) - a` | The port must preserve the same MAC arithmetic; `alpha_i` is the private per-party MAC-key share. This is not a cast into REP3 or a bare value-share array. |
| Transport | `ExternalClients::{start_listening,get_client_connection,get_socket}` plus `ssl_socket` | Established all-server client connection plumbing; C++ sockets set peer verification and expected peer-name verification. Keep TLS enabled and bind identities to the selected job. |

The protocol comes from Damgård et al., [Confidential Benchmarking based on
Multiparty Computation](https://eprint.iacr.org/2015/1006).
[Exact client code](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ExternalIO/Client.hpp),
[server operation](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/types.py#L2751-L2776).

Only the owner reconstructs the random mask. No individual server receives
plaintext `x`; it sees its own mask share and the masked `m`. This statement
requires the established protocol assumptions, authenticated channels to the
selected servers, fresh preprocessing, and at least one honest noncolluding
MASCOT server. It is not a measured privacy result of this project.

**Do not send MAC components to the client.** The upstream distinction matters:
`write_shares_to_socket` sends only value components; `write_to_socket` sends
shares **and MAC shares**. The server keeps the complete authenticated triple
and constructs the authenticated input locally. The intentional one-time mask
value-component delivery is part of this established input protocol; it is not
permission to strip MACs from witness/prover computation.
[Exact methods](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/types.py#L2830-L2860).

## Required strict profile, beyond copying the examples

1. **All three selected servers.** Owner clients are separate processes, not
   computing party0. Require the complete fixed server set, distinct expected
   server identities and complete agreement on the public job before any
   private-input byte. Never use the documented trusted-single-server client
   mode for note openings.
2. **Active input mode is mandatory.** Both upstream C++ and Python clients
   infer active versus one-mask mode from the first server's frame length and
   accept either. Our client must instead require exactly `3*n` field values
   from every server and verify every reconstructed triple; no one-mask
   fallback. The server path must remain active, with normal MASCOT correlation,
   sacrifice and MAC checks enabled. No compiler `--insecure`, `NO_CLIENT_TLS`
   or benchmark check-disabling options.
3. **Exact field and shape.** Require BN254 Fr
   `21888242871839275222246405745257275088548364400416034343698204186575808495617`,
   fixed canonical input count/order and exact frame exhaustion. Do not adopt
   a server-chosen modulus just because all servers echo it. ExternalIO's
   Montgomery field framing is not the Native128 point codec or canonical
   witness file format. Validate unsigned owner values before constructing a
   reducing field object. Enforce explicit byte/Fr/Q subranges where the actual
   circuit requires them; a signing scalar's Q bound remains distinct.
4. **Authenticate TLS, not just encryption.** The C++ path uses `verify_peer`
   and expected peer-name verification unless `NO_CLIENT_TLS` is compiled.
   Its selected build/profile must keep those checks. On the server side,
   `verify_peer` alone does not require a client certificate to be present.
   Require a present, valid, expected named client certificate before any job
   mask delivery, using `verify_fail_if_no_peer_cert` or an equivalent explicit
   post-handshake certificate-presence/identity check. Stock mutual client
   authentication is not qualified merely by observing `verify_peer`. Each owner retains its own TLS private key;
   servers retain theirs; distribute public certificates only. Bind expected
   identities/certificate pins to the job. The stock Python example constructs
   generic `PROTOCOL_TLSv1_2`, loads CA locations, but does not set
   `CERT_REQUIRED` or hostname checking. Loading CAs alone does not enable
   certificate verification. Do not use that example unchanged for real
   openings; use the C++ path or an explicitly authenticated Python wrapper.
5. **Bind the computation, not only the socket.** Before masks/private values,
   owners and every prover agree the exact domain/profile, circuit and matrix
   digest, public-input digest, proving/verifying-key identities, reduction and
   domain plan, fresh run nonce, client role/shape and intended fixed cohort.
   Bind these in authenticated application messages on every TLS channel and
   in the prover's peer agreement. A server identity is not remote attestation
   of a circuit; the model still needs at least one correctly selected honest
   server. Wrong-job/replayed/missing acknowledgments halt before ingestion.
6. **One-time masks and private diagnostics.** Consume fresh checked triples
   once. Never persist/reuse a mask across retries. Reject duplicate client/job
   role registrations in the wrapper. Keep owner values, reconstructed masks,
   signature material, server MAC state and raw diagnostics in their own
   private processes; release only fixed public completion/status. The C++
   example prints triple values on a failed check: those diagnostics must not
   enter coordinator/public logs.

[C++ TLS implementation](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Networking/ssl_sockets.h#L26-L80),
[Python example](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ExternalIO/client.py),
[Python certificate default](https://docs.python.org/3/library/ssl.html#ssl.CERT_NONE).
These are required integration checks and changes, not a claim that an attack
was run or that an upstream security audit was completed.

## Low-level port order

The proposed `receive_owner_inputs_active()` port has this fixed order:

1. Validate the public job, server cohort, external client certificate/role and
   expected shape; finish peer/job agreement.
2. Obtain `n` fresh **authenticated** triples from stock MASCOT preprocessing.
   Complete required preprocessing/protocol checks before exposing mask
   components; retain all MAC lanes privately.
3. On each owner's authenticated socket, send only the value component of each
   `(a,b,c)`, with fixed checked framing and the bound job/phase.
4. The strict external owner reconstructs/checks all triples and broadcasts
   canonical masked values `m=x+a` on all three TLS channels.
5. Receive exactly `n` values, bind/agree their canonical masked-frame digest
   across provers, then construct `AuthConstant(m, party, alpha_i)-[a]`.
   No clear witness is reconstructed on a server; no MAC lane is discarded.
6. Feed authenticated inputs directly into the global witness map and later
   checked Groth16 computation. Wrong/missing inputs, dependency loss or failed
   checks produce no accepted subset or proof. Every retry uses a fresh job,
   mask/preprocessing state and identity; timing alone is not a safety verdict.

The VM implements the established arithmetic recipe. A small direct C++ prover
must port that recipe and its complete authenticated state/transport contract;
`ExternalClients` alone is socket plumbing, not a ready-made low-level secure
input function. No such port has been implemented or tested here.

## Ownership mapping and owner consent remain separate open questions

Client IDs, endpoints, input count/order and global witness offsets may identify
which owner supplied a private register block. If the eventual public NF list
preserves those blocks' order, the coordinator can recover ownership even when
field values stayed secret during arithmetic. The existing private permutation
and canonicalization must continue through witness assembly/proof outputs;
no public owner-to-register/NF selector, private input hash or receipt index may
quietly recreate the mapping. The tiny functional fullproof gate intentionally
uses known fixed synthetic slots and cannot qualify this property.

The inspected NativeAuthSpend signer currently reconstructs its actual200-byte
statement from the complete4077-byte packet, including the complete3756-byte
effects body and prefix193. It does not sign an opaque caller-supplied effects
hash. Its current single-input/two-output fixture contains that sole NF; it
does not implement a multi-owner private approval/finalization protocol.
Sources: prototype `owner_signer.mjs`
`ff7828b3f2bb20e43b2e1cadba811c128b13c73548de273f911e334c0a742552`,
`public_packet.mjs`
`3988e54f6b914a7f7472540dd2f1d1e8b8471ce5cf802a764f3372a309ffb3f8`,
SPEC02 `6e8cc3539bf1d1472e26f4e42caf85434a264f352b7152c0de0f5d3e714d72f6`.

**Question, not an assumed gadget defect:** when generalized to multiple inputs,
which owner/prover learns the other NFs and complete effects before signing?
Publishing the full canonical boundary before collecting signatures can retain
the known pre-settlement abort/retry channel. Keeping NFs hidden until the final
proof instead requires a separately reviewed owner approval/reconstruction
protocol that preserves full exact effects and intended outputs. Do not weaken
the signature message, public validation or owner consent to obtain a privacy
claim. Resolve that change in an ADR before integration. Authority separation,
external-input confidentiality, mapping anonymity and abort/retry privacy retain
separate verdicts.


Source02 preserves source01 and makes its server-side client-certificate
presence requirement explicit. This follows the OpenSSL verification-mode
contract; no TLS connection or attack was executed.
