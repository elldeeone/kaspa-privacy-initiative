# Mandatory server transcript and owner-approval boundary

This addendum narrows the proposed source contract01; it preserves its bytes.
Nothing here is implemented or executed. It is required reading with the
method map and proposed header02 before selecting an implementation.

The selected co-Groth16 formula reconstructs A and auxiliary **B1 in G1** before
computing C. Field checks must finish before those group openings. Both group
MAC checks must finish before either reconstructed point is used as a public
base with private r/s. Unchecked opened points must never enter those secret
scalar maps. Perform the same check discipline for final C/B2.

Here, "opened/public point" means known to the participating MPC servers. It
does **not** authorize sending partial A/B1 or raw prover transcripts to the
coordinator. Keep B1 server-internal; publish only the final A/B2/C proof after
all required checks and final verification. Header02 distinguishes admitted
globally public key points from server-opened points, and provides no generic
coordinator serialization route for the latter.

This operational boundary is **not an augmented-transcript privacy proof**.
Under coordinator plus one colluding prover, that prover can disclose its own
server transcript, including opened B1. MASCOT secrecy for the evaluated
function does not by itself establish that this enlarged Groth16 transcript
is zero knowledge or that active deviations preserve it. Source research,
correctness qualification and a separately reviewed privacy argument remain
necessary; a valid final proof or a benign full-proof run is insufficient.

The full-proof gate's two external clients and fixed x/y slots are public
synthetic plumbing. They do not hide client-to-component assignment or solve
real-owner private-nullifier approval. The current NativeAuth signer reconstructs
the full4077-byte packet,200-byte statement and complete3756-byte effects before
signing. Preserve that packet binding. Do not replace it with approval of an
opaque digest or imply that multiple owners can presently authorize unseen
private nullifiers/effects safely. This backend plan does not implement that
protocol, new-domain Exit/recovery, or actual private payment acceptance.
