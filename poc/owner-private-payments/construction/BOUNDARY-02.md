# Root-reviewed design clarification

ADR0063 and the shared contract supersede DESIGN-01's provisional labels.
The opaque row remains exactly520 bytes. OutputG16 uses the agreed new
`KPX7OU01` domain; post-mix SpendG16 alone authorizes exact final effects.
No public authorization key or extra signature is exported. Exact D is
`32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d`.

`backend.py` is the trusted local process launcher and has Docker authority.
It is explicitly **not** the malicious-coordinator privacy observer. The
separate `coordinator.py` process runs in a least-privilege, network-off
namespace. Its only incoming IPC consists of public session/program data,
three identical completed public MPC projections and public scheduling.
It has no owner path, input stream, private scratch, Docker socket, host
home or execution-request service. The launcher checks the coordinator's
proposal against the direct engine projections. No coordinator assertion
can replace an owner's independent own-engine projection or final effects
verification.

Each isolated engine wrapper writes its direct `OWN-MPC-PROJECTION.json`
inside that owner's private engine scratch before releasing its public
output. A final owner authorization must read that own result, verify the
same session/domain/roster/prior context and genuine proofs, recompute all
effects and verify its own outputs before creating SpendG16. The MPC JSON
is not a cryptographic on-chain certificate. Changed session, output list,
aggregate or financial context cannot be accepted merely because a
collector relabels a result.

Both old trial roots (all eight original files/directories) and all three
new owner private roots are metadata-excluded before public ingress. Only
the explicit typed private-input mount route may select an `Input-Pi-0`
under its corresponding new owner root. The public launcher never reads,
hashes or copies it. The mounted inode must match before the isolated
wrapper reads its first byte. All public files additionally require a
single link, preventing aliases to newly created secret files.

These are local isolation and interface obligations, not independent-host,
operator, adaptive-corruption, network-anonymity or abort-unlinkability
claims. Raw private scratch and input/oracle correspondence stay outside
public evidence. Genuine six-output proof integration and the frozen
attacker experiment remain required after source review.
