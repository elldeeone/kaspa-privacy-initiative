// Proposed interface contract only. No implementation, includes from vendor,
// compilation, curve initialization, keys or runtime execution is supplied.
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace kpi_mascot_groth16_proposed {
// Bind to stock Share<gfp_<0,4>> and Share<BN_SNARK1_G{1,2}Value>.
// No value-only constructor/export is exposed by this interface.
struct FrPublic;
struct G1Public;
struct G2Public;
// Opened to MPC servers only; no coordinator/transcript serializer.
struct G1ServerOpened;
struct G2ServerOpened;
struct AuthScalar;
struct AuthG1;
struct AuthG2;
struct LinearMacContext;  // private party ID and alpha_i; never public logging.
struct MascotContext;    // one ordered ProtocolSetup/ProtocolSet/CryptoPlayer.
struct PublicModel;     // exact matrix, queries, domain, key/source identity.
struct FftPlan;         // explicit omega/invN/coset/order, never mcl default.
struct SparseRow;
struct OwnerInputContract; // strict DDNNT3n/all-server authenticated TLS route.
struct ProofPublic;

// Every function may fail closed; failure releases no partial accepted proof.
// Actual errors use the selected backend's checked exception/Result discipline.
void agree_public_model(MascotContext&, const PublicModel&);
std::vector<AuthScalar> receive_owner_inputs(MascotContext&, const OwnerInputContract&);
AuthScalar public_constant(const LinearMacContext&, const FrPublic&);
AuthScalar random_auth(MascotContext&); // preprocessing.get_random(); no randomize().
AuthScalar evaluate_linear(const SparseRow&, std::span<const AuthScalar> assignment);
std::vector<AuthScalar> multiply_batch(MascotContext&, std::span<const AuthScalar>,
                                      std::span<const AuthScalar>);
void check_field_pending(MascotContext&); // protocol.check + output.Check.
void auth_fft(std::span<AuthScalar>, const FftPlan&);
void auth_ifft(std::span<AuthScalar>, const FftPlan&);
void scale_public(std::span<AuthScalar>, std::span<const FrPublic> coefficients);
std::vector<AuthScalar> libsnark_h(MascotContext&, const PublicModel&,
                                  std::span<const AuthScalar> full_assignment);

AuthG1 msm_g1(std::span<const G1Public>, std::span<const AuthScalar>);
AuthG2 msm_g2(std::span<const G2Public>, std::span<const AuthScalar>);
AuthG1 public_point_map(const G1Public&, const AuthScalar&);
AuthG2 public_point_map(const G2Public&, const AuthScalar&);
AuthG1 server_opened_point_map(const G1ServerOpened&, const AuthScalar&);
void add_public(AuthG1&, const G1Public&, const LinearMacContext&);
void add_public(AuthG2&, const G2Public&, const LinearMacContext&);
// Flush field checks before POpen; complete ALL involved group MAC Checks
// plus field checks before returning any reconstructed point.
std::pair<G1ServerOpened,G1ServerOpened> open_checked_g1_pair(MascotContext&, const AuthG1&, const AuthG1&);
std::pair<G1ServerOpened,G2ServerOpened> open_checked_g1_g2(MascotContext&, const AuthG1&, const AuthG2&);

// Enforces public ONE, all dimensions, matched LibSnark plan and explicit
// original-H-query N-1 -> N padding with exactly one PUBLIC identity point.
// Publish only final verified A/B2/C; auxiliary opened B1 remains server-only.
ProofPublic prove(MascotContext&, const PublicModel&,
                  std::span<const AuthScalar> private_witness);
bool verify_public_proof_with_selected_ark_boundary(const PublicModel&, const ProofPublic&);
} // namespace kpi_mascot_groth16_proposed
