//! Fixed, non-authorizing integration contract for a future W1 runner.
//!
//! This module is private. It deliberately has no run method, path argument,
//! assignment constructor, artifact opener, verifier process, or publication
//! sink. The relation crate must eventually own the fixed entry and borrow its
//! private prepared assignment directly; this crate must not depend on it.

#![allow(
    dead_code,
    reason = "inert source-only contract remains unreachable until every authority is selected"
)]

use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy)]
struct FixedIdentity {
    bytes: u64,
    sha256: &'static str,
}

#[derive(Clone, Copy)]
struct FixedQueryShape {
    a: usize,
    b_g1: usize,
    b_g2: usize,
    h: usize,
    l: usize,
    gamma_abc: usize,
}

#[derive(Clone, Copy)]
struct FixedRunnerContract {
    standard_r1cs: FixedIdentity,
    compressed_pk: FixedIdentity,
    decoded_pk: FixedIdentity,
    independent_vk: FixedIdentity,
    constraints: usize,
    variables: usize,
    instances: usize,
    queries: FixedQueryShape,
    verifier_binary_sha256: &'static str,
    verifier_build_receipt_sha256: &'static str,
    verifier_source_members_sha256: &'static str,
}

const FIXED_RUNNER_CONTRACT: FixedRunnerContract = FixedRunnerContract {
    standard_r1cs: FixedIdentity {
        bytes: 2_840_345_392,
        sha256: "cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc",
    },
    compressed_pk: FixedIdentity {
        bytes: 1_749_414_110,
        sha256: "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff",
    },
    decoded_pk: FixedIdentity {
        bytes: 2_608_842_576,
        sha256: "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945",
    },
    independent_vk: FixedIdentity {
        bytes: 328,
        sha256: "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102",
    },
    constraints: 13_093_029,
    variables: 12_949_821,
    instances: 3,
    queries: FixedQueryShape {
        a: 12_949_821,
        b_g1: 12_949_821,
        b_g2: 12_949_821,
        h: 16_777_215,
        l: 12_949_818,
        gamma_abc: 3,
    },
    verifier_binary_sha256: "915d4fde9e6b28d9569bb61d2629c8b01c09ab78f4acfdf841c55856c4748b9b",
    verifier_build_receipt_sha256: "ea2840748243fb30416cdf4eefee2d33bf06da2bfa54d3a0d04a645a93712a90",
    verifier_source_members_sha256: "57c1820f556cea3e88be5c768600ad5ebf5f0e5df6c2a5be3821644f96132b32",
};

/// Required causal order for the missing production integration.
///
/// This is a source contract, not an executable state machine. In particular,
/// it cannot turn a digest, path, reader, assignment slice, or verifier exit
/// status into proof authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunnerPhase {
    DescriptorAuthoritiesBound,
    R1csPreauthenticated,
    CompressedPkPreauthenticated,
    DecodedPkPreauthenticated,
    IndependentVkPreauthenticated,
    SourceAssignmentBorrowed,
    RelationAndHChecked,
    NonzeroBlindingDrawn,
    ProofConstructed,
    InProcessVerified,
    IndependentVerifierAccepted,
    CanonicallyPublished,
}

const REQUIRED_PHASES: [RunnerPhase; 12] = [
    RunnerPhase::DescriptorAuthoritiesBound,
    RunnerPhase::R1csPreauthenticated,
    RunnerPhase::CompressedPkPreauthenticated,
    RunnerPhase::DecodedPkPreauthenticated,
    RunnerPhase::IndependentVkPreauthenticated,
    RunnerPhase::SourceAssignmentBorrowed,
    RunnerPhase::RelationAndHChecked,
    RunnerPhase::NonzeroBlindingDrawn,
    RunnerPhase::ProofConstructed,
    RunnerPhase::InProcessVerified,
    RunnerPhase::IndependentVerifierAccepted,
    RunnerPhase::CanonicallyPublished,
];

/// Secret blinding owned only by the future fixed runner.
///
/// There is no constructor accepting caller randomness. OS-random failure is
/// fail-stop inside `Fr::rand`; zero samples are discarded.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretBlinding {
    r: Fr,
    s: Fr,
}

impl SecretBlinding {
    fn draw() -> Self {
        let mut rng = OsRng;
        Self {
            r: draw_nonzero(&mut rng),
            s: draw_nonzero(&mut rng),
        }
    }
}

fn draw_nonzero(rng: &mut OsRng) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

/// Non-authorizing status of the fixed runner contract.
///
/// The two true fields describe source-only code and fixed public constants.
/// Every field that could authorize assignment access, artifact access,
/// verification, publication, or execution remains false.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceOnlyRunnerContractStatus {
    fixed_identity_contract: bool,
    internal_nonzero_osrng_control: bool,
    source_owned_assignment_bridge: bool,
    same_inode_artifact_authority: bool,
    in_process_verifier_authority: bool,
    independent_verifier_authority: bool,
    full_secret_zeroization: bool,
    accepted_invalid_fatal: bool,
    canonical_publication_authority: bool,
    runner_selected: bool,
}

impl SourceOnlyRunnerContractStatus {
    pub const fn fixed_identity_contract(self) -> bool {
        self.fixed_identity_contract
    }

    pub const fn internal_nonzero_osrng_control(self) -> bool {
        self.internal_nonzero_osrng_control
    }

    pub const fn source_owned_assignment_bridge(self) -> bool {
        self.source_owned_assignment_bridge
    }

    pub const fn same_inode_artifact_authority(self) -> bool {
        self.same_inode_artifact_authority
    }

    pub const fn in_process_verifier_authority(self) -> bool {
        self.in_process_verifier_authority
    }

    pub const fn independent_verifier_authority(self) -> bool {
        self.independent_verifier_authority
    }

    pub const fn full_secret_zeroization(self) -> bool {
        self.full_secret_zeroization
    }

    pub const fn accepted_invalid_fatal(self) -> bool {
        self.accepted_invalid_fatal
    }

    pub const fn canonical_publication_authority(self) -> bool {
        self.canonical_publication_authority
    }

    pub const fn runner_selected(self) -> bool {
        self.runner_selected
    }
}

pub(super) static SOURCE_ONLY_RUNNER_CONTRACT_STATUS: SourceOnlyRunnerContractStatus =
    SourceOnlyRunnerContractStatus {
        fixed_identity_contract: true,
        internal_nonzero_osrng_control: true,
        source_owned_assignment_bridge: false,
        same_inode_artifact_authority: false,
        in_process_verifier_authority: false,
        independent_verifier_authority: false,
        full_secret_zeroization: false,
        accepted_invalid_fatal: false,
        canonical_publication_authority: false,
        runner_selected: false,
    };

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_contract_matches_the_reviewed_w1_sources() {
        let contract = FIXED_RUNNER_CONTRACT;
        assert_eq!(contract.standard_r1cs.bytes, 2_840_345_392);
        assert_eq!(contract.standard_r1cs.sha256.len(), 64);
        assert_eq!(contract.compressed_pk.bytes, 1_749_414_110);
        assert_eq!(contract.compressed_pk.sha256.len(), 64);
        assert_eq!(contract.decoded_pk.bytes, 2_608_842_576);
        assert_eq!(contract.decoded_pk.sha256.len(), 64);
        assert_eq!(contract.independent_vk.bytes, 328);
        assert_eq!(contract.independent_vk.sha256.len(), 64);
        assert_eq!(contract.constraints, 13_093_029);
        assert_eq!(contract.variables, 12_949_821);
        assert_eq!(contract.instances, 3);
        assert_eq!(contract.queries.a, contract.variables);
        assert_eq!(contract.queries.b_g1, contract.variables);
        assert_eq!(contract.queries.b_g2, contract.variables);
        assert_eq!(contract.queries.h, 16_777_215);
        assert_eq!(contract.queries.l, contract.variables - contract.instances);
        assert_eq!(contract.queries.gamma_abc, contract.instances);
        assert_eq!(contract.verifier_binary_sha256.len(), 64);
        assert_eq!(contract.verifier_build_receipt_sha256.len(), 64);
        assert_eq!(contract.verifier_source_members_sha256.len(), 64);
    }

    #[test]
    fn preauthentication_precedes_every_secret_operation() {
        assert_eq!(
            REQUIRED_PHASES,
            [
                RunnerPhase::DescriptorAuthoritiesBound,
                RunnerPhase::R1csPreauthenticated,
                RunnerPhase::CompressedPkPreauthenticated,
                RunnerPhase::DecodedPkPreauthenticated,
                RunnerPhase::IndependentVkPreauthenticated,
                RunnerPhase::SourceAssignmentBorrowed,
                RunnerPhase::RelationAndHChecked,
                RunnerPhase::NonzeroBlindingDrawn,
                RunnerPhase::ProofConstructed,
                RunnerPhase::InProcessVerified,
                RunnerPhase::IndependentVerifierAccepted,
                RunnerPhase::CanonicallyPublished,
            ]
        );
    }

    #[test]
    fn blinding_is_internal_nonzero_and_zeroizable() {
        for _ in 0..32 {
            let mut blinding = SecretBlinding::draw();
            assert!(!blinding.r.is_zero());
            assert!(!blinding.s.is_zero());
            blinding.zeroize();
            assert!(blinding.r.is_zero());
            assert!(blinding.s.is_zero());
        }
    }
}
