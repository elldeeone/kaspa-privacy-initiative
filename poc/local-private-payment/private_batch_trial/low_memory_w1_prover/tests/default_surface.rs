use kpb_low_memory_w1_prover::{production_boundary_status, source_only_runner_contract_status};

#[test]
fn default_surface_is_explicitly_source_only_and_unconfigured() {
    let status = production_boundary_status();
    assert!(!status.os_rng_blinding());
    assert!(!status.source_owned_assignment());
    assert!(!status.historical_pk());
    assert!(!status.independent_vk());
    assert!(!status.sealed_gzip_same_inode_two_pass());
    assert!(!status.proof_launch());
}

#[test]
fn fixed_runner_contract_is_present_but_every_authorizing_seam_is_absent() {
    let status = source_only_runner_contract_status();
    assert!(status.fixed_identity_contract());
    assert!(status.internal_nonzero_osrng_control());
    assert!(!status.source_owned_assignment_bridge());
    assert!(!status.same_inode_artifact_authority());
    assert!(!status.in_process_verifier_authority());
    assert!(!status.independent_verifier_authority());
    assert!(!status.full_secret_zeroization());
    assert!(!status.accepted_invalid_fatal());
    assert!(!status.canonical_publication_authority());
    assert!(!status.runner_selected());
}
