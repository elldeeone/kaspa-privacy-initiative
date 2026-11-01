#![cfg(feature = "algebraic-controls")]

mod common;

use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_groth16::{
    Groth16, prepare_verifying_key,
    r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
};
use ark_poly::GeneralEvaluationDomain;
use ark_serialize::CanonicalSerialize;
use kpb_low_memory_w1_prover::algebraic_controls::{
    ProvingGeometry, create_proof_from_compressed_pk, stream_r1cs_witness_map,
};
use rand::{SeedableRng, rngs::StdRng};
use std::io::Cursor;

use common::{
    Tiny, assignment, deterministic_case, deterministic_fixture, fixture, geometry, identity,
};

#[test]
fn streamed_rows_and_h_equal_ark_exactly() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let stock = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &fixture.matrices,
        fixture.instances.len(),
        fixture.constraints,
        &assignment,
    )
    .unwrap();
    let streamed = stream_r1cs_witness_map(
        Cursor::new(fixture.bytes.as_slice()),
        geometry(&fixture, &fixture.bytes),
        &assignment,
    )
    .unwrap();
    assert_eq!(streamed.h, stock);
    assert_eq!(streamed.domain_size, stock.len());
}

#[test]
fn deterministic_randomized_rows_match_ark_across_domain_boundaries() {
    for (rows, seed) in [(1, 11), (2, 12), (5, 13), (6, 14), (13, 15), (14, 16)] {
        let fixture = deterministic_fixture(rows, seed);
        let assignment = assignment(&fixture);
        let stock =
            LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
                &fixture.matrices,
                fixture.instances.len(),
                fixture.constraints,
                &assignment,
            )
            .unwrap();
        let streamed = stream_r1cs_witness_map(
            Cursor::new(fixture.bytes.as_slice()),
            geometry(&fixture, &fixture.bytes),
            &assignment,
        )
        .unwrap();
        assert_eq!(streamed.domain_size, stock.len(), "rows={rows}");
        assert_eq!(streamed.h, stock, "rows={rows}");
    }
}

#[test]
fn streamed_pk_proof_equals_stock_ark_with_fixed_randomness() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &fixture.matrices,
        fixture.instances.len(),
        fixture.constraints,
        &assignment,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x5751_4c4d);
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(Tiny::exact(), &mut rng)
        .unwrap();
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded).unwrap();
    let mut encoded_vk = Vec::new();
    pk.vk.serialize_compressed(&mut encoded_vk).unwrap();
    let r = Fr::from(17u64);
    let s = Fr::from(29u64);
    let stock = Groth16::<Bn254>::create_proof_with_reduction(Tiny::exact(), &pk, r, s).unwrap();
    let streamed = create_proof_from_compressed_pk(
        Cursor::new(encoded.as_slice()),
        ProvingGeometry {
            instance_variables: fixture.instances.len(),
            witness_variables: fixture.witnesses.len(),
            domain_size: h.len(),
            identity: identity(&encoded),
            vk_identity: identity(&encoded_vk),
        },
        &fixture.instances,
        &fixture.witnesses,
        &h,
        r,
        s,
    )
    .unwrap();
    assert_eq!(streamed.vk, pk.vk);
    assert_eq!(streamed.proof, stock);

    let pvk = prepare_verifying_key(&streamed.vk);
    assert!(
        Groth16::<Bn254>::verify_proof(&pvk, &streamed.proof, &fixture.instances[1..],).unwrap()
    );
    let mut wrong = fixture.instances[1..].to_vec();
    wrong[0] += Fr::ONE;
    assert!(!Groth16::<Bn254>::verify_proof(&pvk, &streamed.proof, &wrong).unwrap());
    let mut mutated = streamed.proof.clone();
    mutated.a = (mutated.a.into_group() + G1Projective::generator()).into_affine();
    assert!(!Groth16::<Bn254>::verify_proof(&pvk, &mutated, &fixture.instances[1..],).unwrap());
}

#[test]
fn deterministic_randomized_proofs_equal_ark_across_domain_boundaries() {
    for (rows, seed) in [(1, 21), (6, 22), (14, 23)] {
        let (circuit, fixture) = deterministic_case(rows, seed);
        let assignment = assignment(&fixture);
        let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
            &fixture.matrices,
            fixture.instances.len(),
            fixture.constraints,
            &assignment,
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(seed ^ 0x5751_0000);
        let pk =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let mut encoded = Vec::new();
        pk.serialize_compressed(&mut encoded).unwrap();
        let mut encoded_vk = Vec::new();
        pk.vk.serialize_compressed(&mut encoded_vk).unwrap();
        let r = Fr::from(seed + 1);
        let s = Fr::from(seed + 2);
        let stock = Groth16::<Bn254>::create_proof_with_reduction(circuit, &pk, r, s).unwrap();
        let streamed = create_proof_from_compressed_pk(
            Cursor::new(encoded.as_slice()),
            ProvingGeometry {
                instance_variables: fixture.instances.len(),
                witness_variables: fixture.witnesses.len(),
                domain_size: h.len(),
                identity: identity(&encoded),
                vk_identity: identity(&encoded_vk),
            },
            &fixture.instances,
            &fixture.witnesses,
            &h,
            r,
            s,
        )
        .unwrap();
        assert_eq!(streamed.vk, pk.vk, "rows={rows}");
        assert_eq!(streamed.proof, stock, "rows={rows}");
    }
}
