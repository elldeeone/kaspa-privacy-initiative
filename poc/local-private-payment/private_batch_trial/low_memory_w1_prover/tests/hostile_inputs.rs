#![cfg(feature = "algebraic-controls")]

mod common;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::{
    Groth16,
    r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
};
use ark_poly::GeneralEvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpb_low_memory_w1_prover::algebraic_controls::{
    ProvingGeometry, create_proof_from_compressed_pk, rehearse_public_invalid_r1cs,
    stream_r1cs_witness_map,
};
use rand::{SeedableRng, rngs::StdRng};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use common::{Tiny, assignment, fixture, geometry, identity};

#[test]
fn public_invalid_resource_rehearsal_scans_all_rows_and_authenticates_first() {
    let fixture = fixture();
    let rehearsal = rehearse_public_invalid_r1cs(
        Cursor::new(fixture.bytes.as_slice()),
        geometry(&fixture, &fixture.bytes),
    )
    .expect("public invalid rehearsal refused");
    assert_eq!(rehearsal.rows, fixture.constraints);
    assert_eq!(
        rehearsal.wires,
        fixture.instances.len() + fixture.witnesses.len()
    );
    assert_eq!(rehearsal.domain_size, 8);
    assert!(rehearsal.unsatisfied_rows > 0);
    assert_ne!(rehearsal.h_sha256, [0u8; 32]);

    let mut hostile = geometry(&fixture, &fixture.bytes);
    hostile.identity.sha256[0] ^= 1;
    hostile.wires = usize::MAX;
    let got = rehearse_public_invalid_r1cs(Cursor::new(fixture.bytes.as_slice()), hostile)
        .expect_err("wrong identity was accepted before hostile allocation");
    assert_eq!(got.code(), "artifact-sha256");
}

struct SwapAfterFirstPass {
    first: Cursor<Vec<u8>>,
    second: Cursor<Vec<u8>>,
    using_second: bool,
}

impl SwapAfterFirstPass {
    fn new(first: Vec<u8>, second: Vec<u8>) -> Self {
        Self {
            first: Cursor::new(first),
            second: Cursor::new(second),
            using_second: false,
        }
    }
}

impl Read for SwapAfterFirstPass {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.using_second {
            self.second.read(output)
        } else {
            self.first.read(output)
        }
    }
}

impl Seek for SwapAfterFirstPass {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if !self.using_second && position == SeekFrom::Start(0) && self.first.position() != 0 {
            self.using_second = true;
        }
        if self.using_second {
            self.second.seek(position)
        } else {
            self.first.seek(position)
        }
    }
}

#[test]
fn parser_rejects_hostile_container_field_row_and_map_inputs() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let reject = |bytes: Vec<u8>, code: &'static str, values: &[Fr]| {
        let got = stream_r1cs_witness_map(
            Cursor::new(bytes.as_slice()),
            geometry(&fixture, &bytes),
            values,
        )
        .err()
        .expect("hostile input was accepted");
        assert_eq!(got.code(), code, "{got}");
    };

    let mut bad = fixture.bytes.clone();
    bad[0] ^= 1;
    reject(bad, "magic", &assignment);

    let mut bad = fixture.bytes.clone();
    bad[4..8].copy_from_slice(&2u32.to_le_bytes());
    reject(bad, "version", &assignment);

    let mut bad = fixture.bytes.clone();
    bad[8..12].copy_from_slice(&4u32.to_le_bytes());
    reject(bad, "section-count", &assignment);

    let mut bad = fixture.bytes.clone();
    bad[88..92].copy_from_slice(&3u32.to_le_bytes());
    reject(bad, "section-order", &assignment);

    let mut bad = fixture.bytes.clone();
    bad[28] ^= 1;
    reject(bad, "field-modulus", &assignment);

    // Container (12), header frame/body (12 + 64), constraint frame (12),
    // then A-count (4) and first A wire (4).
    let first_coefficient = 108;
    let mut bad = fixture.bytes.clone();
    bad[first_coefficient..first_coefficient + 32].fill(0);
    reject(bad, "coefficient-explicit-zero", &assignment);

    let mut bad = fixture.bytes.clone();
    bad[first_coefficient..first_coefficient + 32].copy_from_slice(&Fr::MODULUS.to_bytes_le());
    reject(bad, "coefficient-noncanonical", &assignment);

    let mut bad = fixture.bytes.clone();
    bad[104..108].copy_from_slice(&u32::MAX.to_le_bytes());
    reject(bad, "wire-out-of-range", &assignment);

    // Row zero occupies 120 bytes. Row one's A terms start at byte 220;
    // its second wire is at byte 260. Repeating wire zero is noncanonical.
    let mut bad = fixture.bytes.clone();
    bad[260..264].copy_from_slice(&0u32.to_le_bytes());
    reject(bad, "wire-noncanonical-order", &assignment);

    let mut bad = fixture.bytes.clone();
    bad.truncate(first_coefficient + 3);
    reject(bad, "coefficient-truncated", &assignment);

    let map_body = 100 + fixture.constraint_bytes as usize + 12;
    let mut bad = fixture.bytes.clone();
    bad[map_body..map_body + 8].copy_from_slice(&1u64.to_le_bytes());
    reject(bad, "wire-map-substitution", &assignment);

    let mut bad = fixture.bytes.clone();
    bad.push(0);
    reject(bad, "trailing-bytes", &assignment);

    let mut wrong_assignment = assignment.clone();
    *wrong_assignment.last_mut().unwrap() += Fr::ONE;
    let got = stream_r1cs_witness_map(
        Cursor::new(fixture.bytes.as_slice()),
        geometry(&fixture, &fixture.bytes),
        &wrong_assignment,
    )
    .err()
    .expect("wrong assignment was accepted");
    assert_eq!(got.code(), "unsatisfied-row");
}

#[test]
fn artifact_identity_and_pk_shape_fail_closed() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let mut wrong_identity = geometry(&fixture, &fixture.bytes);
    wrong_identity.identity.sha256[0] ^= 1;
    assert_eq!(
        stream_r1cs_witness_map(
            Cursor::new(fixture.bytes.as_slice()),
            wrong_identity,
            &assignment,
        )
        .err()
        .unwrap()
        .code(),
        "artifact-sha256"
    );

    let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &fixture.matrices,
        fixture.instances.len(),
        fixture.constraints,
        &assignment,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(4);
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(Tiny::exact(), &mut rng)
        .unwrap();
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded).unwrap();
    let mut encoded_vk = Vec::new();
    pk.vk.serialize_compressed(&mut encoded_vk).unwrap();
    let base = ProvingGeometry {
        instance_variables: fixture.instances.len(),
        witness_variables: fixture.witnesses.len(),
        domain_size: h.len(),
        identity: identity(&encoded),
        vk_identity: identity(&encoded_vk),
    };

    let mut wrong_vk = base;
    wrong_vk.vk_identity.sha256[0] ^= 1;
    assert_eq!(
        create_proof_from_compressed_pk(
            Cursor::new(encoded.as_slice()),
            wrong_vk,
            &fixture.instances,
            &fixture.witnesses,
            &h,
            Fr::ONE,
            Fr::ONE,
        )
        .err()
        .unwrap()
        .code(),
        "vk-sha256"
    );

    let mut bad = base;
    bad.instance_variables += 1;
    assert_eq!(
        create_proof_from_compressed_pk(
            Cursor::new(encoded.as_slice()),
            bad,
            &fixture.instances,
            &fixture.witnesses,
            &h,
            Fr::ONE,
            Fr::ONE,
        )
        .err()
        .unwrap()
        .code(),
        "instance-assignment-length"
    );

    let mut bad = base;
    bad.identity.sha256[0] ^= 1;
    assert_eq!(
        create_proof_from_compressed_pk(
            Cursor::new(encoded.as_slice()),
            bad,
            &fixture.instances,
            &fixture.witnesses,
            &h,
            Fr::ONE,
            Fr::ONE,
        )
        .err()
        .unwrap()
        .code(),
        "artifact-sha256"
    );

    let mut cursor = Cursor::new(encoded.as_slice());
    let _ = G1Affine::deserialize_compressed(&mut cursor).unwrap();
    let _ = G2Affine::deserialize_compressed(&mut cursor).unwrap();
    let _ = G2Affine::deserialize_compressed(&mut cursor).unwrap();
    let _ = G2Affine::deserialize_compressed(&mut cursor).unwrap();
    Vec::<G1Affine>::deserialize_compressed(&mut cursor).unwrap();
    let _ = G1Affine::deserialize_compressed(&mut cursor).unwrap();
    let _ = G1Affine::deserialize_compressed(&mut cursor).unwrap();
    let a_length = cursor.position() as usize;

    let mut substituted = encoded.clone();
    let wrong_length = (fixture.instances.len() + fixture.witnesses.len() + 1) as u64;
    substituted[a_length..a_length + 8].copy_from_slice(&wrong_length.to_le_bytes());
    let mut bad = base;
    bad.identity = identity(&substituted);
    assert_eq!(
        create_proof_from_compressed_pk(
            Cursor::new(substituted.as_slice()),
            bad,
            &fixture.instances,
            &fixture.witnesses,
            &h,
            Fr::ONE,
            Fr::ONE,
        )
        .err()
        .unwrap()
        .code(),
        "a-query"
    );

    let mut malformed_point = encoded.clone();
    malformed_point[a_length + 8..a_length + 40].fill(0xff);
    let mut bad = base;
    bad.identity = identity(&malformed_point);
    assert_eq!(
        create_proof_from_compressed_pk(
            Cursor::new(malformed_point.as_slice()),
            bad,
            &fixture.instances,
            &fixture.witnesses,
            &h,
            Fr::ONE,
            Fr::ONE,
        )
        .err()
        .unwrap()
        .code(),
        "a-query"
    );
}

#[test]
fn artifact_identity_is_checked_before_domain_allocation() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let mut hostile = geometry(&fixture, &fixture.bytes);
    hostile.identity.sha256[0] ^= 1;
    hostile.constraints = usize::MAX / 2;
    let got = stream_r1cs_witness_map(Cursor::new(fixture.bytes.as_slice()), hostile, &assignment)
        .err()
        .expect("wrong identity was accepted");
    assert_eq!(got.code(), "artifact-sha256");
}

#[test]
fn authenticated_impossible_domain_refuses_without_panicking() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let mut hostile = geometry(&fixture, &fixture.bytes);
    hostile.constraints = usize::MAX / 2;
    let got = stream_r1cs_witness_map(Cursor::new(fixture.bytes.as_slice()), hostile, &assignment)
        .err()
        .expect("impossible domain was accepted");
    assert_eq!(got.code(), "domain-overflow");
}

#[test]
fn pk_identity_is_checked_before_point_decode_or_secret_msm() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &fixture.matrices,
        fixture.instances.len(),
        fixture.constraints,
        &assignment,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(Tiny::exact(), &mut rng)
        .unwrap();
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded).unwrap();
    let mut encoded_vk = Vec::new();
    pk.vk.serialize_compressed(&mut encoded_vk).unwrap();
    encoded[..32].fill(0xff);
    let mut wrong_identity = identity(&encoded);
    wrong_identity.sha256[0] ^= 1;
    let got = create_proof_from_compressed_pk(
        Cursor::new(encoded),
        ProvingGeometry {
            instance_variables: fixture.instances.len(),
            witness_variables: fixture.witnesses.len(),
            domain_size: h.len(),
            identity: wrong_identity,
            vk_identity: identity(&encoded_vk),
        },
        &fixture.instances,
        &fixture.witnesses,
        &h,
        Fr::ONE,
        Fr::ONE,
    )
    .err()
    .expect("wrong identity was accepted");
    assert_eq!(got.code(), "artifact-sha256");
}

#[test]
fn decoded_pk_is_rehashed_during_secret_msm_use() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &fixture.matrices,
        fixture.instances.len(),
        fixture.constraints,
        &assignment,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(10);
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(Tiny::exact(), &mut rng)
        .unwrap();
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded).unwrap();
    let mut encoded_vk = Vec::new();
    pk.vk.serialize_compressed(&mut encoded_vk).unwrap();
    let mut substituted = encoded.clone();
    let first_a = encoded_vk.len() + 32 + 32 + 8;
    let (left, right) = substituted.split_at_mut(first_a + 32);
    left[first_a..first_a + 32].swap_with_slice(&mut right[..32]);

    let got = create_proof_from_compressed_pk(
        SwapAfterFirstPass::new(encoded.clone(), substituted),
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
        Fr::ONE,
        Fr::ONE,
    )
    .err()
    .expect("second-pass PK substitution was accepted");
    assert_eq!(got.code(), "artifact-sha256");
}

#[test]
fn every_pk_field_query_length_and_eof_boundary_fail_closed() {
    let fixture = fixture();
    let assignment = assignment(&fixture);
    let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &fixture.matrices,
        fixture.instances.len(),
        fixture.constraints,
        &assignment,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(11);
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(Tiny::exact(), &mut rng)
        .unwrap();
    let mut encoded = Vec::new();
    pk.serialize_compressed(&mut encoded).unwrap();
    let mut encoded_vk = Vec::new();
    pk.vk.serialize_compressed(&mut encoded_vk).unwrap();
    assert_eq!(encoded_vk.len(), 328);

    let reject = |bytes: Vec<u8>, code: &'static str| {
        let got = create_proof_from_compressed_pk(
            Cursor::new(bytes.as_slice()),
            ProvingGeometry {
                instance_variables: fixture.instances.len(),
                witness_variables: fixture.witnesses.len(),
                domain_size: h.len(),
                identity: identity(&bytes),
                vk_identity: identity(&encoded_vk),
            },
            &fixture.instances,
            &fixture.witnesses,
            &h,
            Fr::ONE,
            Fr::ONE,
        )
        .err()
        .expect("hostile PK was accepted");
        assert_eq!(got.code(), code, "{got}");
    };

    for (offset, width, code) in [
        (0, 32, "vk-alpha-g1"),
        (32, 64, "vk-beta-g2"),
        (96, 64, "vk-gamma-g2"),
        (160, 64, "vk-delta-g2"),
        (232, 32, "vk-gamma-abc-length"),
        (328, 32, "pk-beta-g1"),
        (360, 32, "pk-delta-g1"),
    ] {
        let mut hostile = encoded.clone();
        hostile[offset..offset + width].fill(0xff);
        reject(hostile, code);
    }

    let variables = fixture.instances.len() + fixture.witnesses.len();
    let a_len = encoded_vk.len() + 64;
    let b1_len = a_len + 8 + variables * 32;
    let b2_len = b1_len + 8 + variables * 32;
    let h_len = b2_len + 8 + variables * 64;
    let l_len = h_len + 8 + (h.len() - 1) * 32;
    for (length_offset, point_width, expected, code) in [
        (a_len, 32, variables, "a-query"),
        (b1_len, 32, variables, "b-g1-query"),
        (b2_len, 64, variables, "b-g2-query"),
        (h_len, 32, h.len() - 1, "h-query"),
        (l_len, 32, fixture.witnesses.len(), "l-query"),
    ] {
        let mut wrong_length = encoded.clone();
        wrong_length[length_offset..length_offset + 8]
            .copy_from_slice(&((expected as u64) + 1).to_le_bytes());
        reject(wrong_length, code);

        let mut wrong_point = encoded.clone();
        wrong_point[length_offset + 8..length_offset + 8 + point_width].fill(0xff);
        reject(wrong_point, code);
    }

    let mut truncated = encoded.clone();
    truncated.pop();
    reject(truncated, "l-query");
    let mut trailing = encoded;
    trailing.push(0);
    reject(trailing, "trailing-bytes");
}
