//! Public synthetic CS controls for the new Spend/Output relation boundary.
//! Run serialized under the root-selected resource window. No Groth16 setup,
//! proving, private-file ingress or per-case matrix fingerprint is involved.
#![cfg(feature = "prover")]

use ark_bn254::Fr;
use ark_ec::CurveGroup;
use ark_ed_on_bn254::Fr as BabyFr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use kpi_owner_private_lifecycle_relation::{
    CV, DOMAIN, H, MAX, NOTE_FLOOR, OutputCircuit,
    circuit::fixture,
    cv::{parameters, point_bytes, scalar_bytes, scalar_from_bytes},
    key_commitment, membership_root, nullifier, owner,
};

fn assert_cs<C: ConstraintSynthesizer<Fr>>(circuit: C, expected: bool, case: &str) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit
        .generate_constraints(cs.clone())
        .expect("public synthetic circuit must synthesize");
    cs.finalize();
    let satisfied = cs
        .is_satisfied()
        .expect("public synthetic constraint check must complete");
    assert_eq!(satisfied, expected, "{case}");
    // cs is released before the next case. In particular, do not call the
    // production shape checker, which additionally materializes/hashes matrices.
}

/// Test-only arithmetic bypass of native note-value policy. This is necessary
/// to present a matching public CV for an out-of-range private note value.
fn unbounded_test_cv(value: u64, blinding: BabyFr) -> CV {
    let parameters = parameters();
    let point = parameters.generators[0][0] * BabyFr::from(value)
        + parameters.randomness_generator[0] * blinding;
    assert!(!point.is_zero(), "synthetic CV must remain nonidentity");
    point_bytes(&point.into_affine())
}

fn output_with_value(value: u64) -> OutputCircuit {
    let (_, mut circuit) = fixture();
    circuit.witness.note.value = value;
    circuit.statement.cm = circuit.witness.note.commitment(&circuit.statement.domain);
    let blinding = scalar_from_bytes(&circuit.witness.blinding).unwrap();
    circuit.statement.cv = unbounded_test_cv(value, blinding);
    circuit
}

/// Only a deliberately invalid synthetic fixture may reduce noncanonical wire
/// bytes. The resulting public CV agrees with full group arithmetic, so for q
/// and q+1 the subgroup-order constraint is the only reason to reject the case.
fn output_with_noncanonical_scalar(raw: H) -> OutputCircuit {
    let (_, mut circuit) = fixture();
    circuit.witness.blinding = raw;
    let reduced_for_negative_fixture = BabyFr::from_le_bytes_mod_order(&raw);
    circuit.statement.cv =
        unbounded_test_cv(circuit.witness.note.value, reduced_for_negative_fixture);
    circuit
}

#[test]
fn output_accepts_exact_note_value_boundaries() {
    for value in [NOTE_FLOOR, MAX] {
        assert_cs(output_with_value(value), true, "Output value boundary");
    }
}

#[test]
fn output_rejects_out_of_range_values_with_matching_cm_and_unbounded_cv() {
    for value in [0, NOTE_FLOOR - 1, MAX + 1, u64::MAX] {
        let circuit = output_with_value(value);
        // Public syntax is valid: host range rejection must not mask the CS
        // control, and a stale CM/CV must not explain its failure.
        assert!(circuit.statement.validate().is_ok());
        assert_cs(circuit, false, "Output note-value range");
    }
}

#[test]
fn output_rejects_q_and_q_plus_one_with_matching_reduced_scalar_cv() {
    let modulus: H = BabyFr::MODULUS.to_bytes_le().try_into().unwrap();
    let mut above_modulus = modulus;
    for byte in &mut above_modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    for raw in [modulus, above_modulus] {
        let circuit = output_with_noncanonical_scalar(raw);
        assert!(circuit.statement.validate().is_ok());
        assert_cs(circuit, false, "Output canonical subgroup scalar");
    }
}

#[test]
fn output_rejects_bit_255_even_when_the_truncated_scalar_cv_is_unchanged() {
    let (_, mut circuit) = fixture();
    assert_eq!(circuit.witness.blinding, scalar_bytes(&BabyFr::from(7_u64)));
    let original_cv = circuit.statement.cv;
    circuit.witness.blinding[31] |= 0x80;
    // Keep CV(v,7). The fixed-base gadget only consumes the low 251 bits, so
    // recomputing this CV from full-byte reduction would mask an omitted upper-
    // bit constraint by introducing an unrelated commitment mismatch.
    assert_eq!(circuit.statement.cv, original_cv);
    assert_cs(circuit, false, "Output ignored high scalar bit");
}

#[test]
fn spend_accepts_the_synthetic_owned_note_and_membership_path() {
    let (circuit, _) = fixture();
    assert_cs(circuit, true, "Spend synthetic positive");
}

#[test]
fn spend_rejects_wrong_owner_secret_nullifier_secret_and_path() {
    let (original, _) = fixture();

    let mut wrong_owner = original.clone();
    wrong_owner.witness.owner_secret[0] ^= 1;
    assert_cs(wrong_owner, false, "Spend owner-secret binding");

    let mut wrong_key = original.clone();
    wrong_key.witness.nullifier_secret[0] ^= 1;
    let cm = wrong_key
        .witness
        .note
        .commitment(&wrong_key.statement.domain);
    // Recompute NF under the changed key: rejection must still enforce the
    // original note's key commitment, rather than only finding a stale NF.
    wrong_key.statement.nf = nullifier(
        &wrong_key.statement.domain,
        &wrong_key.witness.nullifier_secret,
        &cm,
        wrong_key.witness.position,
    );
    assert_cs(wrong_key, false, "Spend nullifier-key commitment");

    let mut wrong_path = original;
    wrong_path.witness.path[15][0] ^= 1;
    assert_cs(wrong_path, false, "Spend membership path");
}

#[test]
fn spend_rejects_high_position_alias_with_recomputed_full_position_nullifier() {
    let (mut circuit, _) = fixture();
    assert_eq!(circuit.witness.position, 3);
    let original_anchor = circuit.statement.anchor;
    let original_nf = circuit.statement.nf;
    circuit.witness.position = 3 + 65_536;
    let cm = circuit.witness.note.commitment(&circuit.statement.domain);
    circuit.statement.nf = nullifier(
        &circuit.statement.domain,
        &circuit.witness.nullifier_secret,
        &cm,
        circuit.witness.position,
    );
    assert_ne!(circuit.statement.nf, original_nf);
    assert_eq!(circuit.witness.position & 0xffff, 3);
    assert_eq!(circuit.statement.anchor, original_anchor);
    // Do not run membership_root(high_position): its host Range error would
    // hide the exact CS alias guard. The original root matches all low 16 bits.
    assert_cs(circuit, false, "Spend high-position NF alias");
}

#[test]
fn spend_rejects_another_domain_after_all_domain_sensitive_fields_are_rebuilt() {
    let (mut circuit, _) = fixture();
    let mut wrong_domain = DOMAIN;
    wrong_domain[0] ^= 1;
    circuit.statement.domain = wrong_domain;
    circuit.witness.note.owner = owner(
        &wrong_domain,
        &circuit.witness.owner_secret,
        &circuit.witness.note.incoming,
    );
    circuit.witness.note.key_commitment =
        key_commitment(&wrong_domain, &circuit.witness.nullifier_secret);
    let cm = circuit.witness.note.commitment(&wrong_domain);
    circuit.statement.anchor =
        membership_root(&cm, circuit.witness.position, &circuit.witness.path).unwrap();
    circuit.statement.nf = nullifier(
        &wrong_domain,
        &circuit.witness.nullifier_secret,
        &cm,
        circuit.witness.position,
    );
    // CV has no domain input; its opening is unchanged. Statement hashing and
    // its two public limbs follow the rebuilt statement inside synthesis.
    // Bypass host validate/parse so only the circuit's fixed DOMAIN can reject.
    assert_cs(
        circuit,
        false,
        "Spend fixed domain after full recomputation",
    );
}
