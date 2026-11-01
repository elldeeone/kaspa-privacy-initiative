#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, OptimizationGoal,
        R1CS_PREDICATE_LABEL, SynthesisMode, Variable,
    },
    lc,
};
use kpb_low_memory_w1_prover::algebraic_controls::{ExpectedIdentity, R1csGeometry};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct Tiny {
    left: Fr,
    right: Fr,
    x: Fr,
    y: Fr,
    product: Fr,
}

impl Tiny {
    pub fn exact() -> Self {
        Self {
            left: Fr::from(7u64),
            right: Fr::from(11u64),
            x: Fr::from(3u64),
            y: Fr::from(5u64),
            product: Fr::from(15u64),
        }
    }
}

impl ConstraintSynthesizer<Fr> for Tiny {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let left = cs.new_input_variable(|| Ok(self.left))?;
        let right = cs.new_input_variable(|| Ok(self.right))?;
        let x = cs.new_witness_variable(|| Ok(self.x))?;
        let y = cs.new_witness_variable(|| Ok(self.y))?;
        let product = cs.new_witness_variable(|| Ok(self.product))?;
        cs.enforce_r1cs_constraint(|| lc![x], || lc![y], || lc![product])?;
        cs.enforce_r1cs_constraint(
            || {
                lc![
                    (Fr::from(3u64), Variable::One),
                    (Fr::from(2u64), left),
                    (Fr::from(1u64), product)
                ]
            },
            || lc![Variable::One],
            || lc![(Fr::from(10u64), Variable::One), (Fr::from(2u64), right)],
        )?;
        cs.enforce_r1cs_constraint(
            || lc![(Fr::from(1u64), left), (-Fr::from(1u64), x)],
            || lc![(Fr::from(1u64), right), (-Fr::from(1u64), y)],
            || lc![(Fr::from(9u64), Variable::One), (Fr::from(1u64), product)],
        )?;
        Ok(())
    }
}

pub struct Fixture {
    pub bytes: Vec<u8>,
    pub constraint_bytes: u64,
    pub instances: Vec<Fr>,
    pub witnesses: Vec<Fr>,
    pub matrices: Vec<Matrix<Fr>>,
    pub constraints: usize,
}

#[derive(Clone)]
pub struct DeterministicRows {
    left: Fr,
    right: Fr,
    values: Vec<Fr>,
}

impl ConstraintSynthesizer<Fr> for DeterministicRows {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let _left = cs.new_input_variable(|| Ok(self.left))?;
        let _right = cs.new_input_variable(|| Ok(self.right))?;
        for value in self.values {
            let witness = cs.new_witness_variable(|| Ok(value))?;
            cs.enforce_r1cs_constraint(|| lc![witness], || lc![Variable::One], || lc![witness])?;
        }
        Ok(())
    }
}

fn put32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_le_bytes());
}

fn put64(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

fn append(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
}

fn field_bytes(value: Fr) -> [u8; 32] {
    let encoded = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..encoded.len()].copy_from_slice(&encoded);
    out
}

fn fixture_from<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Fixture {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: false,
    });
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert_eq!(cs.is_satisfied(), Ok(true));
    let instances = cs.instance_assignment().unwrap();
    let witnesses = cs.witness_assignment().unwrap();
    let matrices = cs.to_matrices().unwrap()[R1CS_PREDICATE_LABEL].clone();
    let wires = cs.num_variables();
    let constraints = cs.num_constraints();

    let mut header = Vec::new();
    put32(&mut header, 32);
    header.extend_from_slice(&Fr::MODULUS.to_bytes_le());
    put32(&mut header, wires);
    put32(&mut header, 0);
    put32(&mut header, instances.len() - 1);
    put32(&mut header, witnesses.len());
    put64(&mut header, wires);
    put32(&mut header, constraints);
    assert_eq!(header.len(), 64);

    let mut rows = Vec::new();
    for row in 0..constraints {
        for matrix in &matrices {
            put32(&mut rows, matrix[row].len());
            let mut prior = None;
            for &(coefficient, wire) in &matrix[row] {
                assert!(prior.is_none_or(|value| value < wire));
                put32(&mut rows, wire);
                rows.extend_from_slice(&field_bytes(coefficient));
                prior = Some(wire);
            }
        }
    }
    let constraint_bytes = rows.len() as u64;
    let mut map = Vec::new();
    for wire in 0..wires {
        put64(&mut map, wire);
    }
    let mut bytes = b"r1cs".to_vec();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    append(&mut bytes, 1, &header);
    append(&mut bytes, 2, &rows);
    append(&mut bytes, 3, &map);
    Fixture {
        bytes,
        constraint_bytes,
        instances,
        witnesses,
        matrices,
        constraints,
    }
}

pub fn fixture() -> Fixture {
    fixture_from(Tiny::exact())
}

pub fn deterministic_case(rows: usize, seed: u64) -> (DeterministicRows, Fixture) {
    assert!(rows > 0);
    let mut rng = StdRng::seed_from_u64(seed);
    let circuit = DeterministicRows {
        left: Fr::rand(&mut rng),
        right: Fr::rand(&mut rng),
        values: (0..rows).map(|_| Fr::rand(&mut rng)).collect(),
    };
    let fixture = fixture_from(circuit.clone());
    (circuit, fixture)
}

pub fn deterministic_fixture(rows: usize, seed: u64) -> Fixture {
    deterministic_case(rows, seed).1
}

pub fn identity(bytes: &[u8]) -> ExpectedIdentity {
    ExpectedIdentity {
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

pub fn geometry(fixture: &Fixture, bytes: &[u8]) -> R1csGeometry {
    R1csGeometry {
        wires: fixture.instances.len() + fixture.witnesses.len(),
        public_outputs: 0,
        public_inputs: fixture.instances.len() - 1,
        private_inputs: fixture.witnesses.len(),
        labels: (fixture.instances.len() + fixture.witnesses.len()) as u64,
        constraints: fixture.constraints,
        constraint_section_bytes: fixture.constraint_bytes,
        identity: identity(bytes),
    }
}

pub fn assignment(fixture: &Fixture) -> Vec<Fr> {
    fixture
        .instances
        .iter()
        .chain(&fixture.witnesses)
        .copied()
        .collect()
}
