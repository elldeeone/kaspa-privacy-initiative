//! THROWAWAY PROTOTYPE: export one tiny Arkworks BN254 R1CS fixture in the
//! Circom/snarkjs binary R1CS v1 format. This never generates a CRS or key.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, Zero};
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, R1CS_PREDICATE_LABEL,
        Variable,
    },
    lc,
};
use std::{
    env,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

const FIELD_BYTES: usize = 32;
const R1CS_VERSION: u32 = 1;
const SECTION_COUNT: u32 = 3;

#[derive(Clone, Copy)]
struct TinyFixture {
    public_left: Fr,
    public_right: Fr,
    witness_x: Fr,
    witness_y: Fr,
    witness_product: Fr,
}

impl TinyFixture {
    fn exact() -> Self {
        Self {
            public_left: Fr::from(7_u64),
            public_right: Fr::from(11_u64),
            witness_x: Fr::from(3_u64),
            witness_y: Fr::from(5_u64),
            witness_product: Fr::from(15_u64),
        }
    }
}

impl ConstraintSynthesizer<Fr> for TinyFixture {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        // Arkworks order is ONE, instances in allocation order, then witnesses
        // in allocation order. The Python verifier freezes this exact mapping.
        let public_left = cs.new_input_variable(|| Ok(self.public_left))?;
        let public_right = cs.new_input_variable(|| Ok(self.public_right))?;
        let witness_x = cs.new_witness_variable(|| Ok(self.witness_x))?;
        let witness_y = cs.new_witness_variable(|| Ok(self.witness_y))?;
        let witness_product = cs.new_witness_variable(|| Ok(self.witness_product))?;

        // row 0: x * y = product. The explicit zero term proves that the
        // Arkworks matrix boundary removes zero coefficients before export.
        cs.enforce_r1cs_constraint(
            || lc![(Fr::ONE, witness_x), (Fr::ZERO, public_left)],
            || lc![witness_y],
            || lc![witness_product],
        )?;

        // row 1: (product + 2*public_left + 3) * 1
        //        = 2*public_right + 10.
        cs.enforce_r1cs_constraint(
            || {
                lc![
                    (Fr::from(3_u64), Variable::One),
                    (Fr::from(2_u64), public_left),
                    (Fr::ONE, witness_product),
                ]
            },
            || lc![Variable::One],
            || {
                lc![
                    (Fr::from(10_u64), Variable::One),
                    (Fr::from(2_u64), public_right),
                ]
            },
        )?;

        // row 2: (public_left - x) * (public_right - y) = product + 9.
        // Negative one is exported as the canonical residue modulus - 1.
        cs.enforce_r1cs_constraint(
            || lc![(Fr::ONE, public_left), (-Fr::ONE, witness_x)],
            || lc![(Fr::ONE, public_right), (-Fr::ONE, witness_y)],
            || lc![(Fr::from(9_u64), Variable::One), (Fr::ONE, witness_product),],
        )?;
        Ok(())
    }
}

fn put_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(
        &u32::try_from(value)
            .expect("prototype count exceeds u32")
            .to_le_bytes(),
    );
}

fn put_u64(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(
        &u64::try_from(value)
            .expect("prototype count exceeds u64")
            .to_le_bytes(),
    );
}

fn field_bytes(value: Fr) -> [u8; FIELD_BYTES] {
    let encoded = value.into_bigint().to_bytes_le();
    assert!(encoded.len() <= FIELD_BYTES);
    let mut result = [0_u8; FIELD_BYTES];
    result[..encoded.len()].copy_from_slice(&encoded);
    result
}

fn append_section(file: &mut Vec<u8>, section_type: u32, body: &[u8]) {
    file.extend_from_slice(&section_type.to_le_bytes());
    file.extend_from_slice(
        &u64::try_from(body.len())
            .expect("prototype section exceeds u64")
            .to_le_bytes(),
    );
    file.extend_from_slice(body);
}

fn encode_constraints(matrices: &[Matrix<Fr>], constraints: usize, wires: usize) -> Vec<u8> {
    assert_eq!(matrices.len(), 3, "R1CS must contain A, B, C matrices");
    assert!(matrices.iter().all(|matrix| matrix.len() == constraints));
    let mut body = Vec::new();
    for row in 0..constraints {
        for matrix in matrices {
            let terms = &matrix[row];
            put_u32(&mut body, terms.len());
            let mut previous = None;
            for &(coefficient, wire) in terms {
                assert!(!coefficient.is_zero(), "zero term crossed matrix boundary");
                assert!(wire < wires, "wire escaped matrix bounds");
                assert!(
                    previous.is_none_or(|value| value < wire),
                    "Arkworks row terms are not strictly wire-ordered"
                );
                previous = Some(wire);
                put_u32(&mut body, wire);
                body.extend_from_slice(&field_bytes(coefficient));
            }
        }
    }
    body
}

fn encode_fixture() -> Vec<u8> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    TinyFixture::exact()
        .generate_constraints(cs.clone())
        .expect("synthesize exact fixture");
    cs.finalize();
    assert_eq!(cs.is_satisfied(), Ok(true), "fixture must satisfy Arkworks");

    let instance = cs.instance_assignment().expect("instance assignment");
    let witness = cs.witness_assignment().expect("witness assignment");
    assert_eq!(instance, vec![Fr::ONE, Fr::from(7_u64), Fr::from(11_u64)]);
    assert_eq!(
        witness,
        vec![Fr::from(3_u64), Fr::from(5_u64), Fr::from(15_u64)]
    );

    let all_matrices = cs.to_matrices().expect("extract Arkworks matrices");
    assert_eq!(all_matrices.len(), 1, "fixture must contain only R1CS");
    let matrices = all_matrices
        .get(R1CS_PREDICATE_LABEL)
        .expect("R1CS matrices");

    let num_instances = cs.num_instance_variables();
    let num_witnesses = cs.num_witness_variables();
    let num_wires = cs.num_variables();
    let num_constraints = cs.num_constraints();
    assert_eq!(
        (num_instances, num_witnesses, num_wires, num_constraints),
        (3, 3, 6, 3)
    );

    let mut header = Vec::new();
    put_u32(&mut header, FIELD_BYTES);
    let modulus = Fr::MODULUS.to_bytes_le();
    assert_eq!(modulus.len(), FIELD_BYTES);
    header.extend_from_slice(&modulus);
    put_u32(&mut header, num_wires);
    put_u32(&mut header, 0); // nPubOut: Arkworks has one instance class.
    put_u32(&mut header, num_instances - 1); // nPubIn, excluding ONE.
    put_u32(&mut header, num_witnesses); // all fixture witnesses are private.
    put_u64(&mut header, num_wires); // identity labels for this prototype.
    put_u32(&mut header, num_constraints);
    assert_eq!(header.len(), 64);

    let constraints = encode_constraints(matrices, num_constraints, num_wires);
    let mut wire_to_label = Vec::new();
    for wire in 0..num_wires {
        put_u64(&mut wire_to_label, wire);
    }

    let mut file = Vec::new();
    file.extend_from_slice(b"r1cs");
    file.extend_from_slice(&R1CS_VERSION.to_le_bytes());
    file.extend_from_slice(&SECTION_COUNT.to_le_bytes());
    append_section(&mut file, 1, &header);
    append_section(&mut file, 2, &constraints);
    append_section(&mut file, 3, &wire_to_label);
    file
}

fn write_new(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

fn main() {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(output) = args.next() else {
        eprintln!("usage: {} OUTPUT.r1cs", Path::new(&program).display());
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("exactly one output path is required");
        std::process::exit(2);
    }
    let body = encode_fixture();
    if let Err(error) = write_new(Path::new(&output), &body) {
        eprintln!("refused to write prototype fixture: {error}");
        std::process::exit(2);
    }
    println!(
        "{{\"schema\":\"kpb-r1cs-bridge-prototype/v1\",\"bytes\":{},\"constraints\":3,\"instance_variables\":3,\"witness_variables\":3,\"setup_executed\":false}}",
        body.len()
    );
}
