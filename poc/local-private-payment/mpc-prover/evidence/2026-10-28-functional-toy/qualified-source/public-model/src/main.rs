//! Public toy R1CS/setup exporter and independent canonical Ark verifier.
//! This program never ingests an external owner's private input. Setup uses
//! an unassigned circuit. The 3/5 fixture appears only in the public H oracle.
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, FftField, Field, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
        Matrix, OptimizationGoal, SynthesisError, SynthesisMode, Variable,
        R1CS_PREDICATE_LABEL},
    lc,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt::Write as _, fs, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone)]
struct ToyCircuit;
impl ConstraintSynthesizer<Fr> for ToyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> std::result::Result<(), SynthesisError> {
        let t = cs.new_input_variable(|| Err(SynthesisError::AssignmentMissing))?;
        let x = cs.new_witness_variable(|| Err(SynthesisError::AssignmentMissing))?;
        let y = cs.new_witness_variable(|| Err(SynthesisError::AssignmentMissing))?;
        let z = cs.new_witness_variable(|| Err(SynthesisError::AssignmentMissing))?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + y, || lc!() + z)?;
        cs.enforce_r1cs_constraint(|| lc!() + z + Variable::One,
            || lc!() + x + y, || lc!() + t)?;
        Ok(())
    }
}

fn hash(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn serialized<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}
fn fr(value: Fr) -> String { value.into_bigint().to_string() }
fn canonical_scalar(text: &str) -> Result<Fr> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) ||
        !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("noncanonical-public-Fr".into());
    }
    let value: Fr = text.parse().map_err(|_| "public-Fr-range")?;
    if fr(value) != text { return Err("public-Fr-alias".into()); }
    Ok(value)
}
fn point1(point: &G1Affine) -> String {
    if point.is_zero() { return "g1 1 0 0".into(); }
    format!("g1 0 {} {}", point.x.into_bigint(), point.y.into_bigint())
}
fn point2(point: &G2Affine) -> String {
    if point.is_zero() { return "g2 1 0 0 0 0".into(); }
    format!("g2 0 {} {} {} {}", point.x.c0.into_bigint(),
        point.x.c1.into_bigint(), point.y.c0.into_bigint(), point.y.c1.into_bigint())
}
fn matrix(out: &mut String, label: &str, matrix: &Matrix<Fr>) -> Result<()> {
    writeln!(out, "{label} {}", matrix.len())?;
    for row in matrix {
        write!(out, "row {}", row.len())?;
        for (coefficient, index) in row {
            write!(out, " {index} {}", fr(*coefficient))?;
        }
        writeln!(out)?;
    }
    Ok(())
}
fn query1(out: &mut String, label: &str, points: &[G1Affine]) -> Result<()> {
    writeln!(out, "{label} {}", points.len())?;
    for point in points { writeln!(out, "{}", point1(point))?; }
    Ok(())
}
fn query2(out: &mut String, label: &str, points: &[G2Affine]) -> Result<()> {
    writeln!(out, "{label} {}", points.len())?;
    for point in points { writeln!(out, "{}", point2(point))?; }
    Ok(())
}

fn export(destination: &Path) -> Result<()> {
    // A fresh destination preserves every used research-parameter identity.
    fs::create_dir(destination)?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    ToyCircuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let all = cs.to_matrices()?;
    if all.len() != 1 || !all.contains_key(R1CS_PREDICATE_LABEL) {
        return Err("unsupported-GR1CS-predicate".into());
    }
    let matrices = &all[R1CS_PREDICATE_LABEL];
    if matrices.len() != 3 || cs.num_constraints() != 2 ||
        cs.num_instance_variables() != 2 || cs.num_witness_variables() != 3 {
        return Err("unexpected-toy-R1CS-shape".into());
    }
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(ToyCircuit, &mut rand::rngs::OsRng)?;
    let pk_bytes = serialized(&pk)?;
    let vk_bytes = serialized(&pk.vk)?;
    let domain = Radix2EvaluationDomain::<Fr>::new(4).ok_or("domain-unavailable")?;
    if pk.a_query.len() != 5 || pk.b_g1_query.len() != 5 || pk.b_g2_query.len() != 5 ||
        pk.l_query.len() != 3 || pk.h_query.len() != 3 || pk.vk.gamma_abc_g1.len() != 2 {
        return Err("unexpected-Groth16-query-shape".into());
    }
    let mut out = String::new();
    writeln!(out, "KPI_MASCOT_PUBLIC_MODEL_V1\nfield {}\ncurve BN254\nreduction LibSnark", Fr::MODULUS)?;
    writeln!(out, "source {}", hash(include_bytes!("main.rs")))?;
    writeln!(out, "pk_sha256 {}\nvk_sha256 {}", hash(&pk_bytes), hash(&vk_bytes))?;
    writeln!(out, "num_instance 2\nnum_private 3\nnum_constraints 2\ndomain 4")?;
    writeln!(out, "omega {}\nomega_inverse {}\ninv_n {}\ncoset_shift {}",
        fr(domain.group_gen), fr(domain.group_gen_inv), fr(domain.size_inv), fr(Fr::GENERATOR))?;
    writeln!(out, "public_inputs 2 1 128")?;
    for (label, values) in ["A", "B", "C"].iter().zip(matrices) { matrix(&mut out, label, values)?; }
    writeln!(out, "alpha_g1 {}\nbeta_g1 {}\nbeta_g2 {}\ndelta_g1 {}\ndelta_g2 {}",
        point1(&pk.vk.alpha_g1), point1(&pk.beta_g1), point2(&pk.vk.beta_g2),
        point1(&pk.delta_g1), point2(&pk.vk.delta_g2))?;
    query1(&mut out, "a_query", &pk.a_query)?;
    query1(&mut out, "b_g1_query", &pk.b_g1_query)?;
    query2(&mut out, "b_g2_query", &pk.b_g2_query)?;
    query1(&mut out, "l_query", &pk.l_query)?;
    query1(&mut out, "h_query", &pk.h_query)?;
    writeln!(out, "vk_hex {}\nEND", hex::encode(&vk_bytes))?;
    fs::write(destination.join("public_model.txt"), out.as_bytes())?;
    fs::write(destination.join("pk.bin"), &pk_bytes)?;
    fs::write(destination.join("vk.bin"), &vk_bytes)?;
    // Public fixture oracle only: no external owner's input is read here.
    use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
    let h = LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        matrices, 2, 2, &[Fr::ONE, Fr::from(128), Fr::from(3), Fr::from(5), Fr::from(15)])?;
    if h.len() != 4 || h.iter().all(|value| *value == Fr::ZERO) { return Err("H-oracle-degenerate".into()); }
    let h_text = h.into_iter().map(fr).collect::<Vec<_>>().join("\n") + "\n";
    fs::write(destination.join("PUBLIC-FIXTURE-H.txt"), h_text)?;
    println!("{{\"model_sha256\":\"{}\",\"pk_sha256\":\"{}\",\"vk_sha256\":\"{}\",\"source_sha256\":\"{}\",\"scope\":\"public-toy-setup-no-owner-input-or-proof\"}}",
        hash(out.as_bytes()), hash(&pk_bytes), hash(&vk_bytes), hash(include_bytes!("main.rs")));
    Ok(())
}

fn verify(model_path: &Path, proof_path: &Path, public: &str, expected_model: &str) -> Result<bool> {
    if expected_model.len() != 64 || !expected_model.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err("expected-model-identity-format".into());
    }
    let body = fs::read(model_path)?;
    if hash(&body) != expected_model { return Err("unexpected-public-model-identity".into()); }
    let text = std::str::from_utf8(&body)?;
    let field = |name: &str| -> Result<&str> {
        let matches = text.lines().filter_map(|line| line.strip_prefix(name)).collect::<Vec<_>>();
        if matches.len() != 1 { return Err("duplicate-or-missing-model-field".into()); }
        Ok(matches[0])
    };
    if field("field ")? != Fr::MODULUS.to_string() || field("num_instance ")? != "2" {
        return Err("wrong-verifier-field-or-arity".into());
    }
    let vk_bytes = hex::decode(field("vk_hex ")?)?;
    if hash(&vk_bytes) != field("vk_sha256 ")? { return Err("VK-identity-mismatch".into()); }
    let mut remaining = vk_bytes.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut remaining)?;
    if !remaining.is_empty() || serialized(&vk)? != vk_bytes || vk.gamma_abc_g1.len() != 2 ||
        vk.alpha_g1.is_zero() || vk.beta_g2.is_zero() || vk.gamma_g2.is_zero() || vk.delta_g2.is_zero() ||
        vk.gamma_abc_g1.iter().any(AffineRepr::is_zero) { return Err("invalid-toy-VK".into()); }
    let proof_bytes = fs::read(proof_path)?;
    if proof_bytes.len() != 128 { return Err("wrong-Native128-proof-length".into()); }
    let mut remaining = proof_bytes.as_slice();
    let proof = Proof::<Bn254>::deserialize_compressed(&mut remaining)?;
    if !remaining.is_empty() || serialized(&proof)? != proof_bytes ||
        proof.a.is_zero() || proof.b.is_zero() || proof.c.is_zero() { return Err("noncanonical-or-identity-proof".into()); }
    Ok(Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, &[canonical_scalar(public)?])?)
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("export") if args.len() == 3 => export(Path::new(&args[2])),
        Some("verify") if args.len() == 6 => {
            let accepted = verify(Path::new(&args[2]), Path::new(&args[3]), &args[4], &args[5])?;
            println!("{{\"verified\":{accepted},\"public_input\":\"{}\"}}", args[4]);
            if !accepted { std::process::exit(1); }
            Ok(())
        }
        _ => Err("usage: public-model export NEW_DIRECTORY | verify MODEL PROOF PUBLIC_INPUT EXPECTED_MODEL_SHA256".into()),
    }
}
