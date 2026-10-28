//! Actual Groth16 over the complete selected matrix; fresh research parameters.
//! A selected key is trusted only through an external manifest/body hash.
use crate::*;
use ark_bn254::{Bn254, Fr};
use ark_ff::{AdditiveGroup, Field};
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

type R<T> = Result<T, String>;
fn err<T>(code: &str) -> R<T> { Err(code.to_owned()) }
fn need(value: bool, code: &str) -> R<()> { if value { Ok(()) } else { err(code) } }

#[derive(Clone)]
pub struct MatrixCircuit {
    matrix: join::R1cs,
    values: Vec<Fr>,
}
impl MatrixCircuit {
    pub fn checked(matrix: &join::R1cs, values: &[Fr]) -> R<Self> {
        matrix.validate().map_err(|_| "MATRIX_SHAPE")?;
        need(matrix.instances == 3 && values.len() == matrix.variables().map_err(|_| "VARIABLES")?
            && values[0] == Fr::ONE, "COMPLETE_ASSIGNMENT")?;
        let failures = residual_failures(matrix, values)?;
        need(failures == 0, "ACTUAL_R1CS_UNSATISFIED")?;
        Ok(Self { matrix: matrix.clone(), values: values.to_vec() })
    }
}
impl ConstraintSynthesizer<Fr> for MatrixCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.matrix.validate().map_err(|_| SynthesisError::Unsatisfiable)?;
        let mut variables = vec![Variable::One];
        for index in 1..self.matrix.instances {
            variables.push(cs.new_input_variable(|| Ok(self.values[index]))?);
        }
        for index in self.matrix.instances..self.values.len() {
            variables.push(cs.new_witness_variable(|| Ok(self.values[index]))?);
        }
        for index in 0..self.matrix.constraints() {
            let lcs: [LinearCombination<Fr>; 3] = core::array::from_fn(|side| {
                self.matrix.matrices[side][index].iter().fold(LinearCombination::zero(),
                    |sum, (coefficient, at)| sum + (*coefficient, variables[*at]))
            });
            let [a, b, c] = lcs;
            cs.enforce_r1cs_constraint(|| a, || b, || c)?;
        }
        Ok(())
    }
}

pub fn residual_failures(matrix: &join::R1cs, values: &[Fr]) -> R<usize> {
    matrix.validate().map_err(|_| "MATRIX_SHAPE")?;
    need(values.len() == matrix.variables().map_err(|_| "VARIABLES")?
        && values.first() == Some(&Fr::ONE), "COMPLETE_ASSIGNMENT")?;
    let dot = |row: &join::Row| row.iter().fold(Fr::ZERO, |sum, (coefficient, at)| sum + *coefficient * values[*at]);
    Ok((0..matrix.constraints()).filter(|at| dot(&matrix.matrices[0][*at]) * dot(&matrix.matrices[1][*at])
        != dot(&matrix.matrices[2][*at])).count())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub role: String,
    pub domain_hex32: String,
    pub profile_id_hex32: String,
    pub source_sha256: String,
    pub matrix_sha256: String,
    pub instances: usize,
    pub witnesses: usize,
    pub constraints: usize,
    pub pk_bytes: u64,
    pub pk_sha256: String,
    pub vk_hex328: String,
    pub vk_sha256: String,
    pub setup_entropy: String,
}

pub fn source_identity() -> H {
    hash(&[
        include_bytes!("../Cargo.toml"), include_bytes!("../Cargo.lock"),
        include_bytes!("lib.rs"), include_bytes!("circuit.rs"),
        include_bytes!("exact_sha256.rs"), include_bytes!("proof.rs"),
        include_bytes!("main.rs"),
        include_bytes!("../../../native-authority/native-core/src/lib.rs"),
        include_bytes!("../../../native-authority/native-core/src/join.rs"),
        include_bytes!("../../../native-authority/native-core/src/collect.rs"),
        include_bytes!("../../../native-authority/native-core/src/interchange.rs"),
        &native::keys::source_identity(),
    ])
}

fn write_new(path: &Path, bytes: &[u8]) -> R<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o400)
        .open(path).map_err(|_| "FRESH_OUTPUT")?;
    file.write_all(bytes).map_err(|_| "WRITE_OUTPUT")?;
    file.sync_all().map_err(|_| "SYNC_OUTPUT".into())
}

pub fn setup(matrix: &join::R1cs, values: &[Fr], role: &str, profile: Profile, output: &Path) -> R<Manifest> {
    need(matches!(role, "new-auth-exit" | "new-output"), "NEW_RELATION_ROLE")?;
    need(profile.domain != native::DOMAIN && profile.domain != [0; 32] && profile.profile_id != [0; 32], "NEW_PROFILE_REQUIRED")?;
    let circuit = MatrixCircuit::checked(matrix, values)?;
    need(!output.exists(), "FRESH_SETUP_IDENTITY")?;
    fs::create_dir(output).map_err(|_| "FRESH_SETUP_DIRECTORY")?;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rand::rngs::OsRng)
        .map_err(|_| "SETUP")?;
    let mut bytes = Vec::new(); pk.serialize_uncompressed(&mut bytes).map_err(|_| "PK_SERIALIZE")?;
    let vk = native::vk_bytes(&pk.vk).map_err(|_| "VK_CANONICAL")?;
    let manifest = Manifest {
        schema: "kpb-new-wallet-parameters/v1".into(), role: role.into(),
        domain_hex32: hex::encode(profile.domain), profile_id_hex32: hex::encode(profile.profile_id),
        source_sha256: hex::encode(source_identity()), matrix_sha256: join::fingerprint(matrix).map_err(|_| "MATRIX_IDENTITY")?,
        instances: matrix.instances, witnesses: matrix.witnesses, constraints: matrix.constraints(),
        pk_bytes: bytes.len() as u64, pk_sha256: hex::encode(hash(&[&bytes])),
        vk_hex328: hex::encode(vk), vk_sha256: hex::encode(hash(&[&vk])),
        setup_entropy: "PRIVATE_OS_RNG_NOT_RETAINED".into(),
    };
    write_new(&output.join("parameters.pk"), &bytes)?;
    let mut metadata = serde_json::to_vec_pretty(&manifest).map_err(|_| "MANIFEST")?; metadata.push(b'\n');
    write_new(&output.join("MANIFEST.json"), &metadata)?;
    Ok(manifest)
}

fn manifest(path: &Path, pin: &str, profile: Profile, role: &str) -> R<Manifest> {
    let raw = native::keys::read_pinned(path, pin, None).map_err(|_| "MANIFEST_EXTERNAL_PIN")?;
    let result: Manifest = serde_json::from_slice(&raw).map_err(|_| "MANIFEST_PARSE")?;
    need(result.schema == "kpb-new-wallet-parameters/v1" && result.role == role
        && result.domain_hex32 == hex::encode(profile.domain) && result.profile_id_hex32 == hex::encode(profile.profile_id)
        && result.source_sha256 == hex::encode(source_identity()) && result.instances == 3
        && result.setup_entropy == "PRIVATE_OS_RNG_NOT_RETAINED", "EXACT_NEW_PROFILE_PARAMETERS")?;
    let vk = hex::decode(&result.vk_hex328).map_err(|_| "VK_HEX")?;
    need(vk.len() == 328 && hex::encode(hash(&[&vk])) == result.vk_sha256, "VK_EXTERNAL_BINDING")?;
    native::checked_vk(&vk).map_err(|_| "VK_CANONICAL")?;
    Ok(result)
}

pub fn prove(matrix: &join::R1cs, values: &[Fr], role: &str, profile: Profile,
    pk_path: &Path, pk_pin: &str, manifest_path: &Path, manifest_pin: &str) -> R<[u8; 128]> {
    let m = manifest(manifest_path, manifest_pin, profile, role)?;
    need(m.pk_sha256 == pk_pin && m.matrix_sha256 == join::fingerprint(matrix).map_err(|_| "MATRIX_IDENTITY")?
        && m.witnesses == matrix.witnesses && m.constraints == matrix.constraints(), "EXACT_RELATION_MATRIX")?;
    let raw = native::keys::read_pinned(pk_path, pk_pin, Some(m.pk_bytes)).map_err(|_| "PK_EXTERNAL_PIN")?;
    let mut remainder = raw.as_slice();
    // Trusted decode only after exact full public parameter bytes match selection.
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut remainder).map_err(|_| "PK_PARSE")?;
    need(remainder.is_empty() && hex::encode(native::vk_bytes(&pk.vk).map_err(|_| "VK_CANONICAL")?) == m.vk_hex328
        && pk.a_query.len() == values.len() && pk.b_g1_query.len() == values.len()
        && pk.b_g2_query.len() == values.len() && pk.l_query.len() == matrix.witnesses, "PK_QUERY_BINDING")?;
    let circuit = MatrixCircuit::checked(matrix, values)?;
    let result = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rand::rngs::OsRng)
        .map_err(|_| "PROVING")?;
    need(Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &result, &values[1..3])
        .map_err(|_| "INDEPENDENT_VERIFY")?, "FINAL_PROOF_REJECTED")?;
    native::proof_bytes(&result).map_err(|_| "PROOF_CANONICAL".into())
}

pub fn verify(profile: Profile, role: &str, public_inputs: [Fr; 2], proof: &[u8], manifest_path: &Path, manifest_pin: &str) -> R<bool> {
    let m = manifest(manifest_path, manifest_pin, profile, role)?;
    let vk = native::checked_vk(&hex::decode(&m.vk_hex328).map_err(|_| "VK_HEX")?).map_err(|_| "VK_CANONICAL")?;
    let proof = native::checked_proof(proof).map_err(|_| "PROOF_CANONICAL")?;
    Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, &public_inputs).map_err(|_| "VERIFY".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (join::R1cs, Vec<Fr>) {
        let one = Fr::ONE;
        let matrix = join::R1cs { instances: 3, witnesses: 2, matrices: [
            vec![vec![(one, 3)], vec![(one, 3), (one, 4)]],
            vec![vec![(one, 4)], vec![(one, 0)]],
            vec![vec![(one, 1)], vec![(one, 2)]],
        ] };
        (matrix, [1u64, 15, 8, 3, 5].map(Fr::from).to_vec())
    }

    #[test]
    fn matrix_import_preserves_every_row_and_assignment() {
        let (matrix, values) = fixture();
        let circuit = MatrixCircuit::checked(&matrix, &values).unwrap();
        let (actual, assignment) = collect::collect(circuit, 3).unwrap();
        assert_eq!(join::fingerprint(&actual).unwrap(), join::fingerprint(&matrix).unwrap());
        assert_eq!(assignment, values);
        assert_eq!(residual_failures(&actual, &assignment).unwrap(), 0);
    }

    #[test]
    fn complete_assignment_one_range_and_all_rows_are_mandatory() {
        let (matrix, values) = fixture();
        let mut changed = values.clone(); changed[3] += Fr::ONE;
        assert_eq!(residual_failures(&matrix, &changed).unwrap(), 2);
        assert!(MatrixCircuit::checked(&matrix, &changed).is_err());
        changed = values.clone(); changed[0] = Fr::ZERO;
        assert!(MatrixCircuit::checked(&matrix, &changed).is_err());
        assert!(MatrixCircuit::checked(&matrix, &values[..4]).is_err());
        let mut invalid = matrix.clone(); invalid.matrices[0][0][0].1 = values.len();
        assert!(MatrixCircuit::checked(&invalid, &values).is_err());
    }

    #[test]
    fn actual_small_groth16_and_native_codec_bind_public_inputs() {
        // Adapter control only. This arithmetic relation is not an AuthExit.
        let (matrix, values) = fixture();
        let circuit = MatrixCircuit::checked(&matrix, &values).unwrap();
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rand::rngs::OsRng).unwrap();
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rand::rngs::OsRng).unwrap();
        let canonical = native::proof_bytes(&proof).unwrap();
        let proof = native::checked_proof(&canonical).unwrap();
        let canonical_vk = native::vk_bytes(&pk.vk).unwrap();
        let vk = native::checked_vk(&canonical_vk).unwrap();
        assert!(Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, &values[1..3]).unwrap());
        assert!(!Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, &[Fr::from(16u64), Fr::from(8u64)]).unwrap());
    }
}
