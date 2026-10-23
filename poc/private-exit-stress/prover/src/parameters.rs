//! Exact compiled parameter authority. Runtime paths provide bytes, never policy.
use crate::{AUTH_MAGIC, DOMAIN, Role, Verifier, verification_key};
use ark_bn254::Bn254;
use ark_bn254::Fr;
use ark_groth16::ProvingKey;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, fs, io::Read, path::Path, time::Instant};

pub const GENESIS: &str = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370";
const OLD_DOMAIN: &str = "35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6";
const TRIAL: &[u8] = include_bytes!("../trial-selection.json");
fn compiled(role: Role) -> (&'static [u8], &'static [u8], &'static [u8; 328]) {
    match role {
        Role::Compact => (
            include_bytes!("../pins/compact2/parameter-selection.json"),
            include_bytes!("../pins/compact2/public-parameters.json"),
            include_bytes!("../pins/compact2/verification-key.bin"),
        ),
        Role::Wide => (
            include_bytes!("../pins/wide32/parameter-selection.json"),
            include_bytes!("../pins/wide32/public-parameters.json"),
            include_bytes!("../pins/wide32/verification-key.bin"),
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamError(pub &'static str);
impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ParamError {}
pub type Result<T> = std::result::Result<T, ParamError>;
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hash_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical(raw: &[u8]) -> Result<Value> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|_| ParamError("parameter_json_invalid"))?;
    if serde_json::to_vec(&value).map_err(|_| ParamError("parameter_json_invalid"))? != raw {
        return Err(ParamError("parameter_json_noncanonical"));
    }
    Ok(value)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialIdentity {
    pub schema: String,
    pub selected: bool,
    pub trial_id: String,
    pub network_id: String,
    pub genesis_hash_hex: String,
    pub domain_hex32: String,
    pub program_label: String,
    pub auth_magic_hex8: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    role: String,
    selected: bool,
    #[serde(default)]
    manifest_sha256: Option<String>,
    #[serde(default)]
    vk_sha256: Option<String>,
}
pub fn trial_identity() -> Result<TrialIdentity> {
    trial_from_bytes(TRIAL)
}
fn trial_from_bytes(bytes: &[u8]) -> Result<TrialIdentity> {
    let raw: Value =
        serde_json::from_slice(bytes).map_err(|_| ParamError("trial_selection_invalid"))?;
    if !raw.is_object() {
        return Err(ParamError("trial_selection_invalid"));
    }
    if raw.get("selected") != Some(&Value::Bool(true)) {
        return Err(ParamError("trial_unselected"));
    }
    let trial: TrialIdentity =
        serde_json::from_slice(bytes).map_err(|_| ParamError("trial_selection_invalid"))?;
    if trial.schema != "kpx4-selected-compact-batch-source/v1"
        || !trial.selected
        || trial.network_id != "testnet-10"
        || trial.genesis_hash_hex != GENESIS
        || trial.program_label != "AUTH528_PRIVATE_CAPACITY_EXIT/v1"
        || trial.auth_magic_hex8 != hex::encode(AUTH_MAGIC)
        || trial.trial_id.is_empty()
        || !trial
            .trial_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || trial.domain_hex32 != hex::encode(DOMAIN)
        || !hash_shape(&trial.domain_hex32)
        || trial.domain_hex32 == OLD_DOMAIN
        || DOMAIN == [0; 32]
    {
        return Err(ParamError("trial_selection_mismatch"));
    }
    Ok(trial)
}

pub fn source_identity_value() -> Value {
    json!({"lib_rs_sha256":digest(include_bytes!("lib.rs")),
        "circuit_rs_sha256":digest(include_bytes!("circuit.rs")),
        "exact_sha256_rs_sha256":digest(include_bytes!("exact_sha256.rs")),
        "request_rs_sha256":digest(include_bytes!("request.rs")),
        "parameters_rs_sha256":digest(include_bytes!("parameters.rs")),
        "main_rs_sha256":digest(include_bytes!("main.rs")),
        "setup_rs_sha256":digest(include_bytes!("bin/setup.rs")),
        "build_rs_sha256":digest(include_bytes!("../build.rs"))})
}
pub fn build_identity_value() -> Value {
    json!({"schema":"kpx4-prover-build-identity/v1", "source_identity":source_identity_value(),
        "cargo_toml_sha256":digest(include_bytes!("../Cargo.toml")),
        "cargo_lock_sha256":digest(include_bytes!("../Cargo.lock")),
        "trial_selection_sha256":digest(TRIAL),
        "rustc_verbose":env!("KPI_RUSTC_VERBOSE"),"target":env!("KPI_TARGET"),
        "profile":env!("KPI_PROFILE"),"features":env!("KPI_FEATURES"),
        "encoded_rustflags":env!("KPI_RUSTFLAGS")})
}
pub fn build_identity_sha256() -> String {
    digest(&serde_json::to_vec(&build_identity_value()).expect("public fixed build identity"))
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Shape {
    pub constraints: usize,
    pub witness_variables: usize,
    pub instances_including_one: usize,
    pub matrix_sha256: String,
    pub fft_domain_size: usize,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Queries {
    pub a: usize,
    pub b_g1: usize,
    pub b_g2: usize,
    pub l: usize,
    pub h: usize,
    pub instances_including_one: usize,
}
pub fn queries(pk: &ProvingKey<Bn254>) -> Queries {
    Queries {
        a: pk.a_query.len(),
        b_g1: pk.b_g1_query.len(),
        b_g2: pk.b_g2_query.len(),
        l: pk.l_query.len(),
        h: pk.h_query.len(),
        instances_including_one: pk.vk.gamma_abc_g1.len(),
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub executable_sha256: String,
    pub source_freeze_sha256: String,
    pub public_setup_report_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub role: String,
    pub output_arity: usize,
    pub auth_magic_hex8: String,
    pub program_label: String,
    pub trial_id: String,
    pub network_id: String,
    pub genesis_hash_hex: String,
    pub domain_hex32: String,
    pub format: String,
    pub pk_bytes: u64,
    pub pk_sha256: String,
    pub vk_hex328: String,
    pub vk_sha256: String,
    pub core_source_identity: BTreeMap<String, String>,
    pub compiled_build_identity_sha256: String,
    pub constraint_shape: Shape,
    pub queries: Queries,
    pub setup_provenance: Provenance,
}
pub struct Selected {
    pub manifest: Manifest,
    pub manifest_sha256: String,
}
fn selected_from_compiled(role: Role) -> Result<Selected> {
    let trial = trial_identity()?;
    let (selection_bytes, manifest_bytes, vk) = compiled(role);
    if !serde_json::from_slice::<Value>(selection_bytes)
        .map_err(|_| ParamError("parameter_selection_invalid"))?
        .is_object()
    {
        return Err(ParamError("parameter_selection_invalid"));
    }
    let selection: Selection = serde_json::from_slice(selection_bytes)
        .map_err(|_| ParamError("parameter_selection_invalid"))?;
    validate_manifest(role, selection, trial, manifest_bytes, vk)
}
// Private policy seam allows tiny independent test keys to exercise the same
// production validation. Production has exactly the compiled caller above.
fn validate_manifest(
    role: Role,
    selection: Selection,
    trial: TrialIdentity,
    raw: &[u8],
    expected_vk: &[u8; 328],
) -> Result<Selected> {
    if selection.role != role.name() {
        return Err(ParamError("parameter_role_mismatch"));
    }
    if !selection.selected {
        return Err(ParamError("parameters_unselected"));
    }
    if selection.schema != "kpx4-public-parameter-selection/v1" {
        return Err(ParamError("parameter_selection_invalid"));
    }
    let expected = selection
        .manifest_sha256
        .ok_or(ParamError("parameter_selection_invalid"))?;
    if !hash_shape(&expected) || digest(raw) != expected {
        return Err(ParamError("parameter_manifest_digest"));
    }
    let object = canonical(raw)?;
    if !object.is_object()
        || [
            "core_source_identity",
            "constraint_shape",
            "queries",
            "setup_provenance",
        ]
        .iter()
        .any(|key| !object.get(*key).is_some_and(Value::is_object))
    {
        return Err(ParamError("parameter_manifest_invalid"));
    }
    let m: Manifest =
        serde_json::from_slice(raw).map_err(|_| ParamError("parameter_manifest_invalid"))?;
    let vk = hex::decode(&m.vk_hex328).map_err(|_| ParamError("parameter_vk_invalid"))?;
    if m.schema != "kpx4-public-proving-parameters/v1"
        || m.role != role.name()
        || m.output_arity != role.output_count()
        || m.auth_magic_hex8 != hex::encode(AUTH_MAGIC)
        || m.program_label != trial.program_label
        || m.trial_id != trial.trial_id
        || m.network_id != trial.network_id
        || m.genesis_hash_hex != trial.genesis_hash_hex
        || m.domain_hex32 != trial.domain_hex32
        || m.format != "arkworks0.6-bn254-uncompressed"
        || !hash_shape(&m.pk_sha256)
        || m.pk_bytes == 0
        || m.pk_bytes > 32 * 1024 * 1024 * 1024
        || vk.as_slice() != expected_vk
        || hex::encode(&vk) != m.vk_hex328
        || digest(expected_vk) != m.vk_sha256
        || selection.vk_sha256.as_deref() != Some(m.vk_sha256.as_str())
        || serde_json::to_value(&m.core_source_identity)
            .map_err(|_| ParamError("parameter_source_invalid"))?
            != source_identity_value()
        || m.compiled_build_identity_sha256 != build_identity_sha256()
        || !hash_shape(&m.setup_provenance.executable_sha256)
        || !hash_shape(&m.setup_provenance.source_freeze_sha256)
        || !hash_shape(&m.setup_provenance.public_setup_report_sha256)
        || m.constraint_shape.constraints == 0
        || m.constraint_shape.instances_including_one != 3
        || m.queries.instances_including_one != 3
        || m.queries.a
            != m.constraint_shape
                .witness_variables
                .checked_add(3)
                .ok_or(ParamError("parameter_dimensions"))?
        || m.queries.b_g1 != m.queries.a
        || m.queries.b_g2 != m.queries.a
        || m.queries.l != m.constraint_shape.witness_variables
        || !hash_shape(&m.constraint_shape.matrix_sha256)
        || m.constraint_shape.fft_domain_size != fft_domain_size(&m.constraint_shape)?
        || m.queries.h
            != m.constraint_shape
                .fft_domain_size
                .checked_sub(1)
                .ok_or(ParamError("parameter_dimensions"))?
    {
        return Err(ParamError("parameter_manifest_mismatch"));
    }
    Verifier::new(expected_vk, role).map_err(|_| ParamError("parameter_vk_invalid"))?;
    Ok(Selected {
        manifest: m,
        manifest_sha256: expected,
    })
}
pub fn selected_identity(role: Role) -> Result<Selected> {
    selected_from_compiled(role)
}
pub fn selected_vk(role: Role) -> Result<&'static [u8; 328]> {
    selected_from_compiled(role)?;
    Ok(compiled(role).2)
}

// The only constructor authenticates a complete owned buffer before the only
// trusted-input decoder. Neither a matching embedded VK nor a caller hash can
// authorize decode. Changing the source path after read cannot change bytes.
struct AuthenticatedBytes(Vec<u8>);
impl AuthenticatedBytes {
    fn authenticate(bytes: Vec<u8>, manifest: &Manifest) -> Result<Self> {
        if bytes.len() as u64 != manifest.pk_bytes {
            return Err(ParamError("parameter_pk_length"));
        }
        if digest(&bytes) != manifest.pk_sha256 {
            return Err(ParamError("parameter_pk_digest"));
        }
        Ok(Self(bytes))
    }
    fn decode(self, manifest: &Manifest) -> Result<ProvingKey<Bn254>> {
        let mut remaining = self.0.as_slice();
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut remaining)
            .map_err(|_| ParamError("parameter_pk_decode"))?;
        if !remaining.is_empty() {
            return Err(ParamError("parameter_pk_trailing"));
        }
        drop(self);
        if hex::encode(verification_key(&pk).map_err(|_| ParamError("parameter_vk_invalid"))?)
            != manifest.vk_hex328
            || queries(&pk) != manifest.queries
        {
            return Err(ParamError("parameter_extracted_identity"));
        }
        Ok(pk)
    }
}
pub fn fft_domain_size(shape: &Shape) -> Result<usize> {
    let rows = shape
        .constraints
        .checked_add(shape.instances_including_one)
        .ok_or(ParamError("parameter_dimensions"))?;
    GeneralEvaluationDomain::<Fr>::new(rows)
        .map(|domain| domain.size())
        .ok_or(ParamError("parameter_dimensions"))
}

pub struct Loaded {
    pub pk: ProvingKey<Bn254>,
    pub selected: Selected,
    pub phase_seconds: BTreeMap<String, f64>,
}
impl Loaded {
    pub fn ready(&self) -> Value {
        json!({"event":"parameters-ready","role":self.selected.manifest.role,
        "output_arity":self.selected.manifest.output_arity,
        "parameter_manifest_sha256":self.selected.manifest_sha256,
        "domain_hex32":self.selected.manifest.domain_hex32,"vk_sha256":self.selected.manifest.vk_sha256,
        "compiled_build_identity_sha256":self.selected.manifest.compiled_build_identity_sha256})
    }
}
pub fn load(role: Role, path: &Path) -> Result<Loaded> {
    let selected = selected_from_compiled(role)?; // Before file access and allocation.
    let mut phase_seconds = BTreeMap::new();
    let began = Instant::now();
    let file = fs::File::open(path).map_err(|_| ParamError("parameter_pk_io"))?;
    if file
        .metadata()
        .map_err(|_| ParamError("parameter_pk_io"))?
        .len()
        != selected.manifest.pk_bytes
    {
        return Err(ParamError("parameter_pk_length"));
    }
    let length = usize::try_from(selected.manifest.pk_bytes)
        .map_err(|_| ParamError("parameter_pk_length"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            length
                .checked_add(1)
                .ok_or(ParamError("parameter_pk_length"))?,
        )
        .map_err(|_| ParamError("parameter_pk_allocation"))?;
    file.take(selected.manifest.pk_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ParamError("parameter_pk_io"))?;
    phase_seconds.insert("read_owned_bytes".into(), began.elapsed().as_secs_f64());
    let began = Instant::now();
    let authenticated = AuthenticatedBytes::authenticate(bytes, &selected.manifest)?;
    phase_seconds.insert(
        "authenticate_full_bytes".into(),
        began.elapsed().as_secs_f64(),
    );
    let began = Instant::now();
    let pk = authenticated.decode(&selected.manifest)?;
    phase_seconds.insert(
        "decode_exhaustion_checked_vk_and_dimensions".into(),
        began.elapsed().as_secs_f64(),
    );
    Ok(Loaded {
        pk,
        selected,
        phase_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
        lc,
    };
    use ark_serialize::CanonicalSerialize;
    #[derive(Clone)]
    struct Tiny;
    impl ConstraintSynthesizer<Fr> for Tiny {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> std::result::Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
            let b = cs.new_witness_variable(|| Ok(Fr::from(5u64)))?;
            let product = cs.new_input_variable(|| Ok(Fr::from(15u64)))?;
            let sum = cs.new_input_variable(|| Ok(Fr::from(8u64)))?;
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + product)?;
            cs.enforce_r1cs_constraint(|| lc!() + a + b, || lc!() + Variable::One, || lc!() + sum)
        }
    }
    fn tiny() -> (ProvingKey<Bn254>, Vec<u8>, Manifest, TrialIdentity) {
        // Small independent test parameters only; never a development/trial PK.
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            Tiny,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        let mut raw = Vec::new();
        pk.serialize_uncompressed(&mut raw).unwrap();
        let vk = verification_key(&pk).unwrap();
        let trial = TrialIdentity {
            schema: "kpx4-selected-compact-batch-source/v1".into(),
            selected: true,
            trial_id: "test-only".into(),
            network_id: "testnet-10".into(),
            genesis_hash_hex: GENESIS.into(),
            domain_hex32: hex::encode(DOMAIN),
            program_label: "AUTH528_PRIVATE_CAPACITY_EXIT/v1".into(),
            auth_magic_hex8: hex::encode(AUTH_MAGIC),
        };
        let m = Manifest {
            schema: "kpx4-public-proving-parameters/v1".into(),
            role: "compact2".into(),
            output_arity: 2,
            auth_magic_hex8: hex::encode(AUTH_MAGIC),
            program_label: "AUTH528_PRIVATE_CAPACITY_EXIT/v1".into(),
            trial_id: trial.trial_id.clone(),
            network_id: trial.network_id.clone(),
            genesis_hash_hex: trial.genesis_hash_hex.clone(),
            domain_hex32: trial.domain_hex32.clone(),
            format: "arkworks0.6-bn254-uncompressed".into(),
            pk_bytes: raw.len() as u64,
            pk_sha256: digest(&raw),
            vk_hex328: hex::encode(vk),
            vk_sha256: digest(&vk),
            core_source_identity: serde_json::from_value(source_identity_value()).unwrap(),
            compiled_build_identity_sha256: build_identity_sha256(),
            constraint_shape: Shape {
                constraints: 2,
                witness_variables: 2,
                instances_including_one: 3,
                matrix_sha256: "11".repeat(32),
                fft_domain_size: 8,
            },
            queries: queries(&pk),
            setup_provenance: Provenance {
                executable_sha256: "01".repeat(32),
                source_freeze_sha256: "02".repeat(32),
                public_setup_report_sha256: "03".repeat(32),
            },
        };
        (pk, raw, m, trial)
    }
    fn validate_test(m: &Value, trial: TrialIdentity, vk: &[u8; 328]) -> Result<Selected> {
        let raw = serde_json::to_vec(m).unwrap();
        let selection = Selection {
            schema: "kpx4-public-parameter-selection/v1".into(),
            role: "compact2".into(),
            selected: true,
            manifest_sha256: Some(digest(&raw)),
            vk_sha256: Some(digest(vk)),
        };
        validate_manifest(Role::Compact, selection, trial, &raw, vk)
    }
    #[test]
    fn template_is_unselected_before_pk_io() {
        assert_eq!(
            trial_from_bytes(
                b"{\"schema\":\"kpx4-selected-compact-batch-source/v1\",\"selected\":false}"
            )
            .and_then(|_| load(Role::Compact, Path::new("/not/a/parameter/file")))
            .err()
            .unwrap(),
            ParamError("trial_unselected")
        );
    }
    #[test]
    fn unselected_role_policies_reject_before_manifest_decode() {
        let (_, _, manifest, trial) = tiny();
        let vk: [u8; 328] = hex::decode(&manifest.vk_hex328)
            .unwrap()
            .try_into()
            .unwrap();
        for role in [Role::Compact, Role::Wide] {
            let selection = Selection {
                schema: "kpx4-public-parameter-selection/v1".into(),
                role: role.name().into(),
                selected: false,
                manifest_sha256: None,
                vk_sha256: None,
            };
            assert_eq!(
                validate_manifest(role, selection, trial.clone(), b"not-json", &vk).err(),
                Some(ParamError("parameters_unselected"))
            );
        }
    }
    #[test]
    fn role_swaps_reject_before_blob_access() {
        let (_, _, manifest, trial) = tiny();
        let vk: [u8; 328] = hex::decode(&manifest.vk_hex328)
            .unwrap()
            .try_into()
            .unwrap();
        let raw = serde_json::to_vec(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let selection = Selection {
            schema: "kpx4-public-parameter-selection/v1".into(),
            role: "compact2".into(),
            selected: true,
            manifest_sha256: Some(digest(&raw)),
            vk_sha256: Some(digest(&vk)),
        };
        assert_eq!(
            validate_manifest(Role::Wide, selection, trial.clone(), &raw, &vk).err(),
            Some(ParamError("parameter_role_mismatch"))
        );
        let selection = Selection {
            schema: "kpx4-public-parameter-selection/v1".into(),
            role: "wide32".into(),
            selected: true,
            manifest_sha256: Some(digest(&raw)),
            vk_sha256: Some(digest(&vk)),
        };
        assert_eq!(
            validate_manifest(Role::Wide, selection, trial, &raw, &vk).err(),
            Some(ParamError("parameter_manifest_mismatch"))
        );
    }
    #[test]
    fn canonical_manifest_bytes_reject_aliases() {
        assert!(canonical(b"{\"a\":1,\"b\":2}").is_ok());
        for raw in [
            b"{\"b\":2,\"a\":1}".as_slice(),
            b"{\"a\":1,\"b\":2}\n",
            b"{\"a\":1,\"a\":1}",
        ] {
            assert!(canonical(raw).is_err());
        }
    }
    #[test]
    fn tiny_official_parameters_authenticate_decode_prove_and_verify() {
        let (_, raw, m, trial) = tiny();
        let vk: [u8; 328] = hex::decode(&m.vk_hex328).unwrap().try_into().unwrap();
        let selected = validate_test(&serde_json::to_value(&m).unwrap(), trial, &vk).unwrap();
        let loaded = AuthenticatedBytes::authenticate(raw, &selected.manifest)
            .unwrap()
            .decode(&selected.manifest)
            .unwrap();
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            Tiny,
            &loaded,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        assert!(
            Groth16::<Bn254>::verify_proof(
                &prepare_verifying_key(&loaded.vk),
                &proof,
                &[Fr::from(15u64), Fr::from(8u64)]
            )
            .unwrap()
        );
    }
    #[test]
    fn bad_parameter_bytes_never_reach_decoder_or_witness_reader() {
        let (_, raw, m, _) = tiny();
        let mut mutated = raw.clone();
        mutated[0] ^= 1;
        let mut extended = raw.clone();
        extended.push(0);
        let short = raw[..raw.len() - 1].to_vec();
        for bad in [mutated, extended, short] {
            let mut decode_calls = 0;
            let mut witness_reads = 0;
            let result = AuthenticatedBytes::authenticate(bad, &m)
                .and_then(|bytes| {
                    decode_calls += 1;
                    bytes.decode(&m)
                })
                .map(|_| {
                    witness_reads += 1;
                });
            assert!(result.is_err());
            assert_eq!(decode_calls, 0);
            assert_eq!(witness_reads, 0);
        }
    }
    #[test]
    fn authenticated_wrong_vk_dimensions_and_trailing_bytes_reject() {
        let (_, raw, m, _) = tiny();
        let (_, _, other, _) = tiny();
        let mut wrong = m.clone();
        wrong.vk_hex328 = other.vk_hex328;
        assert!(
            AuthenticatedBytes::authenticate(raw.clone(), &wrong)
                .unwrap()
                .decode(&wrong)
                .is_err()
        );
        let mut wrong = m.clone();
        wrong.queries.l += 1;
        assert!(
            AuthenticatedBytes::authenticate(raw.clone(), &wrong)
                .unwrap()
                .decode(&wrong)
                .is_err()
        );
        let mut extended = raw;
        extended.push(0);
        let mut wrong = m;
        wrong.pk_bytes = extended.len() as u64;
        wrong.pk_sha256 = digest(&extended);
        assert_eq!(
            AuthenticatedBytes::authenticate(extended, &wrong)
                .unwrap()
                .decode(&wrong)
                .err()
                .unwrap(),
            ParamError("parameter_pk_trailing")
        );
    }
    #[test]
    fn manifest_policy_rejects_source_domain_format_vk_and_object_aliases() {
        let (_, _, m, trial) = tiny();
        let vk: [u8; 328] = hex::decode(&m.vk_hex328).unwrap().try_into().unwrap();
        let base = serde_json::to_value(&m).unwrap();
        for (name, bad) in [
            ("role", json!("wide32")),
            ("output_arity", json!(32)),
            ("auth_magic_hex8", json!("00".repeat(8))),
            ("program_label", json!("wrong-profile")),
            ("domain_hex32", json!("00".repeat(32))),
            ("network_id", json!("mainnet")),
            ("genesis_hash_hex", json!("00".repeat(32))),
            ("format", json!("compressed")),
            ("compiled_build_identity_sha256", json!("00".repeat(32))),
            ("vk_hex328", json!("00".repeat(328))),
            ("core_source_identity", json!({})),
            ("constraint_shape", json!([2, 2, 3])),
            ("queries", json!([5, 5, 5, 2, 7, 3])),
            (
                "setup_provenance",
                json!(["01".repeat(32), "02".repeat(32), "03".repeat(32)]),
            ),
            ("unknown", json!(true)),
        ] {
            let mut changed = base.clone();
            changed[name] = bad;
            assert!(validate_test(&changed, trial.clone(), &vk).is_err());
        }
        let mut changed = base;
        changed["core_source_identity"]["lib_rs_sha256"] = json!("00".repeat(32));
        assert!(validate_test(&changed, trial, &vk).is_err());
    }
}
