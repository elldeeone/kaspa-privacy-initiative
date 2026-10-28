//! Owner-local actual matrix/proof command; fixed errors never print openings.
use kpi_private_batch_auth_exit::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{io::{self, Read}, path::Path};

type R<T> = Result<T, String>;
fn need(value: bool, code: &str) -> R<()> { if value { Ok(()) } else { Err(code.into()) } }
fn hexbytes<const N: usize>(text: &str) -> R<[u8; N]> {
    need(text.len() == 2 * N && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "CANONICAL_HEX")?;
    hex::decode(text).map_err(|_| "HEX".to_owned())?.try_into().map_err(|_| "LENGTH".into())
}
fn required<'a>(value: &'a Option<String>) -> R<&'a str> { value.as_deref().ok_or_else(|| "MISSING_INPUT".into()) }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileInput { domain_hex32: String, profile_id_hex32: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureInput {
    matrix: String, matrix_sha256: String, mapping_sha256: String,
    witness: String, witness_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    manifest: String, manifest_sha256: String,
    pk: Option<String>, pk_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    role: String,
    profile: ProfileInput,
    statement_hex: String,
    note_hex168: Option<String>,
    owner_key_hex64: Option<String>,
    nullifier_key_hex32: Option<String>,
    position: Option<u32>,
    path_hex32: Option<Vec<String>>,
    blinding_hex32: Option<String>,
    cf_hash_hex32: Option<String>,
    signature: Option<SignatureInput>,
    parameters: Option<Parameters>,
    proof_hex128: Option<String>,
    output_directory: Option<String>,
}

fn profile(value: &ProfileInput) -> R<Profile> {
    let domain = hexbytes(&value.domain_hex32)?;
    let profile_id = hexbytes(&value.profile_id_hex32)?;
    need(domain != native::DOMAIN && domain != [0; 32] && profile_id != [0; 32], "NEW_PROFILE_REQUIRED")?;
    Ok(Profile { domain, profile_id })
}
fn exit_statement(text: &str) -> R<ExitStatement> {
    let bytes = hexbytes::<152>(text)?; need(&bytes[..8] == AUTH_EXIT_TAG, "NEW_EXIT_TAG")?;
    Ok(ExitStatement {
        domain: bytes[8..40].try_into().unwrap(), anchor: bytes[40..72].try_into().unwrap(),
        nf: bytes[72..104].try_into().unwrap(), effects_digest: bytes[104..136].try_into().unwrap(),
        payout: u64::from_le_bytes(bytes[136..144].try_into().unwrap()),
        fee: u64::from_le_bytes(bytes[144..152].try_into().unwrap()),
    })
}
fn output_statement(text: &str) -> R<OutputStatement> {
    let bytes = hexbytes::<168>(text)?; need(&bytes[..8] == OUTPUT_TAG, "NEW_OUTPUT_TAG")?;
    Ok(OutputStatement {
        domain: bytes[8..40].try_into().unwrap(), cm: bytes[40..72].try_into().unwrap(),
        cv: bytes[72..136].try_into().unwrap(), cf_hash: bytes[136..].try_into().unwrap(),
    })
}
fn native_exit(request: &Request, profile: Profile) -> R<AuthExitCircuit> {
    let note = Note::parse(&hexbytes::<168>(required(&request.note_hex168)?)?).map_err(|_| "NOTE_ENCODING")?;
    let paths = request.path_hex32.as_ref().ok_or("MISSING_PATH")?;
    need(paths.len() == CM_DEPTH, "MEMBERSHIP_DEPTH")?;
    let path: Vec<H> = paths.iter().map(|p| hexbytes(p)).collect::<R<Vec<_>>>()?;
    Ok(AuthExitCircuit {
        profile, statement: exit_statement(&request.statement_hex)?,
        witness: ExitWitness {
            note, owner_key: hexbytes(required(&request.owner_key_hex64)?)?,
            nullifier_key: hexbytes(required(&request.nullifier_key_hex32)?)?,
            position: request.position.ok_or("MISSING_POSITION")?, path: path.try_into().map_err(|_| "MEMBERSHIP_DEPTH")?,
        },
    })
}
fn native_output(request: &Request, profile: Profile) -> R<OutputCircuit> {
    let note = Note::parse(&hexbytes::<168>(required(&request.note_hex168)?)?).map_err(|_| "NOTE_ENCODING")?;
    Ok(OutputCircuit { profile, statement: output_statement(&request.statement_hex)?,
        witness: OutputWitness { note, blinding: hexbytes(required(&request.blinding_hex32)?)? } })
}
fn signature(value: &SignatureInput) -> R<(join::R1cs, Vec<ark_bn254::Fr>)> {
    // One source-reviewed, actually compiled mature signature component. A
    // caller-provided hash of arbitrary JSON never selects a weaker predicate.
    need(value.matrix_sha256 == "b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11"
        && value.mapping_sha256 == "dfff3a6a7063aef13b053ad3e5ba96fc46c2b306c4d984747b0ddbb135290712",
        "SELECTED_MATURE_SIGNATURE_COMPONENT")?;
    let matrix = native::keys::read_pinned(Path::new(&value.matrix), &value.matrix_sha256, None).map_err(|_| "SIGNATURE_MATRIX_PIN")?;
    let matrix = interchange::signature_matrix(&matrix, &value.matrix_sha256, &value.mapping_sha256).map_err(|_| "SIGNATURE_MATRIX")?;
    need(matrix.instances == 67 && matrix.witnesses == 9_982 && matrix.constraints() == 10_065,
        "SELECTED_SIGNATURE_DIMENSIONS")?;
    let witness = native::keys::read_pinned(Path::new(&value.witness), &value.witness_sha256, None).map_err(|_| "SIGNATURE_WITNESS_PIN")?;
    let values = interchange::signature_witness(&witness, &value.witness_sha256, &value.matrix_sha256,
        &value.mapping_sha256, matrix.variables().map_err(|_| "SIGNATURE_VARIABLES")?).map_err(|_| "SIGNATURE_WITNESS")?;
    Ok((matrix, values))
}

fn run(request: Request) -> R<Value> {
    let selected = profile(&request.profile)?;
    need(matches!(request.role.as_str(), "new-auth-exit" | "new-output"), "NEW_ROLE")?;
    if request.operation == "derive-output" {
        need(request.role == "new-output", "OUTPUT_ROLE")?;
        let note = Note::parse(&hexbytes::<168>(required(&request.note_hex168)?)?).map_err(|_| "NOTE_ENCODING")?;
        let blinding = hexbytes(required(&request.blinding_hex32)?)?;
        let statement = OutputStatement { domain: selected.domain, cm: note.commitment(&selected.domain),
            cv: native::value_commitment(note.value, &blinding).map_err(|_| "VALUE_COMMITMENT")?,
            cf_hash: hexbytes(required(&request.cf_hash_hex32)?)? };
        return Ok(json!({"schema":"kpb-new-output-public-statement/v1","statement_hex168":hex::encode(statement.bytes()),
            "proof_or_ciphertext_validity_established":false}));
    }
    if request.operation == "verify" {
        need(request.note_hex168.is_none() && request.owner_key_hex64.is_none() && request.nullifier_key_hex32.is_none()
            && request.position.is_none() && request.path_hex32.is_none() && request.blinding_hex32.is_none()
            && request.signature.is_none(), "PUBLIC_VERIFIER_NO_PRIVATE_INPUTS")?;
        let inputs = if request.role == "new-auth-exit" {
            let s = exit_statement(&request.statement_hex)?; need(s.domain == selected.domain, "DOMAIN")?; s.public_inputs()
        } else {
            let s = output_statement(&request.statement_hex)?; need(s.domain == selected.domain, "DOMAIN")?; s.public_inputs()
        };
        let parameters = request.parameters.as_ref().ok_or("PARAMETERS")?;
        need(parameters.pk.is_none() && parameters.pk_sha256.is_none(), "PUBLIC_VERIFIER_NO_PK")?;
        let accepted = proof::verify(selected, &request.role, inputs,
            &hexbytes::<128>(required(&request.proof_hex128)?)?, Path::new(&parameters.manifest), &parameters.manifest_sha256)?;
        return Ok(json!({"schema":"kpb-new-wallet-proof-verification/v1","accepted":accepted,
            "role":request.role,"native_acceptance_or_currentness_established":false}));
    }
    need(matches!(request.operation.as_str(), "check-native" | "check-joined" | "setup" | "prove"), "OPERATION")?;
    let (matrix, values, native_only, counts) = if request.role == "new-output" {
        need(request.signature.is_none(), "OUTPUT_NO_SIGNATURE")?;
        let (matrix, values) = collect::collect(native_output(&request, selected)?, 3).map_err(|_| "OUTPUT_SYNTHESIS")?;
        let failures = proof::residual_failures(&matrix, &values)?;
        (matrix, values, false, json!({"output_residual_failures":failures}))
    } else if request.operation == "check-native" {
        need(request.signature.is_none(), "NATIVE_COMPONENT_ONLY")?;
        let (matrix, values) = collect::collect(native_exit(&request, selected)?, 67).map_err(|_| "EXIT_SYNTHESIS")?;
        let failures = proof::residual_failures(&matrix, &values)?;
        (matrix, values, true, json!({"native_residual_failures":failures,"signature_relation_checked":false}))
    } else {
        let (signature, witness) = signature(request.signature.as_ref().ok_or("FULL_SIGNATURE_COMPONENT_REQUIRED")?)?;
        let (joined, values) = join_exit(native_exit(&request, selected)?, &signature, &witness).map_err(|_| "ACTUAL_MATRIX_JOIN")?;
        let result = join::evaluate(&joined, &values).map_err(|_| "FULL_MATRIX_ASSIGNMENT")?;
        let counts = json!({"native_residual_failures":result.native_failures,"signature_residual_failures":result.signature_failures,
            "link_residual_failures":result.link_failures,"signature_relation_checked":true});
        (joined.cs, values, false, counts)
    };
    if request.operation.starts_with("check-") {
        return Ok(json!({"schema":"kpb-new-wallet-actual-matrix-check/v1","role":request.role,
            "instances":matrix.instances,"witnesses":matrix.witnesses,"constraints":matrix.constraints(),
            "matrix_sha256":join::fingerprint(&matrix).map_err(|_| "MATRIX_IDENTITY")?,"counts":counts,
            "native_component_only":native_only,"proof_or_native_acceptance_established":false}));
    }
    need(!native_only, "COMPLETE_PROOF_RELATION_REQUIRED")?;
    if request.operation == "setup" {
        let manifest = proof::setup(&matrix, &values, &request.role, selected,
            Path::new(required(&request.output_directory)?))?;
        return Ok(json!({"schema":"kpb-new-wallet-fresh-setup/v1","role":manifest.role,
            "matrix_sha256":manifest.matrix_sha256,"pk_bytes":manifest.pk_bytes,"pk_sha256":manifest.pk_sha256,
            "vk_sha256":manifest.vk_sha256,"setup_identity_reused":false,"native_readiness_claimed":false}));
    }
    let parameters = request.parameters.as_ref().ok_or("PARAMETERS")?;
    let result = proof::prove(&matrix, &values, &request.role, selected,
        Path::new(required(&parameters.pk)?), required(&parameters.pk_sha256)?,
        Path::new(&parameters.manifest), &parameters.manifest_sha256)?;
    Ok(json!({"schema":"kpb-new-wallet-complete-proof/v1","role":request.role,"proof_hex128":hex::encode(result),
        "native_acceptance_recovery_or_financial_readiness_established":false}))
}

fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() { eprintln!("new wallet input refused"); std::process::exit(2); }
    let result = serde_json::from_str::<Request>(&input).map_err(|_| "REQUEST".to_owned()).and_then(run);
    match result {
        Ok(value) => println!("{}", value),
        Err(code) => { eprintln!("{}", json!({"schema":"kpb-new-wallet-refusal/v1","category":code})); std::process::exit(2); }
    }
}
