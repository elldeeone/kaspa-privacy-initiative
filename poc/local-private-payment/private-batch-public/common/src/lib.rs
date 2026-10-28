//! ADR0074 mandatory proved public wrapper. No wallet openings or network.
//! The installed NEW profile is embedded into the guest image; a host checker
//! alone cannot authorize a native transition.
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_local_private_payment_relation as relation;
use serde::Deserialize;
use sha2::{Digest, Sha256};
mod g16;
pub mod wire;
#[cfg(test)]
mod tests;
pub use wire::{Body, Context, Projection, BODY_CORE_LEN, BODY_LEN, PREFIX_LEN, PROJECTION_LEN};

pub type H = [u8; 32];
pub type Result<T> = std::result::Result<T, &'static str>;
pub const JOURNAL_LEN: usize = 104;

pub fn need(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
pub fn sha(parts: &[&[u8]]) -> H {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    need(
        text.len() == 2 * N
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "profile_hex",
    )?;
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| "profile_hex")?;
    Ok(bytes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleFile {
    vk_hex328: String,
    vk_sha256: String,
    parameter_manifest_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    schema: String,
    selected: bool,
    classification: String,
    chain_genesis_hex32: String,
    pool_lineage_hex32: String,
    profile_id_hex32: String,
    domain_hex32: String,
    service_policy_hex32: String,
    aggregate: RoleFile,
    output: RoleFile,
    auth_exit: RoleFile,
    value_generator_hex64: String,
    blinding_generator_hex64: String,
    curve_parameters_sha256: String,
    input_count: u16,
    output_count: u16,
    note_floor_sompi: u64,
    max_value_sompi: u64,
    body_core_bytes: usize,
    body_bytes: usize,
    journal_bytes: usize,
    auth_exit_statement_bytes: usize,
}
pub struct Profile {
    pub sha: H,
    pub context: Context,
    pub aggregate_vk_sha: H,
    pub output_vk_sha: H,
    pub auth_exit_vk_sha: H,
    aggregate: g16::Verifier,
    output: g16::Verifier,
    aggregate_key: VerifyingKey<Bn254>,
    output_key: VerifyingKey<Bn254>,
}
fn key(file: &RoleFile) -> Result<(g16::Verifier, H, VerifyingKey<Bn254>)> {
    need(
        decode::<32>(&file.parameter_manifest_sha256)? != [0; 32],
        "profile_parameter_identity",
    )?;
    let raw = decode::<328>(&file.vk_hex328)?;
    let digest = decode::<32>(&file.vk_sha256)?;
    need(sha(&[&raw]) == digest, "profile_key_digest")?;
    let mut rest = raw.as_slice();
    let key = VerifyingKey::<Bn254>::deserialize_compressed(&mut rest)
        .map_err(|_| "profile_key_decode")?;
    let mut encoded = Vec::new();
    key.serialize_compressed(&mut encoded)
        .map_err(|_| "profile_key_encode")?;
    need(
        rest.is_empty()
            && encoded == raw
            && key.gamma_abc_g1.len() == 3
            && !key.alpha_g1.is_zero()
            && !key.beta_g2.is_zero()
            && !key.gamma_g2.is_zero()
            && !key.delta_g2.is_zero()
            && key.gamma_abc_g1.iter().all(|point| !point.is_zero()),
        "profile_key_canonical_or_arity",
    )?;
    Ok((g16::Verifier::from_validated_key(&key), digest, key))
}
impl Profile {
    pub fn installed() -> Result<Self> {
        Self::parse(include_bytes!("../../component-profile.json"))
    }
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let file: ProfileFile = serde_json::from_slice(raw).map_err(|_| "profile_json")?;
        need(
            file.selected
                && file.schema == "private-batch-component-profile/v1"
                && file.classification == "RESEARCH_TESTNET_ONLY"
                && file.input_count == 3
                && file.output_count == 6
                && file.note_floor_sompi == wire::FLOOR
                && file.max_value_sompi == wire::MAX
                && file.body_core_bytes == BODY_CORE_LEN
                && file.body_bytes == BODY_LEN
                && file.journal_bytes == JOURNAL_LEN
                && file.auth_exit_statement_bytes == 152,
            "profile_identity",
        )?;
        let context = Context {
            chain_genesis: decode(&file.chain_genesis_hex32)?,
            pool_lineage: decode(&file.pool_lineage_hex32)?,
            profile_id: decode(&file.profile_id_hex32)?,
            domain: decode(&file.domain_hex32)?,
            service_policy: decode(&file.service_policy_hex32)?,
        };
        need(
            [
                context.chain_genesis,
                context.pool_lineage,
                context.profile_id,
                context.domain,
                context.service_policy,
            ]
            .iter()
            .all(|identity| *identity != [0; 32]),
            "profile_context",
        )?;
        let (value, blind, curve_digest) = public_parameters();
        need(
            decode::<64>(&file.value_generator_hex64)? == value
                && decode::<64>(&file.blinding_generator_hex64)? == blind
                && decode::<32>(&file.curve_parameters_sha256)? == curve_digest,
            "profile_generators",
        )?;
        let _ = relation::point_from_bytes(&value).map_err(|_| "profile_value_generator")?;
        let _ = relation::point_from_bytes(&blind).map_err(|_| "profile_blind_generator")?;
        // Absolute sum of 3 input, 6 output and fee integer magnitudes is below
        // the CV subgroup order. Per-owner range/conservation remains in the CS.
        let bound = 10u128
            .checked_mul(u128::from(wire::MAX))
            .ok_or("antiwrap_bound")?;
        let mut scalar = [0u8; 32];
        scalar[..16].copy_from_slice(&bound.to_le_bytes());
        relation::scalar_from_bytes(&scalar).map_err(|_| "antiwrap_bound")?;
        let (aggregate, aggregate_vk_sha, aggregate_key) = key(&file.aggregate)?;
        let (output, output_vk_sha, output_key) = key(&file.output)?;
        let (_, auth_exit_vk_sha, _) = key(&file.auth_exit)?;
        need(
            aggregate_vk_sha != output_vk_sha
                && aggregate_vk_sha != auth_exit_vk_sha
                && output_vk_sha != auth_exit_vk_sha,
            "distinct_relation_keys",
        )?;
        Ok(Self {
            sha: sha(&[raw]),
            context,
            aggregate_vk_sha,
            output_vk_sha,
            auth_exit_vk_sha,
            aggregate,
            output,
            aggregate_key,
            output_key,
        })
    }
}
pub fn public_parameters() -> ([u8; 64], [u8; 64], H) {
    let (value, blind) = relation::generators_bytes();
    (value, blind, relation::parameter_powers_digest())
}
fn inputs(digest: &H) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&digest[..16]),
        Fr::from_le_bytes_mod_order(&digest[16..]),
    ]
}
fn output_statement(domain: H, output: &wire::Output<'_>) -> [u8; 168] {
    let mut statement = [0; 168];
    statement[..8].copy_from_slice(b"KPXAOU01");
    statement[8..40].copy_from_slice(&domain);
    statement[40..72].copy_from_slice(&output.cm);
    statement[72..136].copy_from_slice(&output.cv);
    statement[136..].copy_from_slice(&output.cfh);
    statement
}
pub fn evaluate(raw: &[u8]) -> Result<[u8; JOURNAL_LEN]> {
    let profile = Profile::installed()?;
    evaluate_with_profile(raw, &profile)
}
pub fn evaluate_with_profile(raw: &[u8], profile: &Profile) -> Result<[u8; JOURNAL_LEN]> {
    let projection = Projection::parse(raw, &profile.context)?;
    wire::validate_transition(&projection)?;
    let body = &projection.body;
    let input_cvs: Vec<_> = body.spends.iter().map(|spend| spend.cv).collect();
    let output_cvs: Vec<_> = body.outputs.iter().map(|output| output.cv).collect();
    need(
        relation::check_balance(&input_cvs, &output_cvs, body.fee, &body.delta)
            .map_err(|_| "curve_scalar_or_balance_encoding")?,
        "global_group_balance",
    )?;
    profile.aggregate.verify_inputs(
        body.aggregate_proof,
        &inputs(&sha(&[&body.raw[..BODY_CORE_LEN]])),
    )?;
    for output in &body.outputs {
        profile.output.verify_inputs(
            output.proof,
            &inputs(&sha(&[&output_statement(profile.context.domain, output)])),
        )?;
    }
    let mut journal = [0; JOURNAL_LEN];
    journal[..8].copy_from_slice(b"KPBAJR01");
    journal[8..40].copy_from_slice(&profile.context.domain);
    journal[40..72].copy_from_slice(&profile.sha);
    journal[72..].copy_from_slice(&sha(&[raw]));
    Ok(journal)
}
#[cfg(not(target_os = "zkvm"))]
fn reference(key: &VerifyingKey<Bn254>, raw: &[u8], public: &[Fr]) -> Result<()> {
    use ark_groth16::{prepare_verifying_key, Groth16, Proof};
    let mut rest = raw;
    let proof = Proof::<Bn254>::deserialize_compressed(&mut rest)
        .map_err(|_| "reference_proof_encoding")?;
    let mut canonical = Vec::new();
    proof
        .serialize_compressed(&mut canonical)
        .map_err(|_| "reference_proof_encoding")?;
    need(
        rest.is_empty()
            && canonical == raw
            && !proof.a.is_zero()
            && !proof.b.is_zero()
            && !proof.c.is_zero(),
        "reference_proof_canonical",
    )?;
    need(
        Groth16::<Bn254>::verify_proof(&prepare_verifying_key(key), &proof, public)
            .map_err(|_| "reference_pairing")?,
        "reference_proof_invalid",
    )
}
#[cfg(not(target_os = "zkvm"))]
pub fn evaluate_reference(raw: &[u8]) -> Result<[u8; JOURNAL_LEN]> {
    let profile = Profile::installed()?;
    let journal = evaluate_with_profile(raw, &profile)?;
    let projection = Projection::parse(raw, &profile.context)?;
    reference(
        &profile.aggregate_key,
        projection.body.aggregate_proof,
        &inputs(&sha(&[&projection.body.raw[..BODY_CORE_LEN]])),
    )?;
    for output in &projection.body.outputs {
        reference(
            &profile.output_key,
            output.proof,
            &inputs(&sha(&[&output_statement(profile.context.domain, output)])),
        )?;
    }
    Ok(journal)
}
