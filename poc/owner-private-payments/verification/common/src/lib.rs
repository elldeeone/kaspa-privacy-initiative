//! New ADR0063 public financial predicate; no owner openings, keys or networking.
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
mod g16;
use g16::Verifier;
use kpi_owner_private_relation as relation;
use serde::Deserialize;
use sha2::{Digest, Sha256};
pub mod wire;
pub use wire::{Body, Projection, BODY_CORE_LEN, BODY_LEN, PREFIX_LEN, PROJECTION_LEN};
pub type H = [u8; 32];
pub type Result<T> = std::result::Result<T, &'static str>;
pub const JOURNAL_LEN: usize = 104;
pub const DOMAIN: H = [
    0x32, 0xb4, 0xf3, 0x1a, 0x58, 0xcc, 0x52, 0xd2, 0x28, 0x62, 0xc2, 0x0a, 0x92, 0x3c, 0x59, 0xcd,
    0xd0, 0x12, 0x77, 0x85, 0xe9, 0x99, 0x8f, 0x63, 0x2e, 0xae, 0x2b, 0x3b, 0xb3, 0x19, 0x91, 0x9d,
];
pub fn need(ok: bool, e: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(e)
    }
}
pub fn sha(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn decode<const N: usize>(s: &str) -> Result<[u8; N]> {
    need(
        s.len() == 2 * N
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "profile_hex",
    )?;
    let mut b = [0; N];
    hex::decode_to_slice(s, &mut b).map_err(|_| "profile_hex")?;
    Ok(b)
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
    domain_hex32: String,
    spend: RoleFile,
    output: RoleFile,
    value_generator_hex64: String,
    blinding_generator_hex64: String,
    curve_parameters_sha256: String,
    spend_count: u16,
    output_count: u16,
    note_floor_sompi: u64,
    max_value_sompi: u64,
    body_bytes: usize,
    journal_bytes: usize,
}
pub struct Profile {
    pub sha: H,
    pub spend_vk_sha: H,
    pub output_vk_sha: H,
    spend: Verifier,
    output: Verifier,
}
fn key(f: &RoleFile) -> Result<(Verifier, H)> {
    decode::<32>(&f.parameter_manifest_sha256)?;
    let raw = decode::<328>(&f.vk_hex328)?;
    let digest = decode(&f.vk_sha256)?;
    need(sha(&[&raw]) == digest, "profile_key_digest")?;
    let mut rest = raw.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut rest)
        .map_err(|_| "profile_key_decode")?;
    let mut encoded = Vec::new();
    vk.serialize_compressed(&mut encoded)
        .map_err(|_| "profile_key_encode")?;
    need(
        rest.is_empty()
            && encoded == raw
            && vk.gamma_abc_g1.len() == 3
            && !vk.alpha_g1.is_zero()
            && !vk.beta_g2.is_zero()
            && !vk.gamma_g2.is_zero()
            && !vk.delta_g2.is_zero()
            && vk.gamma_abc_g1.iter().all(|p| !p.is_zero()),
        "profile_key_canonical_or_arity",
    )?;
    Ok((Verifier::from_validated_key(&vk), digest))
}
impl Profile {
    pub fn installed() -> Result<Self> {
        Self::parse(include_bytes!("../../component-profile.json"))
    }
    fn parse(raw: &[u8]) -> Result<Self> {
        let f: ProfileFile = serde_json::from_slice(raw).map_err(|_| "profile_json")?;
        need(
            f.selected
                && f.schema == "kpx7-owner-private-component-profile/v1"
                && f.classification == "UNFUNDED_RESEARCH_ONLY_ADR0063"
                && decode::<32>(&f.domain_hex32)? == DOMAIN
                && relation::DOMAIN == DOMAIN
                && f.spend_count == 3
                && f.output_count == 6
                && f.note_floor_sompi == wire::FLOOR
                && f.max_value_sompi == wire::MAX
                && f.body_bytes == BODY_LEN
                && f.journal_bytes == JOURNAL_LEN,
            "profile_identity",
        )?;
        let (v, r) = relation::generators_bytes();
        need(
            decode::<64>(&f.value_generator_hex64)? == v
                && decode::<64>(&f.blinding_generator_hex64)? == r
                && decode::<32>(&f.curve_parameters_sha256)? == relation::parameter_powers_digest(),
            "profile_generators",
        )?;
        let _ = relation::point_from_bytes(&v).map_err(|_| "profile_value_generator")?;
        let _ = relation::point_from_bytes(&r).map_err(|_| "profile_blind_generator")?;
        // A strict scalar decoder proves this public absolute integer bound is
        // below q. Genuine component proofs separately range-constrain values.
        let bound = 10u128
            .checked_mul(u128::from(wire::MAX))
            .ok_or("antiwrap_bound")?;
        let mut bounded = [0u8; 32];
        bounded[..16].copy_from_slice(&bound.to_le_bytes());
        relation::scalar_from_bytes(&bounded).map_err(|_| "antiwrap_bound")?;
        let (spend, spend_vk_sha) = key(&f.spend)?;
        let (output, output_vk_sha) = key(&f.output)?;
        need(spend_vk_sha != output_vk_sha, "distinct_relation_keys")?;
        Ok(Self {
            sha: sha(&[raw]),
            spend_vk_sha,
            output_vk_sha,
            spend,
            output,
        })
    }
    fn verify(v: &Verifier, statement: &[u8], proof: &[u8]) -> Result<()> {
        let d = sha(&[statement]);
        let inputs = [
            Fr::from_le_bytes_mod_order(&d[..16]),
            Fr::from_le_bytes_mod_order(&d[16..]),
        ];
        v.verify_inputs(proof, &inputs)
    }
}
pub fn public_parameters() -> ([u8; 64], [u8; 64], H) {
    let (v, r) = relation::generators_bytes();
    (v, r, relation::parameter_powers_digest())
}
/// Host-side differential check against the relation crate's standard Arkworks
/// pairing verifier. The guest uses the accelerated standard equation above.
#[cfg(not(target_os = "zkvm"))]
pub fn evaluate_reference(raw: &[u8]) -> Result<[u8; JOURNAL_LEN]> {
    let journal = evaluate(raw)?;
    let p = Projection::parse(raw)?;
    let effects = wire::effects_digest(&p);
    let f: ProfileFile = serde_json::from_slice(include_bytes!("../../component-profile.json"))
        .map_err(|_| "profile_json")?;
    let spend = relation::Verifier::new(&decode::<328>(&f.spend.vk_hex328)?, relation::Role::Spend)
        .map_err(|_| "reference_spend_key")?;
    let output =
        relation::Verifier::new(&decode::<328>(&f.output.vk_hex328)?, relation::Role::Output)
            .map_err(|_| "reference_output_key")?;
    for o in &p.body.outputs {
        let statement = relation::OutputStatement {
            domain: DOMAIN,
            cm: o.cm,
            cv: o.cv,
            cf_hash: o.cfh,
        };
        need(
            output
                .verify_output(&statement, o.proof)
                .map_err(|_| "reference_output_encoding")?,
            "reference_output_invalid",
        )?;
    }
    for s in &p.body.spends {
        let statement = relation::SpendStatement {
            domain: DOMAIN,
            anchor: p.body.old.cm,
            nf: s.nf,
            cv: s.cv,
            effects_digest: effects,
        };
        need(
            spend
                .verify_spend(&statement, s.proof)
                .map_err(|_| "reference_spend_encoding")?,
            "reference_spend_invalid",
        )?;
    }
    Ok(journal)
}
pub fn evaluate(raw: &[u8]) -> Result<[u8; JOURNAL_LEN]> {
    let profile = Profile::installed()?;
    let p = Projection::parse(raw)?;
    wire::validate_transition(&p)?;
    let b = &p.body;
    let effects = wire::effects_digest(&p);
    let ins: Vec<_> = b.spends.iter().map(|s| s.cv).collect();
    let outs: Vec<_> = b.outputs.iter().map(|o| o.cv).collect();
    need(
        relation::check_balance(&ins, &outs, b.fee, &b.delta)
            .map_err(|_| "curve_scalar_or_balance_encoding")?,
        "global_group_balance",
    )?;
    for o in &b.outputs {
        let statement = relation::OutputStatement {
            domain: DOMAIN,
            cm: o.cm,
            cv: o.cv,
            cf_hash: o.cfh,
        };
        Profile::verify(&profile.output, &statement.bytes(), o.proof)?;
    }
    for s in &b.spends {
        let statement = relation::SpendStatement {
            domain: DOMAIN,
            anchor: b.old.cm,
            nf: s.nf,
            cv: s.cv,
            effects_digest: effects,
        };
        Profile::verify(&profile.spend, &statement.bytes(), s.proof)?;
    }
    let mut j = [0u8; JOURNAL_LEN];
    j[..8].copy_from_slice(b"KPX7JR01");
    j[8..40].copy_from_slice(&DOMAIN);
    j[40..72].copy_from_slice(&profile.sha);
    j[72..104].copy_from_slice(&sha(&[raw]));
    Ok(j)
}
