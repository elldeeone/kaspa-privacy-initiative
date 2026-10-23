//! Public source/byte emitter only. No signer, prover, RPC or funding operation.
mod policy;
#[allow(dead_code)]
mod baseline_policy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    state_hex112: String,
    compact_vk_hex328: String,
    wide_vk_hex328: String,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input=String::new(); io::stdin().read_to_string(&mut input)?;
    let request: Request=serde_json::from_str(&input)?;
    let state: [u8;112]=hex::decode(request.state_hex112)?.try_into().map_err(|_|"State112 length")?;
    let compact=hex::decode(request.compact_vk_hex328)?;
    let wide=hex::decode(request.wide_vk_hex328)?;
    let redeem=match request.operation.as_str() {
        "emit-new-do-not-fund" => policy::redeem(&state,&compact,&wide)?,
        "emit-original-baseline" => baseline_policy::redeem(&state,&compact)?,
        _ => return Err("public emitter operation".into()),
    };
    let witness=policy::witness(&[0;65],&[0;128],&redeem)?;
    println!("{}",serde_json::json!({
        "classification":"PUBLIC_NATIVE_ONLY_DO_NOT_FUND_NO_MATCHED_CIRCUIT",
        "operation":request.operation,
        "redeem_hex":hex::encode(&redeem),"redeem_bytes":redeem.len(),
        "redeem_sha256":hex::encode(Sha256::digest(&redeem)),
        "zero_signature_zero_proof_witness_hex":hex::encode(witness),
        "new_domain_hex":hex::encode(policy::DOMAIN),
        "role_vk_sha256":{"compact":hex::encode(Sha256::digest(&compact)),"wide":hex::encode(Sha256::digest(&wide))},
        "financial_positive":false,"circuit_implemented":false
    })); Ok(())
}
