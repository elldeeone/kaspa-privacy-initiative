//! Public two-role policy/GN bytes only. No PK, seed, prover, signer or network.
mod policy;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Request {
    #[serde(rename = "emit")]
    Emit {
        state_hex112: String,
        compact_vk_hex328: String,
        wide_vk_hex328: String,
    },
    #[serde(rename = "genesis")]
    Genesis {
        note_hex168: String,
        cipher_hex264: String,
        compact_vk_hex328: String,
        wide_vk_hex328: String,
    },
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 || !value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err("CANONICAL_HEX_WIDTH");
    }
    let mut out = [0; N];
    hex::decode_to_slice(value, &mut out).map_err(|_| "CANONICAL_HEX_WIDTH")?;
    Ok(out)
}

fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}

fn execute(request: Request) -> Result<serde_json::Value, &'static str> {
    let (state, compact, wide, genesis) = match request {
        Request::Emit { state_hex112, compact_vk_hex328, wide_vk_hex328 } => (
            fixed::<112>(&state_hex112)?, fixed::<328>(&compact_vk_hex328)?,
            fixed::<328>(&wide_vk_hex328)?, None),
        Request::Genesis { note_hex168, cipher_hex264, compact_vk_hex328, wide_vk_hex328 } => {
            let note = fixed::<168>(&note_hex168)?;
            let cipher = fixed::<264>(&cipher_hex264)?;
            let value = u64::from_le_bytes(note[64..72].try_into().map_err(|_| "GENESIS_VALUE")?);
            if !(policy::NOTE_FLOOR as u64..=policy::MAX as u64).contains(&value) {
                return Err("GENESIS_VALUE");
            }
            let payload = [b"KPX2GN01".as_slice(), policy::DOMAIN.as_slice(), note.as_slice(),
                policy::note_cm(&note).as_slice(), cipher.as_slice(), hash(&cipher).as_slice()].concat();
            if payload.len() != 536 { return Err("GENESIS_PAYLOAD"); }
            (policy::singleton_state(&note), fixed::<328>(&compact_vk_hex328)?,
             fixed::<328>(&wide_vk_hex328)?, Some((payload, value)))
        }
    };
    let redeem = policy::redeem(&state, &compact, &wide).map_err(|_| "SELECTED_DOMAIN_ROLES_OR_PROGRAM")?;
    let witness = policy::witness(&[0; 65], &[0; 128], &redeem).map_err(|_| "WITNESS_FRAME")?;
    let mut result = json!({
        "schema":"kpx4-compact-batch-native-bytes/v1",
        "classification":"LOCAL_SYNTHETIC_RESEARCH_BYTES_NO_ACCEPTED_BACKING_OR_FUNDING_AUTHORITY",
        "domain_hex32":hex::encode(policy::DOMAIN), "state_hex112":hex::encode(state),
        "redeem_hex":hex::encode(&redeem), "redeem_bytes":redeem.len(),
        "redeem_sha256":hex::encode(hash(&redeem)),
        "zero_signature_zero_proof_witness_hex":hex::encode(witness),
        "compact_vk_sha256":hex::encode(hash(&compact)), "wide_vk_sha256":hex::encode(hash(&wide)),
        "private_witness_or_PK_or_seed_read":false, "signing_network_or_broadcast":false
    });
    if let Some((payload, value)) = genesis {
        result["payload_hex536"] = hex::encode(payload).into();
        result["reserve_sompi"] = value.into();
    }
    Ok(result)
}

fn main() {
    let result = (|| {
        let mut raw = Vec::new();
        io::stdin().take(1_048_577).read_to_end(&mut raw).map_err(|_| "STDIN")?;
        if raw.len() > 1_048_576 { return Err("PUBLIC_REQUEST_LIMIT"); }
        let shape: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| "PUBLIC_REQUEST")?;
        if !shape.is_object() { return Err("PUBLIC_REQUEST_OBJECT"); }
        let request = serde_json::from_slice(&raw).map_err(|_| "PUBLIC_REQUEST")?;
        execute(request)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(reason) => { eprintln!("{reason}"); std::process::exit(1); }
    }
}
