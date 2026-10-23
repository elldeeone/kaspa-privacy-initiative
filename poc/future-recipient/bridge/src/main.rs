//! Narrow adapter to established crypto implementations. Requests use stdin so
//! key material is never placed in process arguments. This is an offline PoC.
use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use secp256k1::{Keypair, Secp256k1};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    #[serde(default)]
    secret_hex: String,
    #[serde(default)]
    public_hex: String,
    #[serde(default)]
    payload_hex: String,
}

fn fixed_hex(s: &str) -> Result<[u8; 32], &'static str> {
    let bytes = hex::decode(s).map_err(|_| "hex")?;
    bytes.try_into().map_err(|_| "length")
}

fn execute(req: Request) -> Result<serde_json::Value, &'static str> {
    match req.op.as_str() {
        "derive-xonly" => {
            let raw = fixed_hex(&req.secret_hex)?;
            let key = secp256k1::SecretKey::from_slice(&raw).map_err(|_| "scalar")?;
            let pair = Keypair::from_secret_key(&Secp256k1::new(), &key);
            Ok(json!({"hex": hex::encode(pair.x_only_public_key().0.serialize())}))
        }
        "derive-delivery" => {
            let key = SecretKey::from(fixed_hex(&req.secret_hex)?);
            Ok(json!({"hex": hex::encode(key.public_key().as_bytes())}))
        }
        "seal" => {
            let key = PublicKey::from(fixed_hex(&req.public_hex)?);
            let raw = hex::decode(&req.payload_hex).map_err(|_| "hex")?;
            let encrypted = key.seal(&mut OsRng, &raw).map_err(|_| "seal")?;
            Ok(json!({"hex": hex::encode(encrypted)}))
        }
        "unseal" => {
            let key = SecretKey::from(fixed_hex(&req.secret_hex)?);
            let raw = hex::decode(&req.payload_hex).map_err(|_| "hex")?;
            let decrypted = key.unseal(&raw).map_err(|_| "unseal")?;
            Ok(json!({"hex": hex::encode(decrypted)}))
        }
        _ => Err("operation"),
    }
}

fn main() {
    let mut request = String::new();
    let result = io::stdin()
        .read_to_string(&mut request)
        .map_err(|_| "stdin")
        .and_then(|_| serde_json::from_str(&request).map_err(|_| "request"))
        .and_then(execute);
    match result {
        Ok(value) => println!("{value}"),
        Err(reason) => {
            // Stable error categories; never echo requests, plaintext or keys.
            println!("{}", json!({"error": reason}));
            std::process::exit(1);
        }
    }
}
