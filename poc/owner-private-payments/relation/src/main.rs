//! Fixed boundary: no private values in argv, diagnostics or public results.
use kpi_owner_private_relation::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::Path};
fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Encoding);
    }
    let mut b = [0; N];
    hex::decode_to_slice(s, &mut b).map_err(|_| Error::Encoding)?;
    Ok(b)
}
fn decimal(s: &str) -> Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(Error::Request);
    }
    s.parse().map_err(|_| Error::Request)
}
fn flags(args: &[String], names: &[&str]) -> Result<BTreeMap<String, String>> {
    if args.len() != names.len() * 2 {
        return Err(Error::Request);
    }
    let mut out = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !names.contains(&pair[0].as_str())
            || out.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(Error::Request);
        }
    }
    Ok(out)
}
fn input<T: serde::de::DeserializeOwned>() -> Result<T> {
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take((request::MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| Error::Io)?;
    if raw.len() > request::MAX_REQUEST_BYTES {
        return Err(Error::Request);
    }
    let v: Value = serde_json::from_slice(&raw).map_err(|_| Error::Request)?;
    if !v.is_object() {
        return Err(Error::Request);
    }
    // Parse original bytes again so duplicate fields remain detectable.
    serde_json::from_slice(&raw).map_err(|_| Error::Request)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitRequest {
    schema: String,
    value_sompi: String,
    blind_hex32: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BalanceRequest {
    schema: String,
    input_cv_hex64: Vec<String>,
    output_cv_hex64: Vec<String>,
    fee_sompi: String,
    delta_hex32: String,
}
fn run() -> Result<Value> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    let op = a.first().ok_or(Error::Request)?.as_str();
    match op {
        "public-info" => {
            if a.len() != 1 {
                return Err(Error::Request);
            }
            let (v, r) = generators_bytes();
            Ok(
                json!({"schema":"kpx7-owner-private-public-info/v1","domain_hex32":hex::encode(DOMAIN),"value_generator_hex64":hex::encode(v),"blinding_generator_hex64":hex::encode(r),"curve_parameters_sha256":hex::encode(parameter_powers_digest()),"scalar_modulus_decimal":cv::SCALAR_MODULUS_DECIMAL,"note_floor_sompi":NOTE_FLOOR.to_string(),"max_value_sompi":MAX.to_string(),"spend_statement_bytes":200,"output_statement_bytes":168,"output_tuple_bytes":520,"vk_bytes":328,"proof_bytes":128}),
            )
        }
        "commit" => {
            if a.len() != 1 {
                return Err(Error::Request);
            }
            let q: CommitRequest = input()?;
            if q.schema != "kpx7-private-value-commitment/v1" {
                return Err(Error::Request);
            }
            Ok(
                json!({"cv_hex64":hex::encode(value_commitment(decimal(&q.value_sompi)?,&fixed::<32>(&q.blind_hex32)?)?)}),
            )
        }
        "balance" => {
            if a.len() != 1 {
                return Err(Error::Request);
            }
            let q: BalanceRequest = input()?;
            if q.schema != "kpx7-public-value-balance/v1" {
                return Err(Error::Request);
            }
            let i = q
                .input_cv_hex64
                .iter()
                .map(|s| fixed::<64>(s))
                .collect::<Result<Vec<_>>>()?;
            let o = q
                .output_cv_hex64
                .iter()
                .map(|s| fixed::<64>(s))
                .collect::<Result<Vec<_>>>()?;
            Ok(
                json!({"balanced":check_balance(&i,&o,decimal(&q.fee_sompi)?,&fixed::<32>(&q.delta_hex32)?)?}),
            )
        }
        "shape" => {
            if a.len() != 2 {
                return Err(Error::Request);
            }
            let role = Role::parse(&a[1])?;
            let (s, o) = circuit::fixture();
            let (shape, satisfied) = match role {
                Role::Spend => circuit::check(s)?,
                Role::Output => circuit::check(o)?,
            };
            Ok(
                json!({"schema":"kpx7-public-synthetic-relation-shape/v1","role":role.name(),"domain_hex32":hex::encode(DOMAIN),"shape":shape,"satisfied":satisfied,"financial_authority":false}),
            )
        }
        "setup" => {
            if a.len() != 3 {
                return Err(Error::Request);
            }
            let role = Role::parse(&a[1])?;
            let m = keys::setup(role, Path::new(&a[2]))?;
            let raw =
                std::fs::read(Path::new(&a[2]).join("manifest.json")).map_err(|_| Error::Io)?;
            Ok(
                json!({"manifest":m,"manifest_sha256":hex::encode(hash(&[&raw])),"financial_authority":false}),
            )
        }
        "verify-spend" | "verify-output" => {
            let f = flags(&a[1..], &["--vk", "--statement", "--proof"])?;
            let role = if op == "verify-spend" {
                Role::Spend
            } else {
                Role::Output
            };
            let v = Verifier::new(&fixed::<328>(&f["--vk"])?, role)?;
            let p = fixed::<128>(&f["--proof"])?;
            let yes = match role {
                Role::Spend => v.verify_spend(
                    &SpendStatement::parse(&fixed::<200>(&f["--statement"])?)?,
                    &p,
                )?,
                Role::Output => v.verify_output(
                    &OutputStatement::parse(&fixed::<168>(&f["--statement"])?)?,
                    &p,
                )?,
            };
            Ok(json!({"verified":yes}))
        }
        "prove-spend" | "prove-output" => {
            let f = flags(
                &a[1..],
                &[
                    "--pk",
                    "--pk-sha256",
                    "--manifest",
                    "--manifest-sha256",
                    "--statement",
                ],
            )?;
            let role = if op == "prove-spend" {
                Role::Spend
            } else {
                Role::Output
            };
            // This entire operation completes before opening/reading private stdin.
            let (pk, manifest) = keys::load(
                role,
                Path::new(&f["--pk"]),
                &f["--pk-sha256"],
                Path::new(&f["--manifest"]),
                &f["--manifest-sha256"],
            )?;
            let executable = std::fs::read(std::env::current_exe().map_err(|_| Error::Io)?)
                .map_err(|_| Error::Io)?;
            if hex::encode(hash(&[&executable])) != manifest.executable_sha256 {
                return Err(Error::Parameters);
            }
            let mut stdin = std::io::stdin().lock();
            let proof = match role {
                Role::Spend => {
                    let statement = SpendStatement::parse(&fixed::<200>(&f["--statement"])?)?;
                    let witness = request::read_spend(&mut stdin)?;
                    keys::prove_spend(&pk, SpendCircuit { statement, witness })?
                }
                Role::Output => {
                    let statement = OutputStatement::parse(&fixed::<168>(&f["--statement"])?)?;
                    let witness = request::read_output(&mut stdin)?;
                    keys::prove_output(&pk, OutputCircuit { statement, witness })?
                }
            };
            Ok(
                json!({"schema":"kpx7-owner-private-component-proof/v1","role":role.name(),"statement_hex":f["--statement"],"proof_hex128":hex::encode(proof),"genuine_proof_verified":true}),
            )
        }
        _ => Err(Error::Request),
    }
}
fn main() {
    match run() {
        Ok(v) => println!("{v}"),
        Err(_) => {
            eprintln!("owner-private-operation-refused");
            std::process::exit(2)
        }
    }
}
