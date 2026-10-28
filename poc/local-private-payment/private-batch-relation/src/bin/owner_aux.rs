//! Isolated ONE-owner input preparation. No controller/combined witness mode.
//! Private material is never printed; the sole private output is create-new0600.
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use kpi_private_batch_relation::{
    Context, Note, OutputWitness, OwnerWitness, Profile, owner_local, wire,
};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

type R<T> = Result<T, &'static str>;
// Same strict recursive parser as the retained public emitter; duplicates must
// be rejected before interpreting a typed request or owner record.
struct Unique(Value);
struct UniqueVisitor;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor)
    }
}
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with unique keys")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("finite number"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<Unique>()? {
            out.push(v.0)
        }
        Ok(Unique(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            out.insert(key, map.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(out)))
    }
}
fn json_unique(raw: &[u8]) -> R<Value> {
    serde_json::from_slice::<Unique>(raw)
        .map(|v| v.0)
        .map_err(|_| "JSON_UNIQUE_KEYS")
}
fn need(ok: bool, code: &'static str) -> R<()> {
    if ok { Ok(()) } else { Err(code) }
}
fn at<'a>(v: &'a Value, key: &str) -> R<&'a Value> {
    v.get(key).ok_or("MISSING_FIELD")
}
fn text(v: &Value) -> R<&str> {
    v.as_str().ok_or("STRING")
}
fn uint(v: &Value) -> R<u64> {
    v.as_u64().ok_or("UINT")
}
fn canonical_field(v: &Value, modulus: &str) -> R<()> {
    let s = text(v)?;
    need(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0')),
        "CANONICAL_DECIMAL",
    )?;
    need(
        s.len() < modulus.len() || (s.len() == modulus.len() && s < modulus),
        "DECIMAL_FIELD_RANGE",
    )
}
fn decimal_array(v: &Value, count: usize, modulus: &str) -> R<()> {
    let a = v.as_array().ok_or("ARRAY")?;
    need(a.len() == count, "ARRAY_LENGTH")?;
    for x in a {
        canonical_field(x, modulus)?;
    }
    Ok(())
}
fn keys(v: &Value, required: &[&str], optional: &[&str]) -> R<()> {
    let o = v.as_object().ok_or("OBJECT")?;
    need(
        required.iter().all(|k| o.contains_key(*k))
            && o.keys()
                .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str())),
        "OBJECT_KEYS",
    )
}
fn bytes<const N: usize>(v: &Value) -> R<[u8; N]> {
    let s = text(v)?;
    need(
        s.len() == N * 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "CANONICAL_HEX",
    )?;
    hex::decode(s)
        .map_err(|_| "HEX")?
        .try_into()
        .map_err(|_| "HEX_LENGTH")
}
fn file(v: &Value, base: &Path) -> R<PathBuf> {
    let p = PathBuf::from(text(v)?);
    Ok(if p.is_absolute() { p } else { base.join(p) })
}
fn load(p: &Path) -> R<Vec<u8>> {
    fs::read(p).map_err(|_| "INPUT_FILE")
}
fn context(raw: [u8; 276]) -> Context {
    Context {
        profile: Profile {
            chain_genesis: raw[0..32].try_into().unwrap(),
            pool_lineage: raw[32..64].try_into().unwrap(),
            wallet_profile: raw[64..96].try_into().unwrap(),
            domain: raw[96..128].try_into().unwrap(),
            service_policy: raw[128..160].try_into().unwrap(),
        },
        reserve_outpoint: raw[160..196].try_into().unwrap(),
        old_cm_root: raw[196..228].try_into().unwrap(),
        old_nf_root: raw[228..260].try_into().unwrap(),
        old_cm_count: u32::from_le_bytes(raw[260..264].try_into().unwrap()),
        old_nf_count: u32::from_le_bytes(raw[264..268].try_into().unwrap()),
        old_reserve: u64::from_le_bytes(raw[268..276].try_into().unwrap()),
    }
}
fn record(v: &Value, ctx: &Context) -> R<OwnerWitness> {
    keys(
        v,
        &[
            "input",
            "fee_sompi",
            "nonce_hex32",
            "outputs",
            "private_delta_hex32",
            "intent_hex1460",
            "signature",
            "signature_inputs",
        ],
        &["schema", "owner_component"],
    )?;
    let input = at(v, "input")?;
    keys(
        input,
        &[
            "note_hex168",
            "nk_hex32",
            "position",
            "path_hex32",
            "cv_hex64",
            "blind_hex32",
            "ak_hex64",
            "nf_hex32",
        ],
        &[],
    )?;
    let path = at(input, "path_hex32")?.as_array().ok_or("PATH_ARRAY")?;
    need(path.len() == 16, "PATH_LENGTH")?;
    let path = path
        .iter()
        .map(bytes::<32>)
        .collect::<R<Vec<_>>>()?
        .try_into()
        .map_err(|_| "PATH_LENGTH")?;
    let output = at(v, "outputs")?.as_array().ok_or("OUTPUT_ARRAY")?;
    need(output.len() == 2, "OUTPUT_COUNT")?;
    let output = output
        .iter()
        .map(|o| {
            keys(o, &["tuple_hex520", "note_hex168", "blind_hex32"], &[])?;
            Ok(OutputWitness {
                note: Note::parse(&bytes::<168>(at(o, "note_hex168")?)?).map_err(|_| "NOTE")?,
                blinding: bytes(at(o, "blind_hex32")?)?,
                tuple: bytes(at(o, "tuple_hex520")?)?,
            })
        })
        .collect::<R<Vec<_>>>()?;
    let owner = OwnerWitness {
        input_nf: bytes(at(input, "nf_hex32")?)?,
        input_cv: bytes(at(input, "cv_hex64")?)?,
        note: Note::parse(&bytes::<168>(at(input, "note_hex168")?)?).map_err(|_| "NOTE")?,
        nullifier_secret: bytes(at(input, "nk_hex32")?)?,
        position: uint(at(input, "position")?)?
            .try_into()
            .map_err(|_| "POSITION")?,
        path,
        blinding: bytes(at(input, "blind_hex32")?)?,
        private_delta: bytes(at(v, "private_delta_hex32")?)?,
        authorization_key: bytes(at(input, "ak_hex64")?)?,
        fee_sompi: uint(at(v, "fee_sompi")?)?,
        intent_nonce: bytes(at(v, "nonce_hex32")?)?,
        outputs: output.try_into().map_err(|_| "OUTPUT_COUNT")?,
    };
    let tuples = core::array::from_fn(|i| owner.outputs[i].tuple);
    need(
        wire::intent_bytes(
            ctx,
            &owner.input_nf,
            &owner.input_cv,
            owner.fee_sompi,
            &owner.intent_nonce,
            &tuples,
        ) == bytes::<1460>(at(v, "intent_hex1460")?)?,
        "RESTRICTED_INTENT",
    )?;
    let sig = at(v, "signature")?;
    keys(sig, &["owner_key_hex64", "R8", "S"], &[])?;
    need(
        bytes::<64>(at(sig, "owner_key_hex64")?)? == owner.authorization_key,
        "SIGNATURE_AK",
    )?;
    let p = Fr::MODULUS.to_string();
    let q = kpi_private_batch_relation::cv::SCALAR_MODULUS_DECIMAL;
    decimal_array(at(sig, "R8")?, 2, &p)?;
    canonical_field(at(sig, "S")?, q)?;
    let inputs = at(v, "signature_inputs")?;
    keys(
        inputs,
        &[
            "digestLimbs",
            "ownerKeyBytes",
            "sigR8",
            "sigS",
            "preimageA",
            "preimageR8",
        ],
        &[],
    )?;
    decimal_array(at(inputs, "digestLimbs")?, 2, &p)?;
    decimal_array(at(inputs, "ownerKeyBytes")?, 64, "256")?;
    decimal_array(at(inputs, "sigR8")?, 2, &p)?;
    canonical_field(at(inputs, "sigS")?, q)?;
    decimal_array(at(inputs, "preimageA")?, 2, &p)?;
    decimal_array(at(inputs, "preimageR8")?, 2, &p)?;
    need(
        at(inputs, "sigR8")? == at(sig, "R8")? && at(inputs, "sigS")? == at(sig, "S")?,
        "SIGNATURE_RECORD_BINDING",
    )?;
    // Signature private inputs are consumed only through the real pinned
    // normalized WTNS below. No signing seed/scalar/nonce field is accepted.
    Ok(owner)
}
fn fresh(path: &Path, private: bool) -> R<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(if private { 0o600 } else { 0o644 });
    options.open(path).map_err(|_| "OUTPUT_CREATE_NEW")
}
fn run(request: &Path, private_output: &Path, public_receipt: &Path) -> R<()> {
    let req = json_unique(&load(request)?)?;
    keys(
        &req,
        &[
            "schema",
            "owner_component",
            "context_hex",
            "owner_record_path",
            "signature_matrix_path",
            "signature_witness_path",
            "expected_matrix_sha256",
            "expected_mapping_sha256",
            "expected_witness_sha256",
        ],
        &[],
    )?;
    need(
        text(at(&req, "schema")?)? == "kpi-owner-local-aux-request/v1",
        "REQUEST_SCHEMA",
    )?;
    let role: usize = uint(at(&req, "owner_component")?)?
        .try_into()
        .map_err(|_| "OWNER_COMPONENT")?;
    need(role < 3, "OWNER_COMPONENT")?;
    let ctx = context(bytes(at(&req, "context_hex")?)?);
    let base = request.parent().unwrap_or(Path::new("."));
    let owner_json = json_unique(&load(&file(at(&req, "owner_record_path")?, base)?)?)?;
    if let Some(selected) = owner_json.get("owner_component") {
        need(uint(selected)? == role as u64, "OWNER_RECORD_COMPONENT")?;
    }
    let owner = record(&owner_json, &ctx)?;
    let matrix_raw = load(&file(at(&req, "signature_matrix_path")?, base)?)?;
    let witness_raw = load(&file(at(&req, "signature_witness_path")?, base)?)?;
    let matrix_sha = text(at(&req, "expected_matrix_sha256")?)?;
    let map_sha = text(at(&req, "expected_mapping_sha256")?)?;
    let matrix = auth::interchange::signature_matrix(&matrix_raw, matrix_sha, map_sha)?;
    let n = matrix.variables().map_err(|_| "SIGNATURE_MATRIX_SHAPE")?;
    let signature = auth::interchange::signature_witness(
        &witness_raw,
        text(at(&req, "expected_witness_sha256")?)?,
        matrix_sha,
        map_sha,
        n,
    )?;
    let dot = |r: &auth::join::Row| {
        r.iter()
            .fold(Fr::ZERO, |sum, (c, i)| sum + *c * signature[*i])
    };
    need(
        (0..matrix.constraints()).all(|i| {
            dot(&matrix.matrices[0][i]) * dot(&matrix.matrices[1][i]) == dot(&matrix.matrices[2][i])
        }),
        "SIGNATURE_ROWS_UNSATISFIED",
    )?;
    let auxiliary = owner_local::generate(ctx.profile.clone(), ctx.clone(), role, owner)
        .map_err(|_| "OWNER_AUX_SYNTHESIS")?;
    let ordered = auxiliary
        .ordered_inputs_with_signature(&signature, n)
        .map_err(|_| "SIGNATURE_NATIVE_EDGES")?;
    let mut out = BufWriter::new(fresh(private_output, true)?);
    writeln!(
        out,
        "KPB_OWNER_INPUT_V1\nOWNER owner{role}\nCOUNT {}\nVALUES",
        ordered.len()
    )
    .map_err(|_| "PRIVATE_OUTPUT")?;
    for value in &ordered {
        writeln!(out, "{value}").map_err(|_| "PRIVATE_OUTPUT")?;
    }
    writeln!(out, "END").map_err(|_| "PRIVATE_OUTPUT")?;
    out.flush().map_err(|_| "PRIVATE_OUTPUT")?;
    let range = auxiliary.layout.owner_local_columns[role];
    let receipt = json!({"schema":"kpi-owner-local-aux-public-receipt/v1","owner_component":role,"context_sha256":hex::encode(Sha256::digest(ctx.bytes())),"core_variables":auxiliary.core_variables,"native_edges":66,"native_auxiliary":auxiliary.native_auxiliary().len(),"native_auxiliary_range":{"start":range.start,"end":range.end},"signature_variables":n,"signature_rows":matrix.constraints(),"signature_rows_checked":true,"signature_matrix_sha256":matrix_sha,"signature_mapping_sha256":map_sha,"ordered_private_values":ordered.len(),"private_values_output":true,"combined_dealer":false,"proof_or_mpc_claim":false});
    serde_json::to_writer_pretty(fresh(public_receipt, false)?, &receipt)
        .map_err(|_| "PUBLIC_RECEIPT")?;
    Ok(())
}
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: owner_aux REQUEST.json OWNER-PRIVATE-INPUT.txt PUBLIC-RECEIPT.json");
        std::process::exit(2)
    }
    match run(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    ) {
        Ok(()) => println!("OWNER_LOCAL_AUX_WRITTEN"),
        Err(code) => {
            eprintln!("OWNER_LOCAL_AUX_REFUSED {code}");
            std::process::exit(1)
        }
    }
}
