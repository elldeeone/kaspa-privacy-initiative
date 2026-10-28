//! Unfunded direct-AuthExit component probe. No selected payment profile exists.
//!
//! Reuse the actual native policy and codecs. The two opaque payment metadata
//! digests below cannot be supplied as selected image/component identities.
//! No aggregate key is manufactured, and the ordinary financial emitter keeps
//! its strict selected-manifest boundary unchanged.
#[path = "main.rs"]
#[allow(dead_code)]
mod codec;
use codec::policy;
mod r0_fragment;

use kaspa_txscript::pay_to_script_hash_script;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
type Result<T> = codec::policy::Result<T>;
const CLASS: &str = "UNFUNDED_EXIT_COMPONENT_ONLY_UNSELECTED_PAYMENT_METADATA";

fn fields(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("expected object")?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err("unexpected or missing component-probe field".into());
    }
    Ok(())
}

fn parameters(value: &Value) -> Result<codec::policy::Parameters> {
    fields(value, &["schema", "classification", "payment_profile_selected", "domain_hex32",
        "chain_hex32", "pool_hex32", "profile_hex32", "service_hex32", "auth_exit"])?;
    if value["schema"] != "private-batch-exit-component-parameters/v1"
        || value["classification"] != CLASS || value["payment_profile_selected"] != false {
        return Err("explicit unfunded exit-component scope required".into());
    }
    let domain = codec::array32(&value["domain_hex32"])?;
    let chain = codec::array32(&value["chain_hex32"])?;
    let pool = codec::array32(&value["pool_hex32"])?;
    let profile = codec::array32(&value["profile_hex32"])?;
    let service = codec::array32(&value["service_hex32"])?;
    if [&domain, &chain, &pool, &profile, &service].iter().any(|id| **id == [0;32]) {
        return Err("component context identity".into());
    }
    let (exit_vk, exit_digest) = codec::manifest_key(&value["auth_exit"])?;
    let mut context = Vec::new();
    for identity in [&domain, &chain, &pool, &profile, &service, &exit_digest] {
        context.extend(identity);
    }
    let opaque = |tag: &[u8]| -> [u8;32] {
        Sha256::digest([tag, context.as_slice()].concat()).into()
    };
    let selected = codec::policy::Parameters {domain, chain, pool, profile, service,
        image: opaque(b"UNSELECTED-PAYMENT-IMAGE-EXIT-PROBE01"),
        component: opaque(b"UNSELECTED-PAYMENT-COMPONENT-EXIT-PROBE01"), exit_vk};
    selected.validate()?;
    Ok(selected)
}

fn execute(value: Value) -> Result<Value> {
    let operation = value["operation"].as_str().ok_or("probe operation")?;
    let selected = parameters(&value["parameters"])?;
    let mut result = match operation {
        "emit" => {
            fields(&value, &["operation", "parameters", "state_hex112"])?;
            let state = hex::decode(value["state_hex112"].as_str().ok_or("state hex")?)?;
            let state: [u8;112] = state.try_into().map_err(|_| "state width")?;
            if value["state_hex112"] != hex::encode(state) { return Err("canonical state hex".into()); }
            let redeem = codec::policy::redeem(&state, &selected)?;
            let spk = pay_to_script_hash_script(&redeem);
            let mut encoded_spk = spk.version().to_be_bytes().to_vec();
            encoded_spk.extend(spk.script());
            json!({"schema":"private-batch-exit-component-emission/v1", "state_hex112":hex::encode(state),
                "redeem_hex":hex::encode(&redeem), "redeem_bytes":redeem.len(),
                "immutable_tail_hex":hex::encode(&redeem[114..]),
                "script_public_key":hex::encode(encoded_spk),
                "zero_proof_witness_hex":hex::encode(codec::policy::witness(&[0;128], &redeem)?),
                "opaque_unselected_payment_image_hex32":hex::encode(selected.image),
                "opaque_unselected_payment_component_hex32":hex::encode(selected.component)})
        }
        "body" | "normalize" => {
            fields(&value, &["operation", "parameters", "case"])?;
            let result = codec::body(&value["case"], &selected, operation == "normalize")?;
            if result["mode"] != "exit" { return Err("payment operation forbidden in exit-component probe".into()); }
            result
        }
        "canonicalize-control" => {
            fields(&value, &["operation", "parameters", "case"])?;
            let (tx, entries) = codec::canonicalize_case(&value["case"])?;
            json!({"schema":"private-batch-exit-component-control-canonicalization/v1",
                "case":{"transaction":tx,"entries":entries}})
        }
        _ => return Err("only direct-exit component operations are supported".into()),
    };
    let object = result.as_object_mut().ok_or("component result object")?;
    object.insert("classification".into(), CLASS.into());
    for key in ["payment_profile_selected", "aggregate_proof_selected", "native_VM_executed",
        "accepted_backing_or_chain_confirmation", "funding_or_broadcast"] {
        object.insert(key.into(), false.into());
    }
    Ok(result)
}

fn main() {
    let result = (|| -> Result<Value> {
        let mut raw = Vec::new();
        io::stdin().take(4*1024*1024+1).read_to_end(&mut raw)?;
        if raw.len() > 4*1024*1024 { return Err("component request width".into()); }
        execute(serde_json::from_slice::<codec::Unique>(&raw)?.0)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => { eprintln!("UNFUNDED_EXIT_COMPONENT_REFUSED: {error}"); std::process::exit(1); }
    }
}
