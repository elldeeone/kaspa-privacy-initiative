//! Independent candidate encoder for byte-for-byte interoperability checks.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, fs};

// Typed parsing detects duplicate JSON fields before Value would discard them.
// The original Value's exact-key checks also reject missing optional fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Intent {
    #[serde(rename = "G_hash")]
    genesis: String,
    #[serde(rename = "D")]
    domain: String,
    network_genesis: String,
    pool_id: String,
    lane_id: String,
    statement_id: String,
    proof_suite_id: String,
    wallet_program_or_vk_hash: String,
    operation_kind: u8,
    append_mode: u8,
    expiry_order_bound: Option<u64>,
    anchor: String,
    nf: [String; 2],
    cmx_new: [String; 2],
    ephemeral_key: [String; 2],
    ciphertext: [String; 2],
    deposit_reference: Option<Deposit>,
    deposit_principal: u64,
    exit_script: Option<Script>,
    exit_principal: u64,
    fee_script: Option<Script>,
    private_fee_sompi: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Deposit {
    transaction_id: String,
    index: u32,
    descriptor_hash: String,
    recovery_public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Script {
    version: u16,
    script: String,
}

const IDS: [&str; 8] = [
    "G_hash",
    "D",
    "network_genesis",
    "pool_id",
    "lane_id",
    "statement_id",
    "proof_suite_id",
    "wallet_program_or_vk_hash",
];
fn keys(v: &Value, names: &[&str]) -> Result<()> {
    let got: BTreeSet<_> = v
        .as_object()
        .context("object")?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        got == names.iter().copied().collect(),
        "exact fields required"
    );
    Ok(())
}
fn number(v: &Value, width: usize) -> Result<Vec<u8>> {
    let value = v.as_u64().context("unsigned integer")?;
    ensure!(width == 8 || value < 1u64 << (width * 8), "integer range");
    Ok(value.to_le_bytes()[..width].to_vec())
}
fn blob(v: &Value, length: usize) -> Result<Vec<u8>> {
    let text = v.as_str().context("hex string")?;
    ensure!(
        text.len() == length * 2
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "canonical hex/length"
    );
    Ok(hex::decode(text)?)
}
fn script(v: &Value) -> Result<Vec<u8>> {
    if v.is_null() {
        return Ok(vec![0]);
    }
    keys(v, &["version", "script"])?;
    let text = v["script"].as_str().context("script")?;
    ensure!(
        text.len() % 2 == 0 && (2..=20000).contains(&text.len()),
        "script size"
    );
    let mut out = vec![1];
    out.extend(number(&v["version"], 2)?);
    out.extend(u32::try_from(text.len() / 2)?.to_le_bytes());
    out.extend(blob(&v["script"], text.len() / 2)?);
    Ok(out)
}
fn encode(v: &Value) -> Result<Vec<u8>> {
    let fields: Vec<_> = IDS
        .into_iter()
        .chain([
            "operation_kind",
            "append_mode",
            "expiry_order_bound",
            "anchor",
            "nf",
            "cmx_new",
            "ephemeral_key",
            "ciphertext",
            "deposit_reference",
            "deposit_principal",
            "exit_script",
            "exit_principal",
            "fee_script",
            "private_fee_sompi",
        ])
        .collect();
    keys(v, &fields)?;
    let mut out = b"KPI/private-payment/intent/v1".to_vec();
    for name in IDS {
        out.extend(blob(&v[name], if name == "lane_id" { 20 } else { 32 })?)
    }
    let kind = v["operation_kind"].as_u64().context("kind")?;
    let mode = v["append_mode"].as_u64().context("mode")?;
    ensure!(kind <= 2 && mode <= 1, "unknown enum");
    out.extend([u8::try_from(kind)?, u8::try_from(mode)?]);
    if v["expiry_order_bound"].is_null() {
        out.push(0)
    } else {
        out.push(1);
        out.extend(number(&v["expiry_order_bound"], 8)?)
    }
    out.extend(blob(&v["anchor"], 32)?);
    for (name, size) in [
        ("nf", 32),
        ("cmx_new", 32),
        ("ephemeral_key", 32),
        ("ciphertext", 580),
    ] {
        let slots = v[name].as_array().context("slots")?;
        ensure!(slots.len() == 2, "two slots required");
        for value in slots {
            out.extend(blob(value, size)?)
        }
    }
    let deposit = &v["deposit_reference"];
    if deposit.is_null() {
        out.push(0)
    } else {
        keys(
            deposit,
            &[
                "transaction_id",
                "index",
                "descriptor_hash",
                "recovery_public_key",
            ],
        )?;
        out.push(1);
        out.extend(blob(&deposit["transaction_id"], 32)?);
        out.extend(number(&deposit["index"], 4)?);
        out.extend(blob(&deposit["descriptor_hash"], 32)?);
        out.extend(blob(&deposit["recovery_public_key"], 32)?);
    }
    out.extend(number(&v["deposit_principal"], 8)?);
    out.extend(script(&v["exit_script"])?);
    out.extend(number(&v["exit_principal"], 8)?);
    out.extend(script(&v["fee_script"])?);
    out.extend(number(&v["private_fee_sompi"], 8)?);
    let p = v["deposit_principal"].as_u64().unwrap();
    let x = v["exit_principal"].as_u64().unwrap();
    let fee = v["private_fee_sompi"].as_u64().unwrap();
    ensure!(
        v["fee_script"].is_null() == (fee == 0),
        "fee presence mismatch"
    );
    match kind {
        0 => ensure!(
            !deposit.is_null()
                && p > 0
                && v["exit_script"].is_null()
                && x == 0
                && fee == 0
                && mode == 0,
            "CREDIT fields"
        ),
        1 => ensure!(
            deposit.is_null() && p == 0 && v["exit_script"].is_null() && x == 0 && mode == 0,
            "TRANSFER fields"
        ),
        2 => ensure!(
            deposit.is_null() && p == 0 && !v["exit_script"].is_null() && x > 0,
            "EXIT fields"
        ),
        _ => unreachable!(),
    }
    Ok(out)
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() == 2, "JSON_INPUT");
    let raw = fs::read(&a[1])?;
    let _: Intent = serde_json::from_slice(&raw)?;
    let value: Value = serde_json::from_slice(&raw)?;
    println!("{}", hex::encode(encode(&value)?));
    Ok(())
}
