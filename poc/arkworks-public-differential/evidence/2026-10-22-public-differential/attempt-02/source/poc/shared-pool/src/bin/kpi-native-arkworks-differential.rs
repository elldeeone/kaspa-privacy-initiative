//! Actual pinned Kaspa Groth16 opcode on bounded public differential cases.
//! Standalone native script VM only: not covenant/transaction/chain validation.
use kaspa_consensus_core::{
    hashing::sighash::SigHashReusedValuesUnsync, mass::ScriptUnits, tx::PopulatedTransaction,
};
use kaspa_txscript::{
    SigCacheKey, TxScriptEngine,
    caches::Cache,
    opcodes::codes::{OpTrue, OpZkPrecompile},
    script_builder::ScriptBuilder,
};
use kpi_shared_pool::protocol::hash;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    id: String,
    vk_hex: String,
    proof_hex: String,
    inputs_hex: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema: String,
    vectors: Vec<Value>,
    statements: Vec<Statement>,
}
fn bytes(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.len() > maximum * 2 {
        return Err("predecode byte-size bound".into());
    }
    let b = hex::decode(value).map_err(|_| "hex".to_string())?;
    if hex::encode(&b) != value {
        return Err("canonical hex".into());
    }
    Ok(b)
}
fn one(s: &Statement) -> Value {
    let result: Result<Value, String> = (|| {
        let vk = bytes(&s.vk_hex, 512)?;
        let proof = bytes(&s.proof_hex, 160)?;
        if vk.len() >= 232 && u64::from_le_bytes(vk[224..232].try_into().unwrap()) > 8 {
            return Err("VK vector count bound before decode/allocation".into());
        }
        if s.inputs_hex.len() > 3 {
            return Err("public input vector bound".into());
        }
        let inputs = s
            .inputs_hex
            .iter()
            .map(|x| bytes(x, 40))
            .collect::<Result<Vec<_>, _>>()?;
        let mut builder = ScriptBuilder::new();
        for input in inputs.iter().rev() {
            builder.add_data(input).map_err(|e| e.to_string())?;
        }
        builder
            .add_i64(inputs.len() as i64)
            .map_err(|e| e.to_string())?;
        builder.add_data(&proof).map_err(|e| e.to_string())?;
        builder.add_data(&vk).map_err(|e| e.to_string())?;
        builder.add_data(&[0x20]).map_err(|e| e.to_string())?;
        builder.add_op(OpZkPrecompile).map_err(|e| e.to_string())?;
        builder.add_op(OpTrue).map_err(|e| e.to_string())?;
        let script = builder.drain();
        let cache: Cache<SigCacheKey, bool> = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        let mut engine=TxScriptEngine::<PopulatedTransaction,SigHashReusedValuesUnsync>::from_script_with_script_units_limit(
            &script,&reused,&cache,ScriptUnits(100_000_000),Default::default());
        let verdict = engine.execute();
        Ok(match verdict {
            Ok(()) => {
                json!({"status":"verified","script_units":engine.used_script_units().0})
            }
            Err(e) => {
                json!({"status":"native_rejected","error":e.to_string(),"error_debug":format!("{e:?}"),"script_units":engine.used_script_units().0})
            }
        })
    })();
    result.unwrap_or_else(|e| json!({"status":"guard_rejected","error":e}))
}
fn main() {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() != 1 {
            return Err("INPUT_JSON".into());
        }
        if fs::metadata(&args[0])?.len() > 1_048_576 {
            return Err("input file size bound".into());
        }
        let raw = fs::read(&args[0])?;
        let input: Input = serde_json::from_slice(&raw)?;
        if input.schema != "kpi-arkworks-public-differential-input-v1"
            || input.statements.len() > 50
            || input.vectors.len() > 200
        {
            return Err("input bounds".into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"schema":"kpi-native-arkworks-differential-v1",
            "input_sha256":hex::encode(hash(&raw)),"native_dependency":"01b532e8b553523216471682649693af92f0fd16",
            "scope":"actual standalone TxScriptEngine OpZkPrecompile 0x20; no covenant/transaction/chain validation",
            "statements":input.statements.iter().map(|s|json!({"id":s.id,"native":one(s)})).collect::<Vec<_>>()}))?
        );
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("native arkworks differential: {e}");
        std::process::exit(1);
    }
}
