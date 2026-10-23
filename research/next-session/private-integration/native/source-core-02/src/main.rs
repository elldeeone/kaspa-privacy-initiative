use kpi_future_native_union::{native, policy};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
fn main() -> policy::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args
        .get(1)
        .ok_or("mode inspect/private-freeze/private-run/reveal-freeze/reveal-run")?;
    let input = Path::new(args.get(2).ok_or("input fixture JSON or VK328 file")?);
    let out = Path::new(args.get(3).ok_or("output directory")?);
    fs::create_dir_all(out)?;
    if mode == "inspect" {
        let vk = fs::read(input)?;
        let mut state = [0; 112];
        state[..8].copy_from_slice(policy::STATE_MAGIC);
        state[8..40].copy_from_slice(&policy::DOMAIN);
        state[72..76].copy_from_slice(&1u32.to_le_bytes());
        state[108..112].copy_from_slice(&1u32.to_le_bytes());
        let r = policy::redeem(&state, &vk)?;
        fs::write(out.join("union-redeem.bin"), &r)?;
        fs::write(
            out.join("inspection.json"),
            serde_json::to_vec_pretty(
                &json!({"redeem_bytes":r.len(),"redeem_sha256":hex::encode(Sha256::digest(&r)),"domain":hex::encode(policy::DOMAIN),"actual_private_Groth16_branch":true,"actual_reveal_branch":true,"NOP_standin":false,"native_VM_or_Full_executed":false,"placeholder_roots_not_valid_state":true}),
            )?,
        )?;
        return Ok(());
    }
    let (tx, e) = match mode.as_str() {
        "private-freeze" | "private-run" => native::private_body(&serde_json::from_slice::<
            native::PrivateVector,
        >(&fs::read(input)?)?)?,
        "reveal-freeze" | "reveal-run" => native::reveal_body(&serde_json::from_slice::<
            native::RevealVector,
        >(&fs::read(input)?)?)?,
        _ => return Err("unknown mode".into()),
    };
    fs::write(
        out.join("transaction.json"),
        serde_json::to_vec_pretty(&tx)?,
    )?;
    fs::write(
        out.join("supplied-context.json"),
        serde_json::to_vec_pretty(&native::supplied_context(&e))?,
    )?;
    fs::write(
        out.join("metrics.json"),
        serde_json::to_vec_pretty(&native::metrics(&tx, &e)?)?,
    )?;
    if mode.ends_with("-run") {
        let report = native::execute(&tx, &e);
        fs::write(
            out.join("native-validation.json"),
            serde_json::to_vec_pretty(&report)?,
        )?;
        if report["Full"]["accepted"] != true || report["ScriptEngine"]["accepted"] != true {
            return Err(format!("native validation failed:{report}").into());
        }
    }
    Ok(())
}
