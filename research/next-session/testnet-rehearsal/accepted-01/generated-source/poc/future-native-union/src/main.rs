use kpi_future_native_union::{native, policy};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
fn write(out: &Path, name: &str, value: &impl serde::Serialize) -> policy::Result<()> {
    fs::write(out.join(name), serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn main() -> policy::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).ok_or("mode required")?;
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
        write(
            out,
            "inspection.json",
            &json!({"redeem_bytes":r.len(),"redeem_sha256":hex::encode(Sha256::digest(&r)),"domain":hex::encode(policy::DOMAIN),"actual_private_Groth16_branch":true,"actual_reveal_branch":true,"actual_public_admission_branch":true,"NOP_standin":false,"native_VM_or_Full_executed":false,"placeholder_roots_not_valid_state":true}),
        )?;
        return Ok(());
    }
    if mode == "validate-transaction" {
        let case: native::ValidationCase = serde_json::from_slice(&fs::read(input)?)?;
        let report = native::execute(&case.transaction, &case.entries);
        write(out, "native-validation.json", &report)?;
        write(
            out,
            "metrics.json",
            &native::metrics(&case.transaction, &case.entries)?,
        )?;
        return Ok(());
    }
    let bytes = fs::read(input)?;
    let (tx, e, state) = match mode.as_str() {
        "private-freeze" | "private-run" => {
            let v: native::PrivateVector = serde_json::from_slice(&bytes)?;
            let a = native::exact::<484>(&v.auth_hex)?;
            let (t, e) = native::private_body(&v)?;
            (t, e, Some(a[364..476].to_vec()))
        }
        "reveal-freeze" | "reveal-run" => {
            let v: native::RevealVector = serde_json::from_slice(&bytes)?;
            let p = native::exact::<2029>(&v.payload_hex)?;
            let mut s = native::exact::<112>(&v.state_hex)?;
            let (t, e) = native::reveal_body(&v)?;
            let next = if t.outputs.len() == 2 {
                s[76..108].copy_from_slice(&p[1981..2013]);
                let m = u32::from_le_bytes(s[108..112].try_into()?)
                    .checked_add(1)
                    .ok_or("NF count overflow")?;
                s[108..112].copy_from_slice(&m.to_le_bytes());
                Some(s.to_vec())
            } else {
                None
            };
            (t, e, next)
        }
        "admit-freeze" | "admit-run" => {
            let v: native::AdmitVector = serde_json::from_slice(&bytes)?;
            let p = native::exact::<1344>(&v.payload_hex)?;
            let (t, e) = native::admit_body(&v)?;
            (t, e, Some(p[1048..1160].to_vec()))
        }
        "founding-freeze" | "founding-run" => {
            let v: native::FoundingVector = serde_json::from_slice(&bytes)?;
            let note = native::exact::<168>(&v.note_hex)?;
            let (t, e) = native::founding_body(&v)?;
            (t, e, Some(policy::singleton_state(&note).to_vec()))
        }
        "funding-prep-freeze" | "funding-prep-run" => {
            let v: native::FundingPrepVector = serde_json::from_slice(&bytes)?;
            let (t, e) = native::funding_prep_body(&v)?;
            (t, e, None)
        }
        "control-resign-freeze" => {
            let v: native::ResignControlVector = serde_json::from_slice(&bytes)?;
            let (t, e) = native::resign_control(v)?;
            (t, e, None)
        }
        "control-normalize-freeze" => {
            let mut v: native::ValidationCase = serde_json::from_slice(&bytes)?;
            if v.transaction.inputs.is_empty() || v.transaction.inputs.len() != v.entries.len() {
                return Err("control input/context dimensions".into());
            }
            v.transaction.finalize();
            native::set_mass(&v.transaction, &v.entries)?;
            (v.transaction, v.entries, None)
        }
        _ => return Err("unknown mode".into()),
    };
    write(out, "transaction.json", &tx)?;
    write(out, "supplied-context.json", &native::supplied_context(&e))?;
    write(
        out,
        "validation-case.json",
        &native::ValidationCase {
            transaction: tx.clone(),
            entries: e.clone(),
        },
    )?;
    write(out, "metrics.json", &native::metrics(&tx, &e)?)?;
    let raw_id = hex::encode(tx.id().as_bytes());
    fs::write(out.join("txid-raw.hex"), format!("{raw_id}\n"))?;
    let outputs=tx.outputs.iter().enumerate().map(|(i,o)|json!({"transaction_id_raw_hex":raw_id,"index":i,"amount_sompi":o.value,"script_public_key_hex":hex::encode([o.script_public_key.version().to_be_bytes().as_slice(),o.script_public_key.script()].concat())})).collect::<Vec<_>>();
    write(out, "outputs.json", &outputs)?;
    if let Some(s) = state {
        fs::write(
            out.join("successor-state.hex"),
            format!("{}\n", hex::encode(s)),
        )?
    }
    if mode.ends_with("-run") {
        let report = native::execute(&tx, &e);
        write(out, "native-validation.json", &report)?;
        if report["Full"]["accepted"] != true || report["all_input_engines_accepted"] != true {
            return Err(format!("native validation failed:{report}").into());
        }
    }
    Ok(())
}
