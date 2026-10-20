//! H14 real-proof calibration. Plans and unused authorizations remain private.
use super::*;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    label: String,
    mode: u8,
    inputs: Vec<u32>,
    owners: [usize; 2],
    values: [u64; 2],
    deposit: u64,
    payout: u64,
    depositor: Option<usize>,
    count_before: u32,
    reserve_out: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Drain {
    position: u32,
    owner: usize,
    value: u64,
    born: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    initial: u64,
    steps: Vec<Step>,
    drains: Vec<Drain>,
    interval_minutes: u64,
}

fn isolated(r: &ExitRequest, path: &Path) -> Result<Value> {
    save(path, r)?;
    let p = std::process::Command::new("bwrap")
        .args([
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(std::env::current_exe()?)
        .arg("/app")
        .arg("--ro-bind")
        .arg(path)
        .args(["/request.json", "--", "/app", "exit", "/request.json"])
        .output()?;
    if !p.status.success() {
        return Err(String::from_utf8_lossy(&p.stderr).to_string().into());
    }
    let result: Value = serde_json::from_slice(&p.stdout)?;
    if result["isolated"] != true {
        return Err("exit isolation".into());
    }
    let tx = native::parse_tx(&result["tx"])?;
    if tx.payload[P_AUTH..P_CIPHER] != hex::decode(&r.bundle.authorization)?
        || tx.inputs[0].signature_script[2..130] != hex::decode(&r.bundle.proof)?
    {
        return Err("exit authorization changed".into());
    }
    Ok(result)
}

pub(super) fn run(params: &Path, input: &Path, out: &Path) -> Result<()> {
    run_inner(params, input, out, None)
}

/// Opt-in H17 calibration; the historical H14 command retains its old behavior.
pub(super) fn common(params: &Path, input: &Path, out: &Path) -> Result<()> {
    run_inner(params, input, out, Some(200_000_000))
}

fn run_inner(params: &Path, input: &Path, out: &Path, common: Option<u64>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let plan: Plan = read(input)?;
    if plan.schema != "kpi-h14-private-plan-v1" {
        return Err("study plan schema".into());
    }
    let mut optional = BTreeMap::new();
    for s in &plan.steps {
        if common == Some(s.payout) && s.mode == 1 {
            if s.inputs.len() != 1
                || s.values[0] < 60_000_000
                || s.values[1] != 0
                || optional.insert(s.inputs[0], s.owners[0]).is_some()
            {
                return Err("invalid common-payout fixture".into());
            }
        }
    }
    if common.is_some()
        && (optional.len() != 4 || (0..4).any(|owner| !optional.values().any(|v| *v == owner)))
    {
        return Err("common-payout fixture needs four independent owners".into());
    }
    fs::create_dir(out)?;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700))?;
    let start = Instant::now();
    let pk = ProvingKey::<Bn254>::deserialize_compressed(BufReader::new(fs::File::open(
        params.join("pk.bin"),
    )?))?;
    let load_ms = start.elapsed().as_millis();
    eprintln!("H14 parameters loaded {load_ms} ms");
    let vk = compressed(&pk.vk)?;
    let d = hash(&[b"KPI/H14/OFFLINE/v6\0".as_slice(), &random(), &hash(&vk)].concat());
    let wallets: Vec<_> = (0..4).map(|_| Wallet::fresh()).collect();
    let initial = output(&wallets[0], &d, plan.initial)?;
    let state = PublicState::initial(initial.commitment(&d))?;
    let reserve = native::Utxo {
        txid: hex::encode(random()),
        index: 0,
        amount: plan.initial,
        spk: hex::encode(native::encode_spk(&reserve_spk(&d, &state, &vk)?)),
        daa: 0,
        is_coinbase: false,
    };
    let initial_public = reserve.clone();
    let mut l = Ledger {
        domain: d,
        state,
        reserve,
        vk,
        rows: vec![],
        fees: 0,
        payouts: 0,
        credits: plan.initial,
        controls: vec![],
    };
    let mut notes = BTreeMap::from([(0, (0usize, initial))]);
    let mut saved = BTreeMap::new();
    let mut before_partial = BTreeMap::new();
    let mut optional_checks = Vec::new();
    let mut proofs = Vec::new();
    for s in &plan.steps {
        if l.state.commitments.len() != s.count_before as usize {
            return Err("plan positions".into());
        }
        let ins = s
            .inputs
            .iter()
            .map(|pos| {
                let (owner, n) = notes.get(pos).ok_or("plan input absent")?;
                selected(&wallets[*owner], n, *pos, &l.state)
            })
            .collect::<Result<Vec<_>>>()?;
        let os = [
            output(&wallets[s.owners[0]], &d, s.values[0])?,
            output(&wallets[s.owners[1]], &d, s.values[1])?,
        ];
        let fund = if let Some(owner) = s.depositor {
            Some(native::Utxo {
                txid: hex::encode(random()),
                index: 0,
                amount: s.deposit,
                spk: hex::encode(native::encode_spk(&native::p2pk(&wallets[owner].native)?)),
                daa: 0,
                is_coinbase: false,
            })
        } else {
            None
        };
        let spk = if s.payout > 0 {
            native::encode_spk(&native::p2pk(&random())?)
                .try_into()
                .unwrap()
        } else {
            [0; 36]
        };
        let (c, b) = authorize(
            d,
            &l.state,
            ins,
            os.clone(),
            s.mode,
            s.payout,
            spk,
            fund.as_ref(),
        )?;
        let t = Instant::now();
        let b = prove(&pk, c, b)?;
        proofs.push(json!({"kind":"operation","milliseconds":t.elapsed().as_millis()}));
        let old = if common == Some(s.payout) && s.mode == 1 {
            let old: &Bundle = before_partial
                .get(&s.inputs[0])
                .ok_or("missing pre-partial saved exit")?;
            if old.auth()?.nfs[0] != b.auth()?.nfs[0] {
                return Err("partial and original exit nullifiers differ".into());
            }
            let request = ExitRequest {
                domain: d,
                state: l.state.clone(),
                reserve: l.reserve.clone(),
                vk: hex::encode(&l.vk),
                bundle: old.clone(),
            };
            let rebuilt = isolated(&request, &out.join(format!("optional-{}.json", s.label)))?;
            let mut alternate = l.clone();
            alternate.accept(old, None)?;
            if rebuilt["tx"] != alternate.rows.last().unwrap()["tx"]
                || alternate.accept(&b, None).is_ok()
            {
                return Err("original exit did not exclude partial withdrawal".into());
            }
            Some(old.clone())
        } else {
            None
        };
        l.accept(
            &b,
            fund.as_ref()
                .map(|u| (u, &wallets[s.depositor.unwrap()].native)),
        )?;
        if let Some(old) = old {
            if l.clone().accept(&old, None).is_ok() {
                return Err("partial withdrawal did not exclude original exit".into());
            }
            optional_checks.push(json!({
                "original_position":s.inputs[0],"owner":s.owners[0],
                "saved_before_partial":true,"unchanged_authorization":true,
                "isolated":true,"wallet_keys_mounted":false,"proving_key_available":false,
                "full_wins_partial_rejected":true,"partial_wins_full_rejected":true,
                "old_proof_sha256":hex::encode(hash(&hex::decode(&old.proof)?))
            }));
        }
        if l.reserve.amount != s.reserve_out {
            return Err("plan reserve differs".into());
        }
        for slot in 0..2 {
            let pos = s.count_before + slot as u32;
            let n = os[slot].clone();
            let owner = s.owners[slot];
            // Include real encrypted delivery in calibration; padding is not a wallet receipt.
            if n.value > 0 {
                wallets[owner].decrypt(
                    &d,
                    &hex::decode(&b.ciphertexts[slot])?,
                    &b.auth()?.outputs[slot],
                )?;
            }
            notes.insert(pos, (owner, n.clone()));
            if let Some(expected_owner) = optional.get(&pos) {
                if *expected_owner != owner {
                    return Err("optional cashout owner differs".into());
                }
                let t = Instant::now();
                let old = fallback(&pk, d, &l.state, &wallets[owner], &n, pos)?;
                proofs.push(json!({"kind":"pre_partial_saved_exit",
                    "milliseconds":t.elapsed().as_millis()}));
                before_partial.insert(pos, old);
            }
            if let Some(dr) = plan.drains.iter().find(|dr| dr.position == pos) {
                if dr.owner != owner
                    || dr.value != n.value
                    || dr.born as usize != l.state.commitments.len()
                {
                    return Err("drain plan mismatch".into());
                }
                let t = Instant::now();
                let fallback = fallback(&pk, d, &l.state, &wallets[owner], &n, pos)?;
                proofs.push(json!({"kind":"saved_exit","milliseconds":t.elapsed().as_millis()}));
                saved.insert(pos, fallback);
            }
        }
        eprintln!("H14 operation {} accepted", s.label);
    }
    let mut fresh = BTreeMap::new();
    for dr in &plan.drains {
        let (owner, n) = &notes[&dr.position];
        let t = Instant::now();
        let b = fallback(&pk, d, &l.state, &wallets[*owner], n, dr.position)?;
        if b.auth()?.nfs[0] != saved[&dr.position].auth()?.nfs[0] {
            return Err("fresh/saved real nullifier differs".into());
        }
        proofs.push(json!({"kind":"fresh_exit","milliseconds":t.elapsed().as_millis()}));
        fresh.insert(dr.position, b);
    }
    // No commitments are appended by DRAIN, so this current root remains current for every exit.
    drop(pk);
    let mut arms = serde_json::Map::new();
    for (name, chosen, other) in [("fresh", &fresh, &saved), ("saved", &saved, &fresh)] {
        let mut branch = l.clone();
        let mut payouts = [0u64; 4];
        let mut checks = Vec::new();
        for dr in &plan.drains {
            let b = &chosen[&dr.position];
            let r = ExitRequest {
                domain: d,
                state: branch.state.clone(),
                reserve: branch.reserve.clone(),
                vk: hex::encode(&branch.vk),
                bundle: b.clone(),
            };
            let isolated = isolated(&r, &out.join(format!("{name}-exit-{}.json", dr.position)))?;
            branch.accept(b, None)?;
            if isolated["tx"] != branch.rows.last().unwrap()["tx"] {
                return Err("isolated transaction differs".into());
            }
            // Check spentness against the actual updated public set, including the terminal state.
            if branch.state.witness(&other[&dr.position].auth()?).is_ok()
                || branch.state.witness(&b.auth()?).is_ok()
            {
                return Err("alternate or replay accepted".into());
            }
            payouts[dr.owner] += dr.value - FEE;
            checks.push(
                json!({"position":dr.position,"unchanged_authorization":true,"isolated":true,
                "alternate_rejected":true,"replay_rejected":true,
                "proving_key_available":false,"wallet_keys_mounted":false}),
            );
        }
        if branch.reserve.amount != 0 || payouts.contains(&0) {
            return Err("incomplete drainage".into());
        }
        let raw = json!({"schema":"kpi-h14-native-v1","initial":initial_public,
            "interval_minutes":plan.interval_minutes,
            "transactions":branch.rows.iter().map(|r| r["tx"].clone()).collect::<Vec<_>>()});
        save(&out.join(format!("{name}-native-private.json")), &raw)?;
        arms.insert(name.into(),json!({"operations":branch.rows.len(),"fees_sompi":branch.fees,
            "payout_sompi":branch.payouts,"funding_sompi":branch.credits,"reserve_remaining":0,
            "wallet_exit_payouts_sompi":payouts,"checks":checks,
            "metrics":branch.rows.iter().map(|r| json!({"mode":r["mode"],"mass":r["metrics"],"script_units":r["script_units"]})).collect::<Vec<_>>(),
            "native_mutations":branch.controls}));
        eprintln!("H14 {name} drained");
    }
    save(
        &out.join("summary.json"),
        &json!({"offline_only":true,"synthetic_utxos":true,
        "real_groth16_proofs":true,"load_ms":load_ms,"elapsed_ms":start.elapsed().as_millis(),
        "vk_sha256":hex::encode(hash(&l.vk)),"proofs":proofs,"arms":arms,
        "common_payout_sompi":common,"optional_exit_checks":optional_checks}),
    )?;
    Ok(())
}

/// Revalidate transported public bodies without keys, plans, openings or a prover.
pub(super) fn verify_raw(input: &Path, out: &Path) -> Result<()> {
    let raw: Value = read(input)?;
    if raw["schema"] != "kpi-h14-native-v1" {
        return Err("public study schema".into());
    }
    let mut reserve: native::Utxo = serde_json::from_value(raw["initial"].clone())?;
    let mut credits = reserve.amount;
    let mut fees = 0u64;
    let mut payouts = 0u64;
    let mut rows = Vec::new();
    for body in raw["transactions"]
        .as_array()
        .ok_or("public transactions")?
    {
        let tx = native::parse_tx(body)?;
        if reserve.amount == 0
            || tx.payload.len() != PAYLOAD_SIZE
            || tx.inputs.is_empty()
            || tx.inputs[0].previous_outpoint != reserve.outpoint()?
        {
            return Err("public trace framing/lineage".into());
        }
        let a = Authorization::parse(&tx.payload[P_AUTH..P_CIPHER])?;
        let mut entries = vec![reserve.entry()?];
        if a.mode == 0 {
            let external = native::Utxo {
                txid: hex::encode(&a.funding[..32]),
                index: u32::from_le_bytes(a.funding[32..].try_into()?),
                amount: a.deposit,
                spk: hex::encode(a.funding_spk),
                daa: 0,
                is_coinbase: false,
            };
            if tx.inputs.len() != 2 || tx.inputs[1].previous_outpoint != external.outpoint()? {
                return Err("public funding binding".into());
            }
            entries.push(external.entry()?);
            credits = credits
                .checked_add(external.amount)
                .ok_or("credits overflow")?;
        }
        let fee = native::validate(&tx, &entries)?;
        let metrics = native::policy(&tx, &entries)?;
        if fee != a.fee {
            return Err("public fee differs".into());
        }
        fees = fees.checked_add(fee).ok_or("fee overflow")?;
        payouts = payouts.checked_add(a.payout).ok_or("payout overflow")?;
        if a.mode == 2 && tx.outputs.len() == 1 {
            reserve.amount = 0;
        } else {
            reserve = native::Utxo::output(&tx, 0, 0);
        }
        if credits
            != reserve
                .amount
                .checked_add(fees)
                .and_then(|v| v.checked_add(payouts))
                .ok_or("accounting overflow")?
        {
            return Err("public backing mismatch".into());
        }
        rows.push(
            json!({"id":tx.id().to_string(),"proof_and_native_validation":true,"metrics":metrics}),
        );
    }
    if reserve.amount != 0 {
        return Err("public trace not drained".into());
    }
    save(
        out,
        &json!({"synthetic_utxo_context":true,"transactions":rows.len(),
        "fee_sompi":fees,"payout_sompi":payouts,"reserve_remaining":0,"rows":rows}),
    )
}
