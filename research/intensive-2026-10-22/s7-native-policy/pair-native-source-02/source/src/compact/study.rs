//! H11 native calibration only. No changed circuit, covenant, parameters or RPC.
//! Old/fresh capabilities and truth remain in the private experiment directory.
use super::{deposits as dep, experiment as ex, *};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    kind: String,
    minute: u64,
    owner: usize,
    position: Option<usize>,
    deposit: u64,
    values: Vec<u64>,
    owners: Vec<usize>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    initial_value: u64,
    events: Vec<Event>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub(super) state: PublicState,
    pub(super) reserve: Option<native::Utxo>,
    pub(super) transactions: Vec<Value>,
    pub(super) contexts: Vec<Vec<native::Utxo>>,
    pub(super) metrics: Vec<Value>,
    pub(super) fees: u64,
}
impl Ledger {
    pub(super) fn apply(&mut self, d: &H, vk: &[u8], b: &Bundle,
             external: Option<(&native::Utxo, &H)>) -> Result<()> {
        let input = self.reserve.as_ref().ok_or("drained ledger")?.clone();
        let a = b.auth()?;
        let (mut tx, entries) = dep::settle(d, &self.state, &input, vk, b, external.map(|x| x.0))?;
        if let Some((_, key)) = external {native::sign(&mut tx, &entries, 1, key)?;}
        if tx.inputs[0].previous_outpoint != input.outpoint()? {return Err("current reserve mismatch".into());}
        let fee = native::validate(&tx, &entries)?;
        if fee != a.fee {return Err("native fee differs from authorization".into());}
        let metric = native::policy(&tx, &entries)?;
        native::validate(&native::parse_tx(&native::tx_json(&tx))?, &entries)?;
        if tx.inputs[0].signature_script[2..130] != hex::decode(&b.proof)? ||
            tx.payload[P_AUTH..P_CIPHER] != hex::decode(&b.authorization)? {
            return Err("settlement altered saved bytes".into());
        }
        self.state = dep::update(&self.state, &a, external.is_some())?.0;
        self.reserve = if self.state.compact()?.cm_count == self.state.compact()?.nf_count {
            None
        } else {Some(native::Utxo::output(&tx, 0, 0))};
        self.transactions.push(native::tx_json(&tx));
        let mut ctx = vec![input];
        if let Some((e, _)) = external {ctx.push(e.clone());}
        self.contexts.push(ctx);
        self.metrics.push(metric);
        self.fees = self.fees.checked_add(fee).ok_or("fee overflow")?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub(super) domain: H,
    pub(super) vk: String,
    pub(super) prefix: Ledger,
    pub(super) bundles: Vec<Bundle>,
    pub(super) minutes: Vec<i64>,
}

/// H12 reuses the genuine preparation with a fresh identity for each trial.
/// This still uses synthetic ordinary prevouts; normalization::bind replaces
/// only funding/settlement context and validates every exact unchanged proof.
pub(super) fn prepare_one(params: &Path, plan: &Path, root: &Path) -> Result<Value> {
    let meta: Value = ex::read(&params.join("parameters.json"))?;
    for key in ["pk", "vk"] {
        if meta[format!("{key}_sha256")] != ex::file_hash(&params.join(format!("{key}.bin")))? {
            return Err("parameter pin mismatch".into());
        }
    }
    let vk = fs::read(params.join("vk.bin"))?;
    let now = Instant::now();
    let pk: ProvingKey<Bn254> = ex::decode(&params.join("pk.bin"))?;
    let load_ms = now.elapsed().as_millis();
    if ex::compressed(&pk.vk)? != vk {return Err("PK/VK mismatch".into());}
    let result = case(&pk, &vk, ex::read(plan)?, root)?;
    ex::save(&root.join("parameters.json"), &json!({"parameter_load_ms":load_ms,
        "pk_sha256":meta["pk_sha256"],"vk_sha256":meta["vk_sha256"],
        "binary_sha256":ex::file_hash(&std::env::current_exe()?)?}))?;
    Ok(result)
}

fn case(pk: &ProvingKey<Bn254>, vk: &[u8], plan: Plan, root: &Path) -> Result<Value> {
    dep::harness::dir(root)?;
    let d = hash(&[b"KPI/H11/native/offline\0".as_slice(), &random()].concat());
    let wallets: Vec<Wallet> = (0..4).map(|_| Wallet::fresh()).collect();
    let keys: Vec<H> = (0..4).map(|_| random()).collect();
    let first = wallets[0].receive(&d).note(plan.initial_value)?;
    let state = PublicState::initial(first.commitment(&d))?;
    let source = native::Utxo {txid: hex::encode(random()), index: 0,
        amount: plan.initial_value.checked_mul(2).ok_or("funding range")?,
        spk: hex::encode(native::encode_spk(&native::p2pk(&keys[0])?)), daa: 0, is_coinbase: false};
    let (funding, entries) = native::ordinary(&source, &keys[0], vec![TransactionOutput::new(
        plan.initial_value, dep::reserve_spk(&d, &state, vk)?)])?;
    let fee = native::validate(&funding, &entries)?;
    let mut ledger = Ledger {state, reserve: Some(native::Utxo::output(&funding, 0, 0)),
        transactions: vec![native::tx_json(&funding)], contexts: vec![vec![source]],
        metrics: vec![native::policy(&funding, &entries)?], fees: fee};
    let fees = dep::fees()?;
    if (fees.transfer, fees.deposit, fees.exit) != (21_893_200, 22_005_200, 21_934_400) {
        return Err("model/native fee calibration changed".into());
    }
    let mut notes = vec![(0usize, first)];
    let mut saved = std::collections::BTreeMap::new();
    let mut times = vec![-1i64];
    let mut proof_ms = Vec::new();
    let exits: Vec<&Event> = plan.events.iter().filter(|e| e.kind == "exit").collect();
    for event in plan.events.iter().filter(|e| e.kind != "exit") {
        if event.owner >= 4 || event.values.len() != 2 || event.owners.len() != 2 || event.owners.iter().any(|o| *o >= 4) {
            return Err("plan owner/output shape".into());
        }
        let outputs = [wallets[event.owners[0]].receive(&d).note(event.values[0])?,
                       wallets[event.owners[1]].receive(&d).note(event.values[1])?];
        let virtual_note;
        let virtual_state;
        let (input, state, position, boot, charge) = if event.kind == "deposit" {
            virtual_note = wallets[event.owner].receive(&d).note(event.deposit)?;
            virtual_state = PublicState::initial(virtual_note.commitment(&d))?;
            (&virtual_note, &virtual_state, 0, event.deposit, fees.deposit)
        } else {
            let position = event.position.ok_or("missing input position")?;
            let (owner, n) = notes.get(position).ok_or("input note absent")?;
            if *owner != event.owner {return Err("wrong input owner".into());}
            (n, &ledger.state, position as u32, if event.kind == "bootstrap" {plan.initial_value} else {0}, fees.transfer)
        };
        if input.value != event.values[0].checked_add(event.values[1]).and_then(|v| v.checked_add(charge)).ok_or("value range")? {
            return Err("plan conservation".into());
        }
        let (c, b) = ex::authorization(&wallets[event.owner], input, state, position, outputs,
            d, charge, 0, [0;36], boot)?;
        let (bundle, ms) = ex::prove(pk, c, b)?; proof_ms.push(ms);
        let external = if event.kind == "deposit" {
            Some(native::Utxo {txid: hex::encode(random()), index: 0, amount: event.deposit,
                spk: hex::encode(native::encode_spk(&native::p2pk(&keys[event.owner])?)), daa: 0, is_coinbase: false})
        } else {None};
        ledger.apply(&d, vk, &bundle, external.as_ref().map(|u| (u, &keys[event.owner])))?;
        times.push(event.minute as i64);
        // Recipients use authenticated encrypted delivery, not an injected note.
        for i in 0..2 {
            let owner = event.owners[i];
            let received = wallets[owner].decrypt(&d, &hex::decode(&bundle.ciphertexts[i])?, &bundle.auth()?.outputs[i])?;
            if received.value != event.values[i] {return Err("delivered amount mismatch".into());}
            let index = notes.len();
            notes.push((owner, received));
            if exits.iter().any(|e| e.position == Some(index)) {
                let (exit, ms) = dep::harness::exit_proof(pk, &wallets[owner], &notes[index].1,
                    index as u32, &d, &ledger.state)?;
                proof_ms.push(ms); saved.insert(index, exit);
            }
        }
        eprintln!("calibration operation {} completed", ledger.transactions.len()-1);
    }
    ex::save(&root.join("wallets.json"), &json!({"wallets":wallets,"funding_keys":keys,"notes":notes}))?;
    let mut old_bundles = Vec::new(); let mut fresh_bundles = Vec::new(); let mut fresh_ms = Vec::new();
    for event in exits {
        let position = event.position.ok_or("exit position")?;
        let (owner, n) = notes.get(position).ok_or("exit note")?;
        let old = saved.remove(&position).ok_or("saved exit absent")?;
        let (fresh, ms) = dep::harness::exit_proof(pk, &wallets[*owner], n, position as u32, &d, &ledger.state)?;
        fresh_ms.push(ms); proof_ms.push(ms);
        let mut a = old.auth()?.bytes(); let mut b = fresh.auth()?.bytes();
        a[A_COUNT..A_NF].fill(0); b[A_COUNT..A_NF].fill(0);
        if a != b || old.proof == fresh.proof {return Err("not genuine matched fresh proof".into());}
        old_bundles.push(old); fresh_bundles.push(fresh); times.push(event.minute as i64);
    }
    // Same-claim current-state checks in both orders. H10 additionally exercises
    // hostile duplicate native witnesses below the friendly builder checks.
    for (winner, loser) in [(&old_bundles[0], &fresh_bundles[0]), (&fresh_bundles[0], &old_bundles[0])] {
        let mut after = ledger.clone(); after.apply(&d, vk, winner, None)?;
        let error = dep::settle(&d, &after.state, after.reserve.as_ref().ok_or("remaining claims")?, vk, loser, None)
            .err().ok_or("duplicate accepted")?;
        if !error.to_string().contains("already spent") {return Err("unrelated duplicate rejection".into());}
    }
    ex::save(&root.join("saved-request.json"), &Request {domain:d, vk:hex::encode(vk), prefix:ledger.clone(),
        bundles:old_bundles, minutes:times.clone()})?;
    ex::save(&root.join("fresh-request.json"), &Request {domain:d, vk:hex::encode(vk), prefix:ledger,
        bundles:fresh_bundles, minutes:times})?;
    let result = json!({"complete":true,"genuine_proofs":proof_ms.len(),"proof_ms":proof_ms,
        "fresh_exit_ms":fresh_ms,"unchanged_relation_and_parameters":true,
        "only_anchor_authorization_fields_changed":true,"same_nullifier_recipient_value_fee":true,
        "both_current_state_duplicate_builder_rejections":true,
        "duplicate_scope":"friendly current-state builder; hostile native witness covered by H10"});
    ex::save(&root.join("preparation.json"), &result)?;
    Ok(result)
}

fn prepare(params: &Path, plans: &Path, root: &Path) -> Result<Value> {
    dep::harness::dir(root)?;
    let meta: Value = ex::read(&params.join("parameters.json"))?;
    for key in ["pk", "vk"] {
        if meta[format!("{key}_sha256")] != ex::file_hash(&params.join(format!("{key}.bin")))? {
            return Err("parameter pin mismatch".into());
        }
    }
    let vk = fs::read(params.join("vk.bin"))?;
    let now = Instant::now(); let pk: ProvingKey<Bn254> = ex::decode(&params.join("pk.bin"))?;
    let load_ms = now.elapsed().as_millis();
    if ex::compressed(&pk.vk)? != vk {return Err("PK/VK mismatch".into());}
    eprintln!("native calibration parameters loaded");
    let mut results = Vec::new();
    for name in ["sparse-00", "burst-00"] {
        let plan: Plan = ex::read(&plans.join(format!("{name}.json")))?;
        results.push(json!({"case":name,"result":case(&pk, &vk, plan, &root.join(name))?}));
        eprintln!("{name} preparation complete");
    }
    let result = json!({"complete":true,"parameter_load_ms":load_ms,"vk_sha256":hex::encode(hash(&vk)),
        "pk_sha256":meta["pk_sha256"],"binary_sha256":ex::file_hash(&std::env::current_exe()?)?,"cases":results});
    ex::save(&root.join("preparation.json"), &result)?;
    Ok(result)
}
fn settle(request: &Path, output: &Path) -> Result<Value> {
    let Request {domain, vk, mut prefix, bundles, minutes} = ex::read(request)?;
    dep::harness::dir(output)?;
    let vk = hex::decode(vk)?;
    let now = Instant::now();
    for bundle in &bundles {prefix.apply(&domain, &vk, bundle, None)?;}
    if prefix.reserve.is_some() || prefix.state.compact()?.cm_count != prefix.state.compact()?.nf_count {
        return Err("unpaid claims at drain".into());
    }
    if minutes.len() != prefix.transactions.len() {return Err("clock mismatch".into());}
    let result = json!({"complete":true,"all_claims_drained":true,"unchanged_bundle_bytes":true,
        "native_full_and_policy":true,"transactions":prefix.transactions.len(),
        "fees_sompi":prefix.fees,"settlement_ms":now.elapsed().as_millis(),"no_wallet_or_pk_input":true});
    ex::save(&output.join("chain.json"), &json!({"schema":"kpi-h11-native-chain-v1",
        "transactions":prefix.transactions,"contexts":prefix.contexts,"minutes":minutes}))?;
    ex::save(&output.join("metrics.json"), &prefix.metrics)?;
    ex::save(&output.join("result.json"), &result)?;
    Ok(result)
}
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("prepare") if args.len()==4 => prepare(Path::new(&args[1]), Path::new(&args[2]), Path::new(&args[3]))?,
        Some("settle") if args.len()==3 => settle(Path::new(&args[1]), Path::new(&args[2]))?,
        _ => return Err("prepare PARAMS PLANS NEW_ROOT | settle REQUEST NEW_OUTPUT".into()),
    };
    println!("{}", serde_json::to_string(&result)?); Ok(())
}
