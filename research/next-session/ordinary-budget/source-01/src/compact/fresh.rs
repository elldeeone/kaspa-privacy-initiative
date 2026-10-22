//! H9 offline harness. No circuit/covenant changes, node client or broadcast.
//! Both alternate worlds and all pending authorizations remain private; the
//! separate exporter releases only the selected fresh world's public history.
use super::{experiment as ex, *};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Instant};

fn dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[derive(Clone)]
struct Ledger {
    state: PublicState,
    reserve: Option<native::Utxo>,
    transactions: Vec<Transaction>,
    contexts: Vec<Vec<native::Utxo>>,
    metrics: Vec<Value>,
    fees: u64,
}

impl Ledger {
    fn validate_current(&self, tx: &Transaction) -> Result<u64> {
        let input = self.reserve.as_ref().ok_or("synthetic ledger already drained")?;
        if tx.inputs.len()!=1 || tx.inputs[0].previous_outpoint != input.outpoint()? {
            return Err("synthetic ledger missing reserve outpoint".into());
        }
        native::validate(tx,&[input.entry()?])
    }

    fn accept(&mut self, domain: &H, vk: &[u8], bundle: &Bundle) -> Result<()> {
        let input = self.reserve.as_ref().ok_or("already drained")?.clone();
        let auth = bundle.auth()?;
        let (tx, entries) = settle(domain, &self.state, &input, vk, bundle)?;
        // Explicit UTXO lookup is separate from supplied-context validation.
        let fee = self.validate_current(&tx)?;
        let metrics = native::policy(&tx, &entries)?;
        native::validate(&native::parse_tx(&native::tx_json(&tx))?, &entries)?;
        self.state = self.state.witness(&auth)?.0;
        self.reserve = if self.state.compact()?.nf_count == self.state.compact()?.cm_count {
            None
        } else {
            Some(native::Utxo::output(&tx, 0, 0))
        };
        self.fees = self.fees.checked_add(fee).ok_or("fee overflow")?;
        self.contexts.push(vec![input]);
        self.metrics.push(metrics);
        self.transactions.push(tx);
        Ok(())
    }

    fn save(&self, path: &Path, minutes: &[u64]) -> Result<()> {
        dir(path)?;
        if minutes.len() != self.transactions.len() {
            return Err("schedule length".into());
        }
        for (i, tx) in self.transactions.iter().enumerate() {
            ex::save(&path.join(format!("{i:04}.json")), &native::tx_json(tx))?;
            ex::save(&path.join(format!("{i:04}.inputs.json")), &self.contexts[i])?;
        }
        ex::save(&path.join("metrics.json"), &self.metrics)?;
        let records = self.transactions.iter().zip(minutes).map(|(tx, minute)| {
            json!({"transaction":native::tx_json(tx),"header":{"timestamp":(minute*60_000).to_string()}})
        }).collect::<Vec<_>>();
        ex::save(&path.join("chain.json"), &json!({
            "schema":"kpi-compact-chain-observer-v1","network":"testnet-10","records":records
        }))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementInput {
    domain: H,
    state: PublicState,
    reserve: native::Utxo,
    verification_key: String,
    bundle: Bundle,
}

fn settlement_input(domain: H, state: &Ledger, vk: &[u8], bundle: &Bundle) -> Result<SettlementInput> {
    Ok(SettlementInput {domain, state:state.state.clone(),
        reserve:state.reserve.clone().ok_or("missing reserve")?,
        verification_key:hex::encode(vk), bundle:bundle.clone()})
}

fn public_settle(input: &Path, output: &Path) -> Result<Value> {
    let request: SettlementInput = ex::read(input)?;
    let start = Instant::now();
    let (tx, entries) = settle(&request.domain, &request.state, &request.reserve,
                              &hex::decode(&request.verification_key)?, &request.bundle)?;
    native::validate(&tx, &entries)?;
    let metrics = native::policy(&tx, &entries)?;
    if tx.inputs[0].signature_script[2..130] != hex::decode(&request.bundle.proof)? ||
        tx.payload[P_AUTH..P_CIPHER] != hex::decode(&request.bundle.authorization)? {
        return Err("public settlement changed private authorization".into());
    }
    ex::save(&output.join("transaction.json"), &native::tx_json(&tx))?;
    let result = json!({"native_full":true,"policy":true,"unchanged_proof_and_authorization":true,
        "public_rebuild_us":start.elapsed().as_micros(),"metrics":metrics,
        "no_wallet_or_proving_key_input":true});
    ex::save(&output.join("result.json"), &result)?;
    Ok(result)
}

fn reject(name: &str, mut tx: Transaction, entries: &[UtxoEntry]) -> Result<Value> {
    tx.finalize();
    native::set_mass(&tx, entries)?;
    let error = native::validate(&tx, entries).err().ok_or_else(||format!("NATIVE ACCEPTED {name}"))?;
    // Raw diagnostics stay in the private run, never in the export allowlist.
    Ok(json!({"control":name,"native_rejected":true,"private_error":error.to_string()}))
}

/// Construct a duplicate below friendly spentness checks, retaining the genuine
/// losing proof and using the winner's actual successor. Public paths and roots
/// are recomputed; this is not a replay against the already spent reserve input.
fn duplicate(domain: &H, vk: &[u8], after: &Ledger, losing: &Bundle) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let auth = losing.auth()?;
    let old = &after.state;
    let input = after.reserve.as_ref().ok_or("duplicate control needs remaining claim")?;
    let pred = old.nullifiers.iter().position(|leaf|leaf.value==auth.nullifier).ok_or("winner nullifier missing")?;
    let prior = old.nullifiers[pred].clone();
    let mut next = old.clone();
    let mut witness = vec![0; W_LEN];
    let put = |out: &mut Vec<u8>, offset: usize, path: tree::Path| {
        for (i, h) in path.iter().enumerate() {out[offset+i*32..offset+(i+1)*32].copy_from_slice(h);}
    };
    put(&mut witness, W_ANCHOR, old.history_tree()?.path((auth.count-1)/2)?);
    witness[W_PRED_INDEX..W_PRED_INDEX+4].copy_from_slice(&(pred as u32).to_le_bytes());
    witness[W_PRED..W_PRED+68].copy_from_slice(&prior.bytes());
    put(&mut witness, W_PRED_PATH, old.nf_tree()?.path(pred as u32)?);
    let index = next.nullifiers.len() as u32;
    next.nullifiers[pred].next_index = index;
    next.nullifiers[pred].next_value = auth.nullifier;
    put(&mut witness, W_NF_APPEND, next.nf_tree()?.path(index)?);
    next.nullifiers.push(tree::NfLeaf {value:auth.nullifier,next_index:prior.next_index,next_value:prior.next_value});
    let remaining = input.amount.checked_sub(auth.payout).and_then(|v|v.checked_sub(auth.fee)).ok_or("duplicate amount underflow")?;
    let compact = next.compact()?;
    let mut outputs = vec![TransactionOutput::new(remaining,
        pay_to_script_hash_script(&covenant::redeem(domain, &compact, vk)?))];
    outputs.push(TransactionOutput::new(auth.payout, native::decode_spk(&hex::encode(auth.spk))?));
    let tx = Transaction::new(1, vec![TransactionInput::new_with_compute_budget(input.outpoint()?,
        covenant::signature(&hex::decode(&losing.proof)?, &covenant::redeem(domain,&old.compact()?,vk)?)?,
        u64::MAX,covenant::BUDGET)],outputs,0,Default::default(),0,losing.payload(&compact,&witness)?);
    Ok((tx,vec![input.entry()?]))
}

fn pair_controls(domain: &H, vk: &[u8], before: &Ledger, old: &Bundle, fresh: &Bundle) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for (name, winner, loser) in [("old-wins",old,fresh),("fresh-wins",fresh,old)] {
        let prior = before.reserve.as_ref().ok_or("pre-winner reserve")?;
        let mut after = before.clone();
        after.accept(domain,vk,winner)?;
        let current = after.reserve.as_ref().ok_or("unexpected terminal target")?;
        let error = settle(domain,&after.state,current,vk,loser).err().ok_or("friendly builder accepted duplicate")?;
        if !error.to_string().contains("already spent") {return Err("duplicate rejected for unrelated builder reason".into());}
        if current.outpoint()? == prior.outpoint()? {return Err("winner did not consume reserve".into());}
        let replay = after.validate_current(after.transactions.last().ok_or("missing winner")?)
            .err().ok_or("synthetic ledger accepted spent outpoint replay")?;
        if !replay.to_string().contains("missing reserve outpoint") {return Err("replay rejected for unrelated reason".into());}
        let (bad, entries) = duplicate(domain,vk,&after,loser)?;
        let mut result = reject(name,bad,&entries)?;
        result["builder_rejected_spent_nullifier"] = json!(true);
        result["uses_winner_successor"] = json!(true);
        result["old_outpoint_replay_rejected_by_ledger"] = json!(true);
        result["genuine_losing_proof"] = json!(true);
        // With only one other claim, a duplicate would also make the pool
        // terminal prematurely. Larger fixtures isolate NF rejection without
        // that additional output-shape inconsistency.
        result["also_premature_terminal_shape"] = json!(after.state.compact()?.cm_count == after.state.compact()?.nf_count+1);
        results.push(result);
    }
    let (good, entries) = settle(domain,&before.state,before.reserve.as_ref().unwrap(),vk,fresh)?;
    for (name, offset) in [("wrong-pool",P_AUTH+8),("wrong-root",P_AUTH+A_ANCHOR),
        ("wrong-fee",P_AUTH+A_FEE),("wrong-payout",P_AUTH+A_PAYOUT),
        ("wrong-recipient",P_AUTH+A_SPK+3),("malformed-nullifier-path",P_WITNESS+W_PRED_PATH)] {
        let mut bad = good.clone(); bad.payload[offset] ^= 1;
        results.push(reject(name,bad,&entries)?);
    }
    let mut malformed = good.clone();malformed.inputs[0].signature_script[2] ^= 1;
    results.push(reject("malformed-proof",malformed,&entries)?);
    let mut stale = good.clone();
    stale.payload[P_WITNESS+W_PRED_PATH..P_WITNESS+W_NF_APPEND+PATH_LEN]
        .copy_from_slice(&before.transactions[1].payload[P_WITNESS+W_PRED_PATH..P_WITNESS+W_NF_APPEND+PATH_LEN]);
    results.push(reject("stale-first-transfer-nullifier-paths",stale,&entries)?);
    if old.authorization != fresh.authorization {
        let mut mismatch = fresh.clone();mismatch.proof = old.proof.clone();
        let (bad, context) = settle(domain,&before.state,before.reserve.as_ref().unwrap(),vk,&mismatch)?;
        results.push(reject("old-proof-new-authorization",bad,&context)?);
        let mut mismatch = old.clone();mismatch.proof = fresh.proof.clone();
        let (bad, context) = settle(domain,&before.state,before.reserve.as_ref().unwrap(),vk,&mismatch)?;
        results.push(reject("new-proof-old-authorization",bad,&context)?);
    }
    Ok(results)
}

fn exit_proof(pk: &ProvingKey<Bn254>, wallet: &Wallet, note: &Note, position: u32,
              domain: H, state: &PublicState, fee: u64, spk: [u8;36]) -> Result<(Bundle,u128)> {
    let payout = note.value.checked_sub(fee).filter(|v|*v>=PAYOUT_FLOOR).ok_or("payout floor")?;
    let (c,b) = ex::authorization(wallet,note,state,position,[Note::dummy(),Note::dummy()],
        domain,fee,payout,spk,0)?;
    ex::prove(pk,c,b)
}

fn case(pk: &ProvingKey<Bn254>, vk: &[u8], root: &Path, count: u32, seed: u32, schedule: &[u64], exit_minute: u64) -> Result<Value> {
    dir(root)?;
    let private = root.join("private");dir(&private)?;
    let domain = hash(&[b"KPI/fresh-proof/offline/v1\0".as_slice(),&random()].concat());
    let wallets = [Wallet::fresh(),Wallet::fresh(),Wallet::fresh()];
    let reserve = 1_000_000_000u64;
    let initial = wallets[0].receive(&domain).note(reserve)?;
    let funding_key = random();
    ex::save(&private.join("wallets.json"),&json!({"wallets":wallets,"initial_note":initial,"funding_key":funding_key}))?;
    let source = native::Utxo {txid:hex::encode(random()),index:0,amount:2*reserve,
        spk:hex::encode(native::encode_spk(&native::p2pk(&funding_key)?)),daa:0,is_coinbase:false};
    let initial_state = PublicState::initial(initial.commitment(&domain))?;
    let (funding, entries) = native::ordinary(&source,&funding_key,vec![TransactionOutput::new(reserve,
        pay_to_script_hash_script(&covenant::redeem(&domain,&initial_state.compact()?,vk)?))])?;
    let fee = native::validate(&funding,&entries)?;
    let metrics = native::policy(&funding,&entries)?;
    let mut ledger = Ledger {state:initial_state,reserve:Some(native::Utxo::output(&funding,0,0)),
        transactions:vec![funding],contexts:vec![vec![source]],metrics:vec![metrics],fees:fee};
    let f = ex::fees()?;
    let mut notes = vec![(0usize,initial.clone(),0usize)];
    let mut private_spends = Vec::new();
    let mut proof_times = Vec::new();
    let mut alice_position = 0usize;
    let mut state_seed = seed;
    let mut old_state = None;
    let mut fallback = None;
    let target_spk: [u8;36] = native::encode_spk(&native::p2pk(&wallets[1].payout_key(&domain,1))?).try_into().unwrap();
    for payment in 0..=count {
        let amount = if payment==0 {400_000_000} else {
            state_seed = state_seed.wrapping_mul(1664525).wrapping_add(1013904223);
            60_000_000 + u64::from(state_seed)%40_000_001
        };
        let receiver = if payment==0 {1} else {2};
        let input = &notes[alice_position].1;
        let change = input.value.checked_sub(amount).and_then(|v|v.checked_sub(f.transfer)).filter(|v|*v>=NOTE_FLOOR).ok_or("payment floor")?;
        let outputs = [wallets[receiver].receive(&domain).note(amount)?,wallets[0].receive(&domain).note(change)?];
        let (c,b) = ex::authorization(&wallets[0],input,&ledger.state,alice_position as u32,outputs.clone(),
            domain,f.transfer,0,[0;36],if payment==0 {reserve} else {0})?;
        let (bundle,ms) = ex::prove(pk,c,b)?;proof_times.push(ms);
        let auth = bundle.auth()?;
        // Receiver scans its own ciphertext rather than receiving the sender's
        // plaintext as the input to its exit proof.
        let received = wallets[receiver].decrypt(&domain,&hex::decode(&bundle.ciphertexts[0])?,&auth.outputs[0])?;
        let changed = wallets[0].decrypt(&domain,&hex::decode(&bundle.ciphertexts[1])?,&auth.outputs[1])?;
        let source_step = ledger.transactions.len();
        private_spends.push(json!({"step":source_step,"position":alice_position,"source_step":notes[alice_position].2,"owner":0}));
        ledger.accept(&domain,vk,&bundle)?;
        notes.push((receiver,received,source_step));notes.push((0,changed,source_step));
        alice_position = notes.len()-1;
        if payment==0 {
            let (bundle,ms) = exit_proof(pk,&wallets[1],&notes[1].1,1,domain,&ledger.state,f.exit,target_spk)?;
            proof_times.push(ms);ex::save(&private.join("fallback.bundle.json"),&bundle)?;
            fallback = Some(bundle);old_state = Some(ledger.state.clone());
        }
    }
    let old = fallback.ok_or("missing fallback")?;
    let (fresh,fresh_ms) = exit_proof(pk,&wallets[1],&notes[1].1,1,domain,&ledger.state,f.exit,target_spk)?;
    proof_times.push(fresh_ms);ex::save(&private.join("fresh.bundle.json"),&fresh)?;
    let a = old.auth()?;let b = fresh.auth()?;
    let mut old_bound = a.bytes();let mut new_bound = b.bytes();
    old_bound[A_COUNT..A_NF].fill(0);new_bound[A_COUNT..A_NF].fill(0);
    if old_bound!=new_bound || a.nullifier!=b.nullifier || old.proof==fresh.proof ||
        (count>0 && (a.count==b.count || a.anchor==b.anchor)) {
        return Err("comparison changed fields other than anchor or reused private proof".into());
    }
    // Complete requests are private capabilities. They are used in separately
    // isolated no-prover processes later; never export the old request.
    ex::save(&private.join("old-settlement.json"),&settlement_input(domain,&ledger,vk,&old)?)?;
    ex::save(&private.join("fresh-settlement.json"),&settlement_input(domain,&ledger,vk,&fresh)?)?;
    let controls = pair_controls(&domain,vk,&ledger,&old,&fresh)?;
    ex::save(&private.join("native-controls.json"),&controls)?;
    let mut old_arm = ledger.clone();let mut fresh_arm = ledger;
    let target_step = old_arm.transactions.len();
    old_arm.accept(&domain,vk,&old)?;fresh_arm.accept(&domain,vk,&fresh)?;
    if old_arm.state.compact()? != fresh_arm.state.compact()? {return Err("arms diverged in economic state".into());}
    private_spends.push(json!({"step":target_step,"position":1,"source_step":1,"owner":1}));
    let mut cleanup = notes.iter().enumerate().filter(|(_,n)|n.0==2).map(|(i,_)|i).collect::<Vec<_>>();
    cleanup.push(alice_position);
    for position in cleanup {
        let (owner,note,source_step) = &notes[position];
        let step = fresh_arm.transactions.len();
        let spk = native::encode_spk(&native::p2pk(&wallets[*owner].payout_key(&domain,step as u32))?).try_into().unwrap();
        let (bundle,ms) = exit_proof(pk,&wallets[*owner],note,position as u32,domain,&fresh_arm.state,f.exit,spk)?;
        proof_times.push(ms);
        old_arm.accept(&domain,vk,&bundle)?;fresh_arm.accept(&domain,vk,&bundle)?;
        private_spends.push(json!({"step":step,"position":position,"source_step":source_step,"owner":owner}));
    }
    for arm in [&old_arm,&fresh_arm] {
        let state = arm.state.compact()?;
        if arm.reserve.is_some() || state.cm_count!=state.nf_count || state.cm_count as usize!=notes.len() {
            return Err("claims or reserve remain".into());
        }
        for (position,(owner,note,_)) in notes.iter().enumerate() {
            if !arm.state.spent(&nullifier(&domain,&wallets[*owner].spending,&note.commitment(&domain),position as u32)) {
                return Err("unspent owned claim at drain".into());
            }
        }
        let payout: u64 = arm.transactions[1..].iter().map(|tx|parse_payload(&tx.payload).map(|x|x.0.payout)).collect::<Result<Vec<_>>>()?.iter().sum();
        if payout.checked_add(arm.fees-fee) != Some(reserve) {return Err("reserve reconciliation".into());}
    }
    if old_arm.fees!=fresh_arm.fees || old_arm.metrics!=fresh_arm.metrics {return Err("native fees or mass changed between arms".into());}
    let mut minutes = vec![0,1];minutes.extend(schedule.iter().map(|m|m+1));minutes.push(exit_minute+1);
    minutes.extend((1..=count+1).map(|i|exit_minute+1+u64::from(i)));
    old_arm.save(&private.join("old-arm"),&minutes)?;
    fresh_arm.save(&root.join("fresh-arm"),&minutes)?;
    ex::save(&private.join("truth.json"),&json!({"target_step":target_step,"spends":private_spends,"note_values":notes.iter().map(|n|n.1.value).collect::<Vec<_>>()}))?;
    let result = json!({"complete":true,"offline_only":true,"intervening_payments":count,
        "transactions_per_arm":fresh_arm.transactions.len(),"genuine_proofs":proof_times.len(),
        "proof_ms":proof_times,"fresh_proof_ms":fresh_ms,"parameter_reused":true,
        "same_note_nullifier_payout_fee":true,"only_anchor_fields_changed":true,
        "different_genuine_proofs":true,"fallback_anchor_count":old_state.unwrap().commitments.len(),
        "fresh_anchor_count":b.count,"fees_sompi_per_arm":fresh_arm.fees,"funding_fee_sompi":fee,
        "native_fee_increase_sompi":0,"all_claims_drained_both_arms":true,
        "native_rejections":controls.len(),"target_step":target_step,
        "fallback_file_mode":fs::metadata(private.join("fallback.bundle.json"))?.permissions().mode()&0o777,
        "fallback_sha256":ex::file_hash(&private.join("fallback.bundle.json"))?,
        "new_native_transactions":0,"new_native_fees_sompi":0});
    ex::save(&root.join("result.json"),&result)?;
    Ok(result)
}

fn compare(params: &Path, root: &Path) -> Result<Value> {
    dir(root)?;
    let parameters: Value = ex::read(&params.join("parameters.json"))?;
    for name in ["pk","vk"] {
        if parameters[format!("{name}_sha256")] != ex::file_hash(&params.join(format!("{name}.bin")))? {
            return Err("parameter pin mismatch".into());
        }
    }
    let vk = fs::read(params.join("vk.bin"))?;
    let start = Instant::now();
    let pk: ProvingKey<Bn254> = ex::decode(&params.join("pk.bin"))?;
    let load_ms = start.elapsed().as_millis();
    if ex::compressed(&pk.vk)? != vk {return Err("PK/VK mismatch".into());}
    eprintln!("parameters loaded; starting three offline fixtures");
    let mut results = Vec::new();
    for (name,count,seed,schedule,exit) in [
        ("singleton",0,19001,vec![],5),
        ("low-a",2,19002,vec![5,20],25),
        ("low-b",4,19003,vec![30,90,150,210],240),
    ] {
        let result = case(&pk,&vk,&root.join(name),count,seed,&schedule,exit)?;
        eprintln!("{name}: both arms drained, both duplicate spend orders rejected");
        results.push(json!({"case":name,"result":result}));
    }
    let result = json!({"complete":true,"offline_only":true,"parameter_load_ms":load_ms,
        "vk_sha256":hex::encode(hash(&vk)),"binary_sha256":ex::file_hash(&std::env::current_exe()?)?,
        "cases":results,"scope":"synthetic explicit UTXOs; no chain acceptance, real-world anonymity or independent security audit"});
    ex::save(&root.join("result.json"),&result)?;
    Ok(result)
}

pub fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len()!=3 {return Err("run PARAMS NEW_PRIVATE_ROOT | settle PRIVATE_REQUEST EXISTING_OUTPUT_DIR".into());}
    let result = match args[0].as_str() {
        "run"=>compare(Path::new(&args[1]),Path::new(&args[2]))?,
        "settle"=>public_settle(Path::new(&args[1]),Path::new(&args[2]))?,
        _=>return Err("unknown offline comparison command".into()),
    };
    println!("{}",serde_json::to_string(&result)?);
    Ok(())
}
