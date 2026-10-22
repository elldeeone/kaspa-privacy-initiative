use super::*;
use kaspa_consensus_core::{hashing::sighash_type::*, tx::PopulatedTransaction};

fn reject(
    name: &str,
    mut tx: Transaction,
    entries: &[UtxoEntry],
    reserve_reject: bool,
) -> Result<Value> {
    tx.finalize();
    native::set_mass(&tx, entries)?;
    let err = native::validate(&tx, entries)
        .err()
        .ok_or_else(|| format!("native accepted {name}"))?;
    let script = native::script_units_at(&tx, entries, 0).is_err();
    if reserve_reject && !script {
        return Err(format!("{name} failed only outside the reserve script").into());
    }
    Ok(
        json!({"control":name,"native_rejected":true,"reserve_script_rejected":script,"private_error":err.to_string()}),
    )
}
#[derive(Clone)]
struct Ledger {
    state: PublicState,
    reserve: Option<native::Utxo>,
}
impl Ledger {
    fn apply(
        &mut self,
        d: &H,
        vk: &[u8],
        b: &Bundle,
        e: Option<(&native::Utxo, &H)>,
    ) -> Result<Transaction> {
        let a = b.auth()?;
        let (mut tx, entries) = settle(
            d,
            &self.state,
            self.reserve.as_ref().ok_or("closed control ledger")?,
            vk,
            b,
            e.map(|(u, _)| u),
        )?;
        if let Some((_, key)) = e {
            native::sign(&mut tx, &entries, 1, key)?;
        }
        native::validate(&tx, &entries)?;
        native::policy(&tx, &entries)?;
        native::validate(&native::parse_tx(&native::tx_json(&tx))?, &entries)?;
        self.state = update(&self.state, &a, e.is_some())?.0;
        self.reserve = if self.state.compact()?.cm_count == self.state.compact()?.nf_count {
            None
        } else {
            Some(native::Utxo::output(&tx, 0, 0))
        };
        Ok(tx)
    }
    fn drain_saved(&mut self, d: &H, vk: &[u8], saved: &[Saved]) -> Result<()> {
        for w in saved {
            for b in &w.bundles {
                if !self.state.spent(&b.auth()?.nullifier) {
                    self.apply(d, vk, b, None)?;
                }
            }
        }
        if self.reserve.is_some() {
            return Err("control ledger did not drain".into());
        }
        Ok(())
    }
}
fn duplicate(d: &H, vk: &[u8], old: &Ledger, b: &Bundle) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let a = b.auth()?;
    let input = old.reserve.as_ref().ok_or("duplicate needs other claims")?;
    let pred = old
        .state
        .nullifiers
        .iter()
        .position(|n| n.value == a.nullifier)
        .ok_or("missing spent NF")?;
    let prior = old.state.nullifiers[pred].clone();
    let mut next = old.state.clone();
    let mut w = vec![0; W_LEN];
    let put = |w: &mut Vec<u8>, o: usize, p: tree::Path| {
        for (i, h) in p.iter().enumerate() {
            w[o + i * 32..o + (i + 1) * 32].copy_from_slice(h)
        }
    };
    put(
        &mut w,
        W_ANCHOR,
        old.state.history_tree()?.path((a.count - 1) / 2)?,
    );
    w[W_PRED_INDEX..W_PRED_INDEX + 4].copy_from_slice(&(pred as u32).to_le_bytes());
    w[W_PRED..W_PRED + 68].copy_from_slice(&prior.bytes());
    put(&mut w, W_PRED_PATH, old.state.nf_tree()?.path(pred as u32)?);
    let index = next.nullifiers.len() as u32;
    next.nullifiers[pred].next_index = index;
    next.nullifiers[pred].next_value = a.nullifier;
    put(&mut w, W_NF_APPEND, next.nf_tree()?.path(index)?);
    next.nullifiers.push(tree::NfLeaf {
        value: a.nullifier,
        next_index: prior.next_index,
        next_value: prior.next_value,
    });
    let value = input
        .amount
        .checked_sub(a.payout + a.fee)
        .ok_or("duplicate value")?;
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            input.outpoint()?,
            covenant::signature(
                &hex::decode(&b.proof)?,
                &covenant::redeem(d, &old.state.compact()?, vk)?,
            )?,
            u64::MAX,
            covenant::BUDGET,
        )],
        vec![
            TransactionOutput::new(value, reserve_spk(d, &next, vk)?),
            TransactionOutput::new(a.payout, native::decode_spk(&hex::encode(a.spk))?),
        ],
        0,
        Default::default(),
        0,
        payload(b, &next.compact()?, &w, false)?,
    );
    Ok((tx, vec![input.entry()?]))
}
pub fn run(root: &Path, params: &Path, out: &Path) -> Result<Value> {
    let public = root.join("public");
    let (desc, vk) = context(&public)?;
    let h = replay(&public, &desc, &vk)?;
    if h.transactions.len() != 5 {
        return Err("controls require fully joined prefix".into());
    }
    let d = desc.identity.domain;
    let f = fees()?;
    let allocator = out.join("allocator-private");
    dir(&allocator)?;
    let allocation = out.join("allocation");
    dir(&allocation)?;
    let allocator_key = random();
    ex::write(
        &allocator.join("funding.key"),
        hex::encode(allocator_key).as_bytes(),
    )?;
    ex::save(
        &allocator.join("funding.json"),
        &json!({"network":"testnet-10","address":native::address(&native::p2pk(&allocator_key)?)?}),
    )?;
    let source = native::Utxo {
        txid: hex::encode(random()),
        index: 0,
        amount: 6_000_000_000,
        spk: hex::encode(native::encode_spk(&native::p2pk(&allocator_key)?)),
        daa: 0,
        is_coinbase: false,
    };
    ex::save(&out.join("allocation-input.json"), &source)?;
    allocate(
        root,
        &out.join("allocation-input.json"),
        &allocator,
        &allocation,
    )?;
    let wallets = (0..4)
        .map(|i| ex::read::<Private>(&root.join(format!("wallet{i}.json"))))
        .collect::<Result<Vec<_>>>()?;
    let saved = (0..4)
        .map(|i| ex::read::<Saved>(&root.join(format!("prover-{i}/saved.json"))))
        .collect::<Result<Vec<_>>>()?;
    let good = h.transactions[2].clone();
    let inputs: Vec<native::Utxo> = ex::read(&root.join("prover-1/admission.inputs.json"))?;
    let entries = inputs
        .iter()
        .map(native::Utxo::entry)
        .collect::<Result<Vec<_>>>()?;
    let key = &wallets[1].funding_key;
    native::validate(&good, &entries)?;
    let mut rejections = Vec::new();
    for (name, offset) in [
        ("wrong-domain", P_AUTH + 8),
        ("wrong-virtual-root", P_AUTH + A_ANCHOR),
        ("wrong-bootstrap-value", P_AUTH + A_BOOT),
        ("wrong-output-commitment", P_AUTH + A_CM),
        ("wrong-fee", P_AUTH + A_FEE),
        ("wrong-mode", P_AUTH + A_MODE),
        ("wrong-ciphertext", P_CIPHER),
        ("wrong-state-tag", P_STATE),
        ("increment-spent-count", P_STATE + 5),
        ("reset-nullifier-root", P_STATE + 41),
        ("wrong-history-root", P_STATE + 73),
        ("nonzero-unused-witness", P_WITNESS),
        ("wrong-first-append", P_WITNESS + W_CM_APPEND),
        ("wrong-second-append", P_WITNESS + W_CM_APPEND + PATH_LEN),
        ("wrong-history-append", P_WITNESS + W_HISTORY_APPEND),
    ] {
        let mut bad = good.clone();
        bad.payload[offset] ^= 1;
        native::sign(&mut bad, &entries, 1, key)?;
        rejections.push(reject(name, bad, &entries, true)?);
    }
    for delta in [-1i64, 1] {
        let mut bad = good.clone();
        bad.outputs[0].value = (bad.outputs[0].value as i64 + delta) as u64;
        native::sign(&mut bad, &entries, 1, key)?;
        rejections.push(reject(
            if delta > 0 {
                "one-sompi-overcredit"
            } else {
                "charge-old-claims-extra-fee"
            },
            bad,
            &entries,
            true,
        )?);
    }
    let mut bad = good.clone();
    bad.inputs[0].signature_script[2] ^= 1;
    native::sign(&mut bad, &entries, 1, key)?;
    rejections.push(reject(
        "malformed-proof-with-valid-funder",
        bad,
        &entries,
        true,
    )?);
    let mut bad = good.clone();
    bad.payload.truncate(PAYLOAD_SIZE - 1);
    native::sign(&mut bad, &entries, 1, key)?;
    rejections.push(reject("short-payload", bad, &entries, true)?);
    let mut bad = good.clone();
    bad.payload[..8].copy_from_slice(b"KPICR01\0");
    native::sign(&mut bad, &entries, 1, key)?;
    rejections.push(reject("deposit-in-spend-envelope", bad, &entries, true)?);
    let mut bad = good.clone();
    bad.inputs[1].signature_script = vec![];
    bad.finalize();
    rejections.push(reject("missing-funding-signature", bad, &entries, true)?);
    for (name, kind) in [
        ("sighash-none", SIG_HASH_NONE),
        ("sighash-single", SIG_HASH_SINGLE),
        ("anyone-can-pay", SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY),
    ] {
        let mut bad = good.clone();
        bad.inputs[1].signature_script = kaspa_consensus_core::sign::sign_input(
            &PopulatedTransaction::new(&bad, entries.clone()),
            1,
            key,
            kind,
        );
        rejections.push(reject(name, bad, &entries, true)?);
    }
    let mut bad = good.clone();
    bad.inputs[1].signature_script[5] ^= 1;
    rejections.push(reject("invalid-funding-signature", bad, &entries, false)?);
    let mut bad = good.clone();
    bad.inputs[1].previous_outpoint.index += 1;
    rejections.push(reject(
        "outpoint-substitution-after-signing",
        bad,
        &entries,
        false,
    )?);
    let mut changed = entries.clone();
    changed[1].amount += 1;
    let mut bad = good.clone();
    bad.outputs[0].value += 1;
    native::sign(&mut bad, &changed, 1, key)?;
    rejections.push(reject(
        "actual-backing-versus-proved-value",
        bad,
        &changed,
        true,
    )?);
    let mut changed = entries.clone();
    changed[1].script_public_key = native::p2pk(&[8; 32])?;
    rejections.push(reject(
        "funding-script-substitution",
        good.clone(),
        &changed,
        false,
    )?);
    let mut changed = entries.clone();
    changed[1].is_coinbase = true;
    rejections.push(reject("coinbase-deposit", good.clone(), &changed, true)?);
    let mut bad = good.clone();
    bad.outputs[0].script_public_key = native::p2pk(&[8; 32])?;
    native::sign(&mut bad, &entries, 1, key)?;
    rejections.push(reject("replace-immutable-successor", bad, &entries, true)?);
    let seed = PublicState::initial(desc.identity.initial_commitment)?;
    let initial = native::Utxo::output(&h.transactions[0], 0, 0);
    let mut bad = good.clone();
    bad.inputs[0].previous_outpoint = initial.outpoint()?;
    bad.inputs[0].signature_script = covenant::signature(
        &good.inputs[0].signature_script[2..130],
        &covenant::redeem(&d, &seed.compact()?, &vk)?,
    )?;
    let early = vec![initial.entry()?, entries[1].clone()];
    native::sign(&mut bad, &early, 1, key)?;
    rejections.push(reject("deposit-before-bootstrap", bad, &early, true)?);
    // Compute budgets are not signed: insufficient budget must fail execution;
    // changing it cannot alter accounting or grant a privileged exit.
    let mut bad = good.clone();
    bad.inputs[0].compute_commit = kaspa_consensus_core::tx::ComputeCommit::ComputeBudget(1.into());
    rejections.push(reject("insufficient-compute-budget", bad, &entries, true)?);

    let ledger = Ledger {
        state: h.state.clone(),
        reserve: h.reserve.clone(),
    };
    let old = &saved[0].bundles[0];
    let a = old.auth()?;
    let mut exit = settle(
        &d,
        &ledger.state,
        ledger.reserve.as_ref().unwrap(),
        &vk,
        old,
        None,
    )?;
    exit.0.payload[..8].copy_from_slice(b"KPICD01\0");
    rejections.push(reject("exit-in-deposit-envelope", exit.0, &exit.1, true)?);
    let bob_bundle: Bundle = ex::read(&root.join("prover-1/admission.bundle.json"))?;
    let (replayed, e) = settle(
        &d,
        &h.state,
        h.reserve.as_ref().unwrap(),
        &vk,
        &bob_bundle,
        Some(&desc.sources[1]),
    )?;
    let mut replayed = replayed;
    native::sign(&mut replayed, &e, 1, key)?;
    native::validate(&replayed, &e)?;
    let replay_pub = out.join("spent-input-replay");
    dir(&replay_pub)?;
    for file in ["descriptor.json", "vk.bin"] {
        fs::copy(public.join(file), replay_pub.join(file))?;
    }
    let mut rows = h
        .transactions
        .iter()
        .map(native::tx_json)
        .collect::<Vec<_>>();
    rows.push(native::tx_json(&replayed));
    ex::save(&replay_pub.join("history.json"), &rows)?;
    let error = replay(&replay_pub, &desc, &vk)
        .err()
        .ok_or("accepted spent funding input")?;
    if !error.to_string().contains("already consumed") {
        return Err("funding replay failed for unrelated reason".into());
    }

    // Genuine alternate proof for one economic note, and genuine private transfer.
    let started = Instant::now();
    let pk = load_pk(params, &desc.identity, &vk)?;
    let load_ms = started.elapsed().as_millis();
    let own = scan(&h, &wallets[0].wallet, &d)?;
    let selected = &own[0];
    let (fresh, _) = exit_proof(
        &pk,
        &wallets[0].wallet,
        &selected.1,
        selected.0,
        &d,
        &h.state,
    )?;
    if fresh.auth()?.nullifier != a.nullifier {
        return Err("fresh proof not same claim".into());
    }
    for (name, winner, loser) in [("old-wins", old, &fresh), ("fresh-wins", &fresh, old)] {
        let mut after = ledger.clone();
        after.apply(&d, &vk, winner, None)?;
        let (bad, e) = duplicate(&d, &vk, &after, loser)?;
        rejections.push(reject(name, bad, &e, true)?);
        after.drain_saved(&d, &vk, &saved)?;
    }
    let bob_notes = scan(&h, &wallets[1].wallet, &d)?;
    let outputs = [
        wallets[0].wallet.receive(&d).note(150_000_000)?,
        wallets[2]
            .wallet
            .receive(&d)
            .note(bob_notes[0].1.value - 150_000_000 - f.transfer)?,
    ];
    let (c, b) = ex::authorization(
        &wallets[1].wallet,
        &bob_notes[0].1,
        &h.state,
        bob_notes[0].0,
        outputs.clone(),
        d,
        f.transfer,
        0,
        [0; 36],
        0,
    )?;
    let (payment, _) = ex::prove(&pk, c, b)?;
    let mut paid = ledger.clone();
    let tx = paid.apply(&d, &vk, &payment, None)?;
    for (i, recipient) in [0usize, 2].iter().enumerate() {
        let a = payment.auth()?;
        let n = wallets[*recipient].wallet.decrypt(
            &d,
            &tx.payload[P_CIPHER + i * 185..P_CIPHER + (i + 1) * 185],
            &a.outputs[i],
        )?;
        if n.commitment(&d) != outputs[i].commitment(&d) {
            return Err("private payment delivery".into());
        }
        let (b, _) = exit_proof(
            &pk,
            &wallets[*recipient].wallet,
            &n,
            9 + i as u32,
            &d,
            &paid.state,
        )?;
        paid.apply(&d, &vk, &b, None)?;
    }
    paid.drain_saved(&d, &vk, &saved)?;
    // Same admission proof + different signed backing creates real new positions.
    let mut repeated = ledger.clone();
    let mut funding = desc.sources[1].clone();
    funding.txid = hex::encode(random());
    repeated.apply(&d, &vk, &bob_bundle, Some((&funding, key)))?;
    let mut repeat_nfs = Vec::new();
    for (i, (_, n)) in bob_notes.iter().enumerate() {
        let (b, _) = exit_proof(
            &pk,
            &wallets[1].wallet,
            n,
            9 + i as u32,
            &d,
            &repeated.state,
        )?;
        if b.auth()?.nullifier == saved[1].bundles[i].auth()?.nullifier {
            return Err("positioned NF collision".into());
        }
        repeat_nfs.push(hex::encode(b.auth()?.nullifier));
        repeated.apply(&d, &vk, &b, None)?;
    }
    repeated.drain_saved(&d, &vk, &saved)?;
    // Minimum admitted notes must actually pass native settlement, not just a
    // wallet-side floor check. Keep this separate from the four-wallet fixture.
    let minimum = 2 * NOTE_FLOOR + f.deposit;
    let virtual_note = wallets[1].wallet.receive(&d).note(minimum)?;
    let virtual_state = PublicState::initial(virtual_note.commitment(&d))?;
    let outputs = [
        wallets[1].wallet.receive(&d).note(NOTE_FLOOR)?,
        wallets[1].wallet.receive(&d).note(NOTE_FLOOR)?,
    ];
    let (c, b) = ex::authorization(
        &wallets[1].wallet,
        &virtual_note,
        &virtual_state,
        0,
        outputs.clone(),
        d,
        f.deposit,
        0,
        [0; 36],
        minimum,
    )?;
    check_own_delivery(&wallets[1].wallet, &d, &b, &outputs)?;
    let mut bad_delivery = b.clone();
    let mut bytes = hex::decode(&bad_delivery.ciphertexts[0])?;
    bytes[0] ^= 1;
    bad_delivery.ciphertexts[0] = hex::encode(bytes);
    let mut bad_auth = bad_delivery.auth()?;
    bad_auth.cipher_hash = hash(&bad_delivery.ciphertext_bytes()?);
    bad_delivery.authorization = hex::encode(bad_auth.bytes());
    if check_own_delivery(&wallets[1].wallet, &d, &bad_delivery, &outputs).is_ok() {
        return Err("wallet accepted corrupted self-deposit delivery".into());
    }
    let mut relation = Vec::new();
    for delta in [-1i64, 0, 1] {
        let mut test = c.clone();
        test.outputs[0].value = (NOTE_FLOOR as i64 + delta) as u64;
        test.outputs[1].value = (NOTE_FLOOR as i64 - delta) as u64;
        test.auth.outputs = test.outputs.clone().map(|n| n.commitment(&d));
        test.public = test.auth.inputs();
        let (_, ok) = test.check()?;
        if ok != (delta == 0) {
            return Err("circuit note-floor boundary".into());
        }
        relation.push(json!({"case":format!("balanced-floor-offset-{delta}"),"satisfied":ok}));
    }
    let mut overcredit = c.clone();
    overcredit.outputs[1].value += 1;
    overcredit.auth.outputs = overcredit.outputs.clone().map(|n| n.commitment(&d));
    overcredit.public = overcredit.auth.inputs();
    if overcredit.check()?.1 {
        return Err("circuit accepted one-sompi inflation".into());
    }
    relation
        .push(json!({"case":"one-sompi-inflation-with-matching-commitments","satisfied":false}));
    let mut bad_context = desc.sources[1].clone();
    bad_context.amount = MAX_SOMPI;
    if settle(
        &d,
        &h.state,
        h.reserve.as_ref().unwrap(),
        &vk,
        &bob_bundle,
        Some(&bad_context),
    )
    .is_ok()
    {
        return Err("builder accepted invalid aggregate/binding".into());
    }
    let mut overflow = entries.clone();
    overflow[1].amount = MAX_SOMPI;
    if native::validate(&good, &overflow).is_ok() {
        return Err("native aggregate MAX bound absent".into());
    }
    let (b, _) = ex::prove(&pk, c, b)?;
    let mut minimum_ledger = ledger.clone();
    let mut funding = desc.sources[1].clone();
    funding.txid = hex::encode(random());
    funding.amount = minimum;
    minimum_ledger.apply(&d, &vk, &b, Some((&funding, key)))?;
    for (i, n) in outputs.iter().enumerate() {
        let (b, _) = exit_proof(
            &pk,
            &wallets[1].wallet,
            n,
            9 + i as u32,
            &d,
            &minimum_ledger.state,
        )?;
        minimum_ledger.apply(&d, &vk, &b, None)?;
    }
    minimum_ledger.drain_saved(&d, &vk, &saved)?;
    ex::save(&out.join("native-rejections.json"), &rejections)?;
    let result = json!({"complete":true,"native_rejections":rejections.len(),"reserve_script_rejections":rejections.iter().filter(|v|v["reserve_script_rejected"]==true).count(),
        "spent_funding_replay_rejected_by_ledger":true,"populated_context_alone_is_not_unspentness":true,
        "same_claim_both_winner_orders_rejected":true,"private_transfer_recipients_paid":2,
        "repeated_admission_fresh_backing_claims_paid":repeat_nfs.len(),"minimum_note_claims_paid":2,
        "all_control_ledgers_drained":true,"corrupted_delivery_rejected_before_signing":true,"aggregate_overflow_rejected":true,
        "relation_boundaries":relation,"parameter_load_ms":load_ms,"additional_private_proofs":9});
    ex::save(&out.join("result.json"), &result)?;
    Ok(result)
}
