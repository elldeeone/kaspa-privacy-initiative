use crate::fixtures::sample;
use kpi_shared_pool::{circuit::SpendCircuit, native, protocol::*};
fn check(c: &SpendCircuit) -> bool {
    c.check().unwrap().1
}
fn rebuild(c: &mut SpendCircuit) {
    let mode = c.transition.payload[8];
    let n = output_count(mode).unwrap();
    let next = if mode == 0 {
        let mut s = c.transition.old.clone();
        s.commitments.extend(
            c.outputs[..n]
                .iter()
                .map(|x| x.commitment(&c.transition.domain)),
        );
        s
    } else {
        c.transition
            .old
            .spend(&c.transition.domain, &c.secret, &c.input, &c.outputs[..n])
            .unwrap()
    };
    let mut cipher = [vec![0; 185], vec![0; 185]];
    for (i, x) in cipher.iter_mut().enumerate().take(n) {
        *x = c.outputs[i].encrypt(&c.transition.domain).unwrap();
    }
    c.transition.payload = payload(mode, &next, &cipher).unwrap();
    c.public = c.transition.inputs();
}
fn deposit() -> SpendCircuit {
    let first = sample().unwrap();
    let d = first.transition.domain;
    let w = Wallet {
        spending: [4; 32],
        viewing: [5; 32],
        native: [6; 32],
    };
    let old = parse_payload(&first.transition.payload).unwrap().1;
    let fee = native::fee_for(0).unwrap();
    let u = native::Utxo {
        txid: hex::encode([8; 32]),
        index: 1,
        amount: 1_200_000_000,
        spk: hex::encode(native::encode_spk(&native::p2pk(&w.native).unwrap())),
        daa: 0,
        is_coinbase: false,
    };
    let t = Transition {
        domain: d,
        old: old.clone(),
        txid: [7; 32],
        index: 0,
        reserve_in: first.transition.reserve_out,
        reserve_out: first.transition.reserve_out + u.amount - fee,
        payout: 0,
        payout_spk: vec![0; 36],
        deposit: native::deposit_bytes(&u).unwrap(),
        payload: payload(0, &old, &[vec![0; 185], vec![0; 185]]).unwrap(),
    };
    let mut c = SpendCircuit {
        public: t.inputs(),
        transition: t,
        secret: w.spending,
        input: Note::dummy(),
        outputs: [w.receive(&d).note(u.amount - fee).unwrap(), Note::dummy()],
        fee,
    };
    rebuild(&mut c);
    c
}
fn withdrawal(first: &SpendCircuit, partial: bool) -> SpendCircuit {
    let d = first.transition.domain;
    let w = Wallet {
        spending: [4; 32],
        viewing: [5; 32],
        native: [6; 32],
    };
    let input = first.outputs[0].clone();
    let old = parse_payload(&first.transition.payload).unwrap().1;
    let mode = if partial { 4 } else { 2 };
    let fee = native::fee_for(mode).unwrap();
    let payout = if partial {
        25_000_000
    } else {
        input.value - fee
    };
    let t = Transition {
        domain: d,
        old: old.clone(),
        txid: [8; 32],
        index: 0,
        reserve_in: first.transition.reserve_out,
        reserve_out: first.transition.reserve_out - payout - fee,
        payout,
        payout_spk: native::encode_spk(&native::p2pk(&w.payout_key(&d, 3)).unwrap()),
        deposit: vec![0; 84],
        payload: payload(mode, &old, &[vec![0; 185], vec![0; 185]]).unwrap(),
    };
    let outputs = if partial {
        [
            w.receive(&d).note(input.value - payout - fee).unwrap(),
            Note::dummy(),
        ]
    } else {
        [Note::dummy(), Note::dummy()]
    };
    let mut c = SpendCircuit {
        public: t.inputs(),
        transition: t,
        secret: w.spending,
        input,
        outputs,
        fee,
    };
    rebuild(&mut c);
    c
}
#[test]
fn shared_relation_rejects_accounting_and_state_attacks() {
    let first = sample().unwrap();
    let dep = deposit();
    let part = withdrawal(&first, true);
    let full = withdrawal(&first, false);
    for c in [&first, &dep, &part, &full] {
        assert!(check(c));
    }
    let mut cases = Vec::new();
    let mut c = first.clone();
    c.transition.reserve_in -= 1;
    c.transition.reserve_out -= 1;
    c.public = c.transition.inputs();
    cases.push(("underbacked genesis", c));
    let mut c = first.clone();
    c.secret[0] ^= 1;
    cases.push(("wrong authority", c));
    let mut c = first.clone();
    c.outputs[1].value = u64::MAX;
    rebuild(&mut c);
    cases.push(("u64 hidden inflation", c));
    let mut c = dep.clone();
    c.outputs[0].value += 1;
    rebuild(&mut c);
    cases.push(("deposit excess credit", c));
    let mut c = dep.clone();
    c.transition.reserve_out -= 1;
    c.fee += 1;
    rebuild(&mut c);
    cases.push(("deposit charges existing holders", c));
    let mut c = dep.clone();
    c.transition.old = first.transition.old.clone();
    c.transition.reserve_in = RESERVE;
    c.transition.reserve_out = RESERVE + 1_200_000_000 - c.fee;
    rebuild(&mut c);
    cases.push(("deposit skips initial backing proof", c));
    let mut c = dep.clone();
    c.transition.payload[9 + NF_START] ^= 1;
    c.public = c.transition.inputs();
    cases.push(("deposit erases spentness", c));
    let mut c = part.clone();
    c.transition.payout += 1;
    c.transition.reserve_out -= 1;
    c.public = c.transition.inputs();
    cases.push(("partial excess payout with native balance preserved", c));
    let mut c = part.clone();
    c.outputs[0].value += 1;
    c.transition.reserve_in += 1;
    c.transition.reserve_out += 1;
    rebuild(&mut c);
    cases.push(("partial private change inflation", c));
    let mut c = part.clone();
    c.transition.payload[9 + 3] ^= 1;
    c.public = c.transition.inputs();
    cases.push(("old commitment overwritten", c));
    let mut c = part.clone();
    c.transition.payload[CIPHER_START + 185] = 1;
    c.public = c.transition.inputs();
    cases.push(("nonzero unused ciphertext", c));
    let mut c = part.clone();
    c.transition.payload[CIPHER_START] ^= 1;
    cases.push(("ciphertext not bound to proof", c));
    let mut c = part.clone();
    c.transition.txid[0] ^= 1;
    cases.push(("stale state public digest", c));
    let mut c = part.clone();
    c.transition.domain[0] ^= 1;
    c.public = c.transition.inputs();
    cases.push(("foreign domain", c));
    let mut c = full.clone();
    c.transition.payload[8] = 3;
    c.public = c.transition.inputs();
    cases.push(("premature terminal exit", c));
    let mut c = full.clone();
    let nf = nullifier(
        &c.transition.domain,
        &c.secret,
        &c.input.commitment(&c.transition.domain),
    );
    c.transition.old.nullifiers.push(nf);
    let mut next = parse_payload(&c.transition.payload).unwrap().1;
    next.nullifiers.push(nf);
    c.transition.payload[9..CIPHER_START].copy_from_slice(&next.bytes());
    c.public = c.transition.inputs();
    cases.push(("spent-note replay with counts preserved", c));
    for (label, c) in cases {
        eprintln!("negative: {label}");
        assert!(!check(&c), "accepted {label}");
    }
}
#[test]
fn terminal_exit_works_at_capacity() {
    let first = sample().unwrap();
    let full = withdrawal(&first, false);
    let input = first.outputs[1].clone();
    let d = first.transition.domain;
    let old = parse_payload(&full.transition.payload).unwrap().1;
    let fee = native::fee_for(3).unwrap();
    let t = Transition {
        domain: d,
        old: old.clone(),
        txid: [9; 32],
        index: 0,
        reserve_in: input.value,
        reserve_out: 0,
        payout: input.value - fee,
        payout_spk: native::encode_spk(&native::p2pk(&[3; 32]).unwrap()),
        deposit: vec![0; 84],
        payload: payload(3, &old, &[vec![0; 185], vec![0; 185]]).unwrap(),
    };
    let mut c = SpendCircuit {
        public: t.inputs(),
        transition: t,
        secret: [1; 32],
        input,
        outputs: [Note::dummy(), Note::dummy()],
        fee,
    };
    rebuild(&mut c);
    assert!(check(&c));
    while c.transition.old.commitments.len() < CAP {
        let n = c.transition.old.commitments.len() as u8;
        c.transition.old.commitments.push([100 + n; 32]);
        c.transition.old.nullifiers.push([150 + n; 32]);
    }
    rebuild(&mut c);
    assert!(check(&c));
    let mut bad = c.clone();
    bad.transition.reserve_out = 1;
    bad.transition.reserve_in += 1;
    bad.public = bad.transition.inputs();
    assert!(!check(&bad));
}
#[test]
fn encrypted_delivery_and_fresh_native_destinations() {
    let d = new_domain();
    let w = Wallet::fresh();
    let other = Wallet::fresh();
    let n = w.receive(&d).note(1).unwrap();
    let cm = n.commitment(&d);
    let c = n.encrypt(&d).unwrap();
    assert_eq!(w.decrypt(&d, &c, &cm).unwrap().value, 1);
    assert!(other.decrypt(&d, &c, &cm).is_err());
    assert!(w.decrypt(&random(), &c, &cm).is_err());
    let mut keys = std::collections::BTreeSet::new();
    for step in 0..100 {
        let k = w.payout_key(&d, step);
        assert!(native::p2pk(&k).is_ok());
        assert_eq!(k, w.payout_key(&d, step));
        assert!(keys.insert(k));
        assert_ne!(k, w.payout_key(&random(), step));
    }
    let mut s = State {
        commitments: vec![cm],
        nullifiers: vec![],
    };
    for _ in 0..100 {
        let note = w.receive(&d).note(1).unwrap();
        if s.commitments.len() < CAP {
            s.commitments.push(note.commitment(&d));
        }
        assert_eq!(State::parse(&s.bytes()).unwrap(), s);
    }
    let mut bytes = s.bytes();
    bytes[2] = (CAP + 1) as u8;
    assert!(State::parse(&bytes).is_err());
}

#[test]
fn joining_wallet_rejects_forged_bootstrap_descriptor() {
    let honest = State {
        commitments: vec![[1; 32]],
        nullifiers: vec![],
    };
    assert!(crate::app::check_genesis(&honest).is_ok());
    let forged = State {
        commitments: vec![[1; 32], [2; 32]],
        nullifiers: vec![[3; 32]],
    };
    assert!(forged.check().is_ok());
    assert!(crate::app::check_genesis(&forged).is_err());
    let mut extra = honest.clone();
    extra.commitments.push([2; 32]);
    assert!(crate::app::check_genesis(&extra).is_err());
}

#[test]
fn wallet_rejects_notes_that_cannot_self_fund_exit() {
    let minimum = native::fee_for(2).unwrap().max(native::fee_for(3).unwrap()) + 10_000_000;
    for bad in [0, 1, minimum - 1] {
        assert!(crate::app::accept_note_value(bad).is_err());
    }
    assert!(crate::app::accept_note_value(minimum).is_ok());
}

#[test]
fn wallet_quarantines_dust_without_blocking_usable_claims() {
    let w = Wallet::fresh();
    let d = new_domain();
    let good = w.receive(&d).note(100_000_000).unwrap();
    let dust = w.receive(&d).note(1).unwrap();
    let good_cm = good.commitment(&d);
    let dust_cm = dust.commitment(&d);
    let (accepted, rejected) = crate::app::partition_notes(vec![(dust_cm, dust), (good_cm, good)]);
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].0, good_cm);
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].0, dust_cm);
}

#[test]
fn protocol_floor_covers_every_creation_path_and_payout() {
    let first = sample().unwrap();
    let dep = deposit();
    let part = withdrawal(&first, true);
    for value in [MIN_NOTE - 1, MIN_NOTE, MIN_NOTE + 1] {
        let expected = value >= MIN_NOTE;
        let mut c = dep.clone();
        c.outputs[0].value = value;
        c.transition.deposit[40..48].copy_from_slice(&(value + c.fee).to_le_bytes());
        c.transition.reserve_out = c.transition.reserve_in + value;
        rebuild(&mut c);
        eprintln!("floor deposit: {value}");
        assert_eq!(check(&c), expected, "deposit floor {value}");
        for slot in 0..2 {
            let mut c = first.clone();
            c.outputs[slot].value = value;
            c.outputs[1 - slot].value = c.input.value - c.fee - value;
            rebuild(&mut c);
            eprintln!("floor transfer slot {slot}: {value}");
            assert_eq!(check(&c), expected, "transfer slot {slot} floor {value}");
        }
        let mut c = part.clone();
        c.outputs[0].value = value;
        c.transition.payout = c.input.value - c.fee - value;
        c.transition.reserve_out = c.transition.reserve_in - c.transition.payout - c.fee;
        rebuild(&mut c);
        eprintln!("floor partial change: {value}");
        assert_eq!(check(&c), expected, "partial change floor {value}");
    }
    for value in [
        MIN_NATIVE_PAYOUT - 1,
        MIN_NATIVE_PAYOUT,
        MIN_NATIVE_PAYOUT + 1,
    ] {
        let mut c = part.clone();
        c.transition.payout = value;
        c.outputs[0].value = c.input.value - c.fee - value;
        c.transition.reserve_out = c.transition.reserve_in - value - c.fee;
        rebuild(&mut c);
        eprintln!("floor public payout: {value}");
        assert_eq!(
            check(&c),
            value >= MIN_NATIVE_PAYOUT,
            "payout floor {value}"
        );
    }
    // Bypass the honest constructor and native fee policy to isolate the
    // relation's input/bootstrap floor. The other predicates remain valid.
    for value in [MIN_NOTE - 1, MIN_NOTE, MIN_NOTE + 1] {
        let mut c = first.clone();
        c.input.value = value;
        c.outputs = [Note::dummy(), Note::dummy()];
        c.fee = 1;
        c.transition.old = State {
            commitments: vec![c.input.commitment(&c.transition.domain)],
            nullifiers: vec![],
        };
        c.transition.reserve_in = value;
        c.transition.reserve_out = 0;
        c.transition.payout = value - 1;
        c.transition.payout_spk = native::encode_spk(&native::p2pk(&[3; 32]).unwrap());
        c.transition.payload[8] = 3;
        rebuild(&mut c);
        eprintln!("floor bootstrap terminal input: {value}");
        assert_eq!(
            check(&c),
            value >= MIN_NOTE,
            "bootstrap input floor {value}"
        );
    }
}

#[test]
fn native_storage_mass_at_minimum_and_large_note_values() {
    let first = sample().unwrap();
    let mut t = withdrawal(&first, false).transition;
    let exit_fee = native::fee_for(2).unwrap();
    assert_eq!(exit_fee + MIN_NATIVE_PAYOUT, MIN_NOTE);
    let mut values = vec![MIN_NOTE, MIN_NOTE + 1, MIN_NOTE * 2, RESERVE, MAX_SOMPI / 3];
    // Deterministic varying sizes exercise the integer divisions in native
    // storage mass, not just a second copy of the floor implementation.
    let mut x = 0x6a09e667f3bcc909u64;
    for _ in 0..24 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        values.push(MIN_NOTE + x % (MAX_SOMPI / 3 - MIN_NOTE));
    }
    for &spent in &values {
        for &remaining in &values {
            t.reserve_in = spent + remaining;
            t.reserve_out = remaining;
            t.payout = spent - exit_fee;
            let (tx, entries) = native::proof_tx(&t, &[0; 328], &[0; 128], None).unwrap();
            // This control checks native mass/policy only; dummy proof bytes
            // are not evidence of script/proof acceptance.
            let m = native::policy(&tx, &entries).unwrap();
            assert!(m["storage_mass"].as_u64().unwrap() <= 137_434);
            assert!(m["mining_mass"].as_u64().unwrap() * 100 <= exit_fee);
        }
        t.payload[8] = 3;
        t.reserve_in = spent;
        t.reserve_out = 0;
        t.payout = spent - native::fee_for(3).unwrap();
        let (tx, entries) = native::proof_tx(&t, &[0; 328], &[0; 128], None).unwrap();
        assert!(
            native::policy(&tx, &entries).unwrap()["storage_mass"]
                .as_u64()
                .unwrap()
                <= 100_000
        );
        t.payload[8] = 2;
    }
    // A large legitimate claim cannot exit leaving this tiny native reserve:
    // demonstrate the failure prevented by the protocol floor.
    t.reserve_out = 1;
    t.payout = MIN_NATIVE_PAYOUT;
    t.reserve_in = t.reserve_out + t.payout + exit_fee;
    let (tx, entries) = native::proof_tx(&t, &[0; 328], &[0; 128], None).unwrap();
    assert!(native::policy(&tx, &entries).is_err());
}
