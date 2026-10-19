use super::{circuit::AuthorizationCircuit, experiment::*, *};

fn accepted(c: &AuthorizationCircuit) -> bool {
    c.check().map(|(_, ok)| ok).unwrap_or(false)
}
fn refresh(c: &mut AuthorizationCircuit) {
    c.public = c.auth.inputs();
}
fn exit(value: u64) -> AuthorizationCircuit {
    let d = random();
    let w = Wallet::fresh();
    let mut n = w.receive(&d).note(NOTE_FLOOR).unwrap();
    n.value = value;
    let old = State {
        commitments: vec![n.commitment(&d)],
        nullifiers: vec![],
    };
    authorization(
        &w,
        &n,
        &old,
        [Note::dummy(), Note::dummy()],
        d,
        1_000,
        value.saturating_sub(1_000),
        native::encode_spk(&native::p2pk(&[2; 32]).unwrap())
            .try_into()
            .unwrap(),
        0,
    )
    .unwrap()
    .0
}
#[test]
fn authorization_relation_rejects_ownership_membership_binding_and_inflation() {
    let (good, _) = fixture().unwrap();
    assert!(accepted(&good));
    let cases: Vec<(&str, Box<dyn Fn(&mut AuthorizationCircuit)>)> = vec![
        ("wrong owner", Box::new(|c| c.secret[0] ^= 1)),
        (
            "absent member",
            Box::new(|c| {
                c.anchor[0] = random();
                c.auth.anchor = hash(&anchor_bytes(&c.anchor));
            }),
        ),
        ("fake anchor digest", Box::new(|c| c.auth.anchor[0] ^= 1)),
        ("count mismatch", Box::new(|c| c.auth.count += 1)),
        ("wrong pool", Box::new(|c| c.auth.domain[0] ^= 1)),
        ("wrong nullifier", Box::new(|c| c.auth.nullifier[0] ^= 1)),
        (
            "changed output commitment",
            Box::new(|c| c.auth.outputs[0][0] ^= 1),
        ),
        ("inflation", Box::new(|c| c.outputs[0].value += 1)),
        (
            "64-bit sum overflow",
            Box::new(|c| {
                c.outputs[0].value = u64::MAX;
                c.outputs[1].value = u64::MAX;
            }),
        ),
        ("unauthorized fee", Box::new(|c| c.auth.fee += 1)),
        ("zero fee", Box::new(|c| c.auth.fee = 0)),
        ("bootstrap mismatch", Box::new(|c| c.auth.bootstrap += 1)),
        ("unknown mode", Box::new(|c| c.auth.mode = 0)),
        ("payout on transfer", Box::new(|c| c.auth.payout = 1)),
        ("nonzero transfer SPK", Box::new(|c| c.auth.spk[5] = 1)),
    ];
    for (name, mutate) in cases {
        let mut c = good.clone();
        mutate(&mut c);
        refresh(&mut c);
        assert!(!accepted(&c), "{name}");
    }
    let mut wrong_public = good;
    wrong_public.public[0] += Fr::from(1);
    assert!(!accepted(&wrong_public));
}
#[test]
fn integer_and_note_floor_boundaries() {
    for (value, valid) in [
        (NOTE_FLOOR - 1, false),
        (NOTE_FLOOR, true),
        (NOTE_FLOOR + 1, true),
        (MAX_SOMPI - 1, true),
        (MAX_SOMPI, true),
        (MAX_SOMPI + 1, false),
        (u64::MAX, false),
    ] {
        assert_eq!(accepted(&exit(value)), valid, "input {value}");
    }
    let (base, _) = fixture().unwrap();
    for index in 0..2 {
        for value in [NOTE_FLOOR - 1, NOTE_FLOOR, NOTE_FLOOR + 1] {
            let mut c = base.clone();
            c.outputs[index].value = value;
            c.outputs[1 - index].value = RESERVE - value - c.auth.fee;
            c.auth.outputs = c.outputs.clone().map(|n| n.commitment(&c.auth.domain));
            refresh(&mut c);
            assert_eq!(
                accepted(&c),
                value >= NOTE_FLOOR,
                "output {index} value {value}"
            );
        }
    }
    for payout in [PAYOUT_FLOOR - 1, PAYOUT_FLOOR, PAYOUT_FLOOR + 1] {
        let mut c = exit(NOTE_FLOOR);
        c.auth.payout = payout;
        c.auth.fee = NOTE_FLOOR - payout;
        refresh(&mut c);
        assert_eq!(accepted(&c), payout >= PAYOUT_FLOOR, "payout {payout}");
    }
}
#[test]
fn authorization_codec_and_capacity() {
    let (c, b) = fixture().unwrap();
    assert_eq!(c.auth.bytes().len(), AUTH_LEN);
    assert_eq!(
        Authorization::parse(&c.auth.bytes()).unwrap().bytes(),
        c.auth.bytes()
    );
    for n in [0, 1, AUTH_LEN - 1, AUTH_LEN + 1] {
        assert!(Authorization::parse(&vec![0; n]).is_err());
    }
    let mut old = State {
        commitments: vec![],
        nullifiers: vec![],
    };
    for i in 0..CAP {
        old.commitments.push(hash(&[i as u8]));
    }
    let mut a = c.auth.clone();
    a.count = CAP as u8;
    a.anchor = hash(&anchor_bytes(&old.commitments));
    assert!(a.next(&old).is_err(), "two outputs exceed capacity");
    a.mode = 2;
    a.outputs = [[0; 32]; 2];
    assert!(a.next(&old).is_ok(), "exit remains possible at capacity");
    old.nullifiers.push(a.nullifier);
    assert!(a.next(&old).is_err(), "duplicate nullifier");
    let mut malformed = b;
    malformed.ciphertexts[0].push_str("00");
    assert!(malformed.ciphertext_bytes().is_err());
}
#[test]
fn fixed_layout_fee_and_immutable_suffix() {
    let f = fees().unwrap();
    assert!(f.exit + PAYOUT_FLOOR <= NOTE_FLOOR);
    let d = random();
    let vk = [0; 328];
    let old = State {
        commitments: vec![[1; 32]],
        nullifiers: vec![],
    };
    let next = State {
        commitments: vec![[1; 32], [2; 32], [3; 32]],
        nullifiers: vec![[4; 32]],
    };
    let a = covenant::redeem(&d, &old, &vk).unwrap();
    let b = covenant::redeem(&d, &next, &vk).unwrap();
    assert_eq!(a.len(), covenant::REDEEM_LEN);
    assert_eq!(&a[37 + STATE_LEN + 1..], &b[37 + STATE_LEN + 1..]);
    assert_eq!(
        covenant::signature(&[0; 128], &a).unwrap().len(),
        covenant::WITNESS_LEN
    );
}
