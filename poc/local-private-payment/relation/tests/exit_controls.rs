//! Public synthetic direct-exit controls. No original wallet data or setup.
#![cfg(feature = "prover")]
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use kpi_local_private_payment_relation::{
    DOMAIN, Error, ExitCircuit, ExitStatement, MAX, NOTE_FLOOR, PAYOUT_FLOOR,
    circuit::{exit_fixture, fixture},
    key_commitment, membership_root, nullifier, owner, request,
};
use serde_json::{Value, json};

fn assert_cs(c: ExitCircuit, expected: bool) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    c.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert_eq!(cs.is_satisfied().unwrap(), expected);
}
fn rebuild_note(c: &mut ExitCircuit) {
    let cm = c.witness.note.commitment(&c.statement.domain);
    c.statement.anchor = membership_root(&cm, c.witness.position, &c.witness.path).unwrap();
    c.statement.nf = nullifier(
        &c.statement.domain,
        &c.witness.nullifier_secret,
        &cm,
        c.witness.position,
    );
}
fn request_fixture() -> Value {
    let c = exit_fixture();
    json!({
        "schema":request::EXIT_SCHEMA,
        "note_hex168":hex::encode(c.witness.note.bytes()),
        "s_hex32":hex::encode(c.witness.owner_secret),
        "k_hex32":hex::encode(c.witness.nullifier_secret),
        "position":c.witness.position,
        "cm_path_hex":c.witness.path.iter().map(hex::encode).collect::<Vec<_>>()
    })
}
#[test]
fn exit_statement_is_exact_roundtrip_and_role_separated() {
    let c = exit_fixture();
    let bytes = c.statement.bytes();
    assert_eq!(bytes.len(), 152);
    assert_eq!(&bytes[..8], b"KPXAEX01");
    assert_eq!(ExitStatement::parse(&bytes), Ok(c.statement.clone()));
    assert_eq!(&bytes[136..144], &c.statement.payout.to_le_bytes());
    assert_eq!(&bytes[144..152], &c.statement.fee.to_le_bytes());
    for other_tag in [b"KPX8SP01", b"KPX8OU01", b"KPX7EX01"] {
        let mut bad = bytes;
        bad[..8].copy_from_slice(other_tag);
        assert_eq!(ExitStatement::parse(&bad), Err(Error::Encoding));
    }
    assert_eq!(ExitStatement::parse(&bytes[..151]), Err(Error::Length));
    assert_eq!(
        ExitStatement::parse(&[bytes.as_slice(), &[0]].concat()),
        Err(Error::Length)
    );
}
#[test]
fn exit_public_range_checks_reject_overflow_and_invalid_boundaries() {
    for (payout, fee) in [
        (0, NOTE_FLOOR),
        (PAYOUT_FLOOR - 1, NOTE_FLOOR),
        (NOTE_FLOOR, 0),
        (MAX, 1),
        (MAX + 1, 1),
        (1, u64::MAX),
        (u64::MAX, u64::MAX),
    ] {
        let mut s = exit_fixture().statement;
        s.payout = payout;
        s.fee = fee;
        assert_eq!(s.validate(), Err(Error::Range));
    }
    for (payout, fee) in [(PAYOUT_FLOOR, NOTE_FLOOR - PAYOUT_FLOOR), (MAX - 1, 1)] {
        let mut s = exit_fixture().statement;
        s.payout = payout;
        s.fee = fee;
        assert!(s.validate().is_ok());
    }
}
#[test]
fn exit_accepts_exact_claim_boundaries_and_highest_membership_position() {
    for (value, payout, fee, position) in [
        (NOTE_FLOOR, PAYOUT_FLOOR, NOTE_FLOOR - PAYOUT_FLOOR, 0),
        (MAX, MAX - 1, 1, 65_535),
    ] {
        let mut c = exit_fixture();
        c.witness.note.value = value;
        c.witness.position = position;
        c.statement.payout = payout;
        c.statement.fee = fee;
        rebuild_note(&mut c);
        assert_cs(c, true);
    }
}
#[test]
fn exit_constrains_ranges_and_exact_integer_value_without_host_prechecks() {
    for (value, payout, fee) in [
        (NOTE_FLOOR - 1, NOTE_FLOOR - 2, 1),
        (MAX + 1, MAX, 1),
        (NOTE_FLOOR, PAYOUT_FLOOR - 1, NOTE_FLOOR - PAYOUT_FLOOR + 1),
        (NOTE_FLOOR, NOTE_FLOOR, 0),
        (NOTE_FLOOR, MAX, u64::MAX - MAX + NOTE_FLOOR + 1),
    ] {
        let mut c = exit_fixture();
        c.witness.note.value = value;
        c.statement.payout = payout;
        c.statement.fee = fee;
        rebuild_note(&mut c);
        assert_cs(c, false);
    }
    for changed_fee in [19_999_999, 20_000_001] {
        let mut c = exit_fixture();
        c.statement.fee = changed_fee;
        assert!(c.statement.validate().is_ok());
        assert_cs(c, false);
    }
}
#[test]
fn exit_rejects_wrong_authority_key_and_membership_root() {
    let mut c = exit_fixture();
    c.witness.owner_secret[0] ^= 1;
    assert_cs(c, false);
    let mut c = exit_fixture();
    c.witness.nullifier_secret[0] ^= 1;
    rebuild_note(&mut c);
    assert_cs(c, false);
    let mut c = exit_fixture();
    c.witness.path[15][0] ^= 1;
    assert_cs(c, false);
    let mut c = exit_fixture();
    c.statement.anchor[0] ^= 1;
    assert_cs(c, false);
    let mut c = exit_fixture();
    c.statement.nf[0] ^= 1;
    assert_cs(c, false);
}
#[test]
fn exit_rejects_high_position_alias_and_rebuilt_foreign_domain() {
    let mut c = exit_fixture();
    c.witness.position += 65_536;
    let cm = c.witness.note.commitment(&DOMAIN);
    c.statement.nf = nullifier(
        &DOMAIN,
        &c.witness.nullifier_secret,
        &cm,
        c.witness.position,
    );
    assert_cs(c, false);
    let mut c = exit_fixture();
    c.statement.domain[0] ^= 1;
    c.witness.note.owner = owner(
        &c.statement.domain,
        &c.witness.owner_secret,
        &c.witness.note.incoming,
    );
    c.witness.note.key_commitment =
        key_commitment(&c.statement.domain, &c.witness.nullifier_secret);
    rebuild_note(&mut c);
    assert_cs(c, false);
}
#[test]
fn same_note_keeps_the_same_nf_across_exit_spend_and_effects() {
    let (spend, _) = fixture();
    let mut exit = exit_fixture();
    assert_eq!(spend.statement.nf, exit.statement.nf);
    let original_nf = exit.statement.nf;
    exit.statement.effects_digest[0] ^= 1;
    rebuild_note(&mut exit);
    assert_eq!(original_nf, exit.statement.nf);
    assert_ne!(spend.statement.digest(), exit.statement.digest());
}
#[test]
fn exit_private_request_is_strict_and_has_no_blinding_field() {
    let good = request_fixture();
    let raw = serde_json::to_vec(&good).unwrap();
    let parsed = request::parse_exit(&raw).unwrap();
    assert_eq!(parsed.position, 3);
    for field in good.as_object().unwrap().keys() {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(request::parse_exit(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    for (field, value) in [
        ("schema", json!(request::SPEND_SCHEMA)),
        ("blind_hex32", json!("00".repeat(32))),
        ("s_hex32", json!("AF".repeat(32))),
        ("position", json!(-1)),
        ("position", json!(4_294_967_296_u64)),
        ("cm_path_hex", json!(vec!["00".repeat(32); 15])),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(request::parse_exit(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let raw = serde_json::to_string(&good).unwrap();
    let duplicate = format!("{{\"schema\":\"{}\",{}", request::EXIT_SCHEMA, &raw[1..]);
    assert!(request::parse_exit(duplicate.as_bytes()).is_err());
    assert!(
        request::parse_exit(
            &serde_json::to_vec(&good.as_object().unwrap().values().collect::<Vec<_>>()).unwrap()
        )
        .is_err()
    );
    assert!(request::parse_exit(&vec![b' '; request::MAX_REQUEST_BYTES + 1]).is_err());
}
