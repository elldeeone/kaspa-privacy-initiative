//! Public synthetic controls of the pinned v6 relation; never setup or prove.
#![allow(dead_code, unused_imports)]
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use serde_json::json;
use std::time::Instant;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[path = "../../shared-pool/src/protocol.rs"]
pub mod protocol;
pub mod compact {
    use crate::protocol::H;
    include!(concat!(env!("OUT_DIR"), "/compact.rs"));
}
pub mod two_input {
    use crate::{Result, protocol::{H, MAX_SOMPI, NOTE_TAG, Note, OWNER_TAG, hash, random}};
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
    pub mod tree {
        use super::*;
        include!(concat!(env!("OUT_DIR"), "/tree.rs"));
    }
    pub mod circuit {
        include!(concat!(env!("OUT_DIR"), "/circuit.rs"));
        // Invoke the exact private bounds helper in the same lexical module.
        // This is helper evidence, separate from complete-circuit satisfaction.
        pub fn bounds_control(value: u64, active: bool) -> R<(usize, Option<String>)> {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let bytes = B::new_witness_vec(cs.clone(), &value.to_le_bytes())?;
            let flag = Flag::new_witness(cs.clone(), || Ok(active))?;
            bounds(cs.clone(), &bytes, value, NOTE_FLOOR, &flag)?;
            Ok((cs.num_constraints(), cs.which_is_unsatisfied()?))
        }
    }
}
use protocol::{H, MAX_SOMPI, Note, Wallet};
use two_input::{Authorization, FEE, NOTE_FLOOR, PAYOUT_FLOOR};
use two_input::circuit::{Circuit, Input};
const D: H = [9; 32];
// These disclosed fixed development bytes instantiate the existing harness
// fixture shape. They are not secrets, evaluation seeds, or funded wallets.
fn wallet(owner: u8) -> Wallet {
    Wallet { spending: [1 + owner * 3; 32], viewing: [2 + owner * 3; 32], native: [3 + owner * 3; 32] }
}
fn note(owner: u8, value: u64, rho: u8) -> Note {
    let r = wallet(owner).receive(&D);
    Note { owner: r.owner, incoming: r.incoming, value, rho: [rho; 32] }
}
fn padding(slot: u8) -> Input {
    Input { real: false, note: Note::dummy(), secret: [0; 32], position: 0,
        path: vec![[0; 32]; 16], dummy_key: [50 + slot; 32], dummy_seed: [60 + slot; 32] }
}
fn selected(n: Note, owner: u8, position: u32) -> Input {
    Input { real: true, note: n, secret: wallet(owner).spending, position,
        path: vec![[0; 32]; 16], dummy_key: [0; 32], dummy_seed: [0; 32] }
}
fn refresh_nfs(c: &mut Circuit) {
    c.auth.nfs = std::array::from_fn(|slot| {
        let i = &c.inputs[slot];
        if c.auth.mode == 0 { [0; 32] } else if i.real {
            compact::nullifier(&D, &i.secret, &i.note.commitment(&D), i.position)
        } else { two_input::dummy_nf(&D, &i.dummy_key, &i.dummy_seed, slot as u8) }
    });
}
fn refresh_outputs(c: &mut Circuit) {
    c.auth.outputs = if c.auth.mode == 2 { [[0; 32]; 2] }
        else { c.outputs.each_ref().map(|n| n.commitment(&D)) };
}
fn refresh_membership(c: &mut Circuit) {
    let count = c.inputs.iter().filter(|i| i.real).map(|i| i.position + 1).max().unwrap().max(3);
    let mut leaves = vec![two_input::tree::cm_leaf(&note(0, 2_000_000_000, 10).commitment(&D)); count as usize];
    for i in c.inputs.iter().filter(|i| i.real) {
        leaves[i.position as usize] = two_input::tree::cm_leaf(&i.note.commitment(&D));
    }
    let tree = two_input::tree::Tree::new(leaves, 16).unwrap();
    for i in c.inputs.iter_mut().filter(|i| i.real) { i.path = tree.path(i.position).unwrap(); }
    c.auth.count = count;
    c.auth.anchor = tree.root();
    refresh_nfs(c);
}
fn blank(inputs: [Input; 2], outputs: [Note; 2]) -> Circuit {
    let mut c = Circuit { inputs, outputs, auth: Authorization {
        domain: D, count: 0, anchor: [0; 32], nfs: [[0; 32]; 2], outputs: [[0; 32]; 2],
        mode: 1, payout: 0, fee: FEE, spk: [0; 36], deposit: 0, funding: [0; 36],
        funding_spk: [0; 36], bootstrap: 0, cipher_hash: [80; 32],
    }};
    refresh_membership(&mut c);
    refresh_outputs(&mut c);
    c
}
fn baseline() -> Circuit {
    // Existing circuit_controls' 900m+1060m -> 731m+1189m+40m
    // with two disclosed owners and input slots intentionally reversed.
    blank([selected(note(1, 1_060_000_000, 12), 1, 2), selected(note(0, 900_000_000, 11), 0, 1)],
        [note(1, 731_000_000, 19), note(0, 1_189_000_000, 20)])
}
fn single(slot: usize) -> Circuit {
    let mut inputs = [padding(0), padding(1)];
    inputs[slot] = selected(note(0, 2_000_000_000, 10), 0, 1);
    blank(inputs, [note(0, 900_000_000, 19), note(0, 1_060_000_000, 20)])
}
fn payout_spk() -> [u8; 36] {
    let mut s = [7; 36]; s[..3].copy_from_slice(&[0, 0, 0x20]); s[35] = 0xac; s
}
fn metadata(name: &str) -> (bool, &'static str, &'static str) {
    match name {
        "mixed-owner-reversed" => (true, "circuit:136-139,180-205,212-218", "Both owners and positioned nullifiers valid; reversed slots preserve conservation"),
        "wrong-owner-repaired-nf" => (false, "circuit:136-139", "Alter only spend secret and recompute its public nullifier; owner opening, membership and balance unchanged"),
        "slot1-only" => (true, "circuit:140-150,199-212", "Slot0 canonical padding; slot1 owns the only real input and its slot1 nullifier"),
        "same-commitment-distinct-positions" => (true, "circuit:180-205,213-218", "Same note opening at positions1 and2 has valid distinct positioned nullifiers"),
        "aggregate-max" => (true, "circuit:255-270", "Each input in range; total exactlyMAX; balanced outputs and positive fee"),
        "aggregate-max-plus-one" => (false, "circuit:255-267", "Each input/output in range; recomputed membership/NFs; balanced totalMAX+1 isolates aggregate upper limit"),
        "fee-zero" => (false, "circuit:245", "Fee0 with compensated valid output; only fee lower bound violated"),
        "fee-only-burn" => (false, "circuit:249", "All value assigned to in-range fee; no payout or positive output"),
        "drain-positive-output" => (false, "circuit:227", "DRAIN with valid positive payout, zero public output commitments and conserved60m hidden output"),
        "payout-below-floor" => (false, "circuit:244", "Positive payout one below floor; valid-shaped SPK and compensated change"),
        "padding-value-compensated" => (false, "circuit:142", "Padding has60m value, with output increased60m; all other padding fields zero and dummyNF unchanged"),
        "padding-secret" => (false, "circuit:140-142", "Padding secret nonzero while dummy derivation, note, membership gating and balance unchanged"),
        "bounds-max" => (true, "circuit:62-72", "Exact private helper at inclusiveMAX"),
        "bounds-max-plus-one" => (false, "circuit:62-72", "Exact private helper aboveMAX, independent of total conservation"),
        "bounds-u64-max" => (false, "circuit:62-72", "Exact private helper at u64MAX, no field wrap"),
        "bounds-inactive-max-plus-one" => (true, "circuit:62-72", "Exact helper is conditional; inactive range guard permits valueMAX+1 only in this helper harness"),
        _ => panic!("unknown finite case {name}"),
    }
}
fn circuit_case(name: &str) -> Circuit {
    let mut c = baseline();
    match name {
        "mixed-owner-reversed" => {},
        "wrong-owner-repaired-nf" => { c.inputs[1].secret[0] ^= 1; refresh_nfs(&mut c); },
        "slot1-only" => c = single(1),
        "same-commitment-distinct-positions" => {
            c.inputs[0] = selected(note(0, 900_000_000, 11), 0, 2);
            c.outputs[1].value = 1_029_000_000;
            refresh_membership(&mut c); refresh_outputs(&mut c);
            assert_ne!(c.auth.nfs[0], c.auth.nfs[1]);
        },
        "aggregate-max" | "aggregate-max-plus-one" => {
            let extra = u64::from(name.ends_with("plus-one"));
            c.inputs[0].note.value = MAX_SOMPI / 2;
            c.inputs[1].note.value = MAX_SOMPI - MAX_SOMPI / 2 + extra;
            c.outputs[0].value = NOTE_FLOOR;
            c.outputs[1].value = MAX_SOMPI + extra - NOTE_FLOOR - FEE;
            refresh_membership(&mut c); refresh_outputs(&mut c);
        },
        "fee-zero" => { c.outputs[1].value += c.auth.fee; c.auth.fee = 0; refresh_outputs(&mut c); },
        "fee-only-burn" => {
            c.auth.fee = c.inputs.iter().map(|i| i.note.value).sum();
            c.outputs[0].value = 0; c.outputs[1].value = 0; refresh_outputs(&mut c);
        },
        "drain-positive-output" => {
            c = single(0); c.auth.mode = 2; c.outputs[0].value = NOTE_FLOOR; c.outputs[1].value = 0;
            c.auth.payout = 2_000_000_000 - NOTE_FLOOR - FEE;
            c.auth.spk = payout_spk(); refresh_outputs(&mut c);
        },
        "payout-below-floor" => {
            c.auth.payout = PAYOUT_FLOOR - 1; c.auth.spk = payout_spk();
            c.outputs[1].value -= c.auth.payout; refresh_outputs(&mut c);
        },
        "padding-value-compensated" => {
            c = single(0); c.inputs[1].note.value = NOTE_FLOOR;
            c.outputs[1].value += NOTE_FLOOR; refresh_outputs(&mut c);
        },
        "padding-secret" => { c = single(0); c.inputs[1].secret[0] = 1; },
        _ => panic!("not full circuit"),
    }
    c
}
const CASES: [&str; 16] = ["mixed-owner-reversed", "wrong-owner-repaired-nf", "slot1-only",
    "same-commitment-distinct-positions", "aggregate-max", "aggregate-max-plus-one", "fee-zero", "fee-only-burn",
    "drain-positive-output", "payout-below-floor", "padding-value-compensated", "padding-secret",
    "bounds-max", "bounds-max-plus-one", "bounds-u64-max", "bounds-inactive-max-plus-one"];
fn main() -> Result<()> {
    let name = std::env::args().nth(1).ok_or("specify one finite case or list")?;
    if name == "list" { for c in CASES { println!("{c}"); } return Ok(()); }
    let (expected, source, isolation) = metadata(&name);
    let start = Instant::now();
    let helper = name.starts_with("bounds-");
    let (count, failure) = if helper {
        let value = match name.as_str() { "bounds-max" => MAX_SOMPI, "bounds-u64-max" => u64::MAX, _ => MAX_SOMPI + 1 };
        two_input::circuit::bounds_control(value, name != "bounds-inactive-max-plus-one")?
    } else {
        let c = circuit_case(&name);
        let input_total: u128 = c.inputs.iter().map(|i| i.note.value as u128).sum::<u128>() + c.auth.deposit as u128;
        let output_total: u128 = c.outputs.iter().map(|n| n.value as u128).sum::<u128>() + c.auth.payout as u128 + c.auth.fee as u128;
        assert_eq!(input_total, output_total, "all selected controls preserve integer conservation");
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone())?;
        (cs.num_constraints(), cs.which_is_unsatisfied()?)
    };
    let satisfied = failure.is_none();
    println!("{}", json!({"case":name,"kind":if helper {"exact_bounds_helper"} else {"full_circuit_constraint_satisfaction"},
        "expected_satisfied":expected,"satisfied":satisfied,"passed":satisfied==expected,
        "constraints":count,"first_unsatisfied":failure,"elapsed_ms":start.elapsed().as_millis(),
        "source_branch":source,"isolation":isolation,"proof_generated":false,"native_or_chain_result":false}));
    if satisfied != expected { return Err("unexpected constraint result; stop lane".into()); }
    Ok(())
}
