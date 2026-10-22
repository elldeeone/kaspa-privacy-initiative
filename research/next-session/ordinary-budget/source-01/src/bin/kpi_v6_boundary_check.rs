//! Fixed PUBLIC constraint-only vectors. No setup, proof, key-file, wallet or ledger API.
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use kpi_shared_pool::{
    Result,
    protocol::{H, MAX_SOMPI, Note, OWNER_TAG, hash, tagged},
    two_input::{
        self, Authorization, NOTE_FLOOR,
        circuit::{Circuit, Input},
        tree::{Tree, cm_leaf},
    },
};
use serde_json::json;
use std::time::Instant;

const CONSTRAINTS: usize = 4_372_824;
const FEE: u64 = 40_000_000;
const CASES: &[(&str, &str)] = &[
    ("baseline-two-real", "satisfied"),
    ("aggregate-max", "satisfied"),
    ("aggregate-max-plus-one", "unsatisfied"),
    ("input-floor", "satisfied"),
    ("input-floor-minus-one", "unsatisfied"),
    ("output-floor", "satisfied"),
    ("output-floor-minus-one", "unsatisfied"),
    ("zero-output-padding", "satisfied"),
    ("one-sompi-output", "unsatisfied"),
    ("both-zero-outputs", "unsatisfied"),
    ("fee-one", "satisfied"),
    ("fee-zero", "unsatisfied"),
    ("inflation-one", "unsatisfied"),
    ("deflation-one", "unsatisfied"),
    ("last-16-bit-position", "satisfied"),
    ("position-16-bit-alias", "unsatisfied"),
    ("count-underflow", "unsatisfied"),
    ("count-u32-max", "satisfied"),
    ("real-input-swap", "satisfied"),
    ("inactive-real-dummy-keys", "satisfied"),
    ("baseline-one-real", "satisfied"),
    ("padding-secret", "unsatisfied"),
    ("padding-owner", "unsatisfied"),
    ("padding-incoming", "unsatisfied"),
    ("padding-rho", "unsatisfied"),
    ("padding-position", "unsatisfied"),
    ("padding-path", "unsatisfied"),
    ("unsupported-mode", "unsatisfied"),
    ("path-short", "synthesis-error"),
    ("path-long", "synthesis-error"),
];

fn label(text: &str) -> H {
    hash(
        &[
            b"KPI/PUBLIC/DO-NOT-FUND/v6-constraint-boundaries/v1/",
            text.as_bytes(),
        ]
        .concat(),
    )
}
fn note(domain: H, slot: usize, value: u64, output: bool) -> Note {
    let prefix = if output { "output" } else { "input" };
    let incoming = label(&format!("{prefix}/{slot}/incoming"));
    let secret = label(&format!("{prefix}/{slot}/secret"));
    Note {
        owner: tagged(OWNER_TAG, &domain, &[&secret, &incoming]),
        incoming,
        value,
        rho: label(&format!("{prefix}/{slot}/rho")),
    }
}
fn padding() -> Input {
    Input {
        real: false,
        note: Note::dummy(),
        secret: [0; 32],
        position: 0,
        path: vec![[0; 32]; 16],
        dummy_key: label("padding/key"),
        dummy_seed: label("padding/seed"),
    }
}

/// Rebuild all amount-dependent CMs, paths and NFs instead of masking an
/// integer failure with an unrelated stale commitment/membership failure.
fn fixture(
    values: [u64; 2],
    outputs: [u64; 2],
    fee: u64,
    positions: [u32; 2],
    count: u32,
    two_real: bool,
) -> Result<Circuit> {
    let domain = label("domain");
    let notes = std::array::from_fn::<_, 2, _>(|i| note(domain, i, values[i], false));
    // The alias control deliberately supplies the low-16-bit Merkle path for
    // a high-bit position. The circuit must reject that position explicitly.
    let physical = positions.map(|p| p & 0xffff);
    let len = if two_real {
        physical.into_iter().max().unwrap() as usize + 1
    } else {
        physical[0] as usize + 1
    }
    .max(5);
    let mut leaves: Vec<H> = (0..len)
        .map(|i| cm_leaf(&label(&format!("filler/{i}"))))
        .collect();
    leaves[physical[0] as usize] = cm_leaf(&notes[0].commitment(&domain));
    if two_real {
        leaves[physical[1] as usize] = cm_leaf(&notes[1].commitment(&domain));
    }
    let tree = Tree::new(leaves, 16)?;
    let inputs = std::array::from_fn(|i| {
        if i == 1 && !two_real {
            padding()
        } else {
            Input {
                real: true,
                note: notes[i].clone(),
                secret: label(&format!("input/{i}/secret")),
                position: positions[i],
                path: tree.path(physical[i]).unwrap(),
                dummy_key: [0; 32],
                dummy_seed: [0; 32],
            }
        }
    });
    let outs = std::array::from_fn(|i| note(domain, i, outputs[i], true));
    let nfs = std::array::from_fn(|i| {
        let input: &Input = &inputs[i];
        if input.real {
            kpi_shared_pool::compact::nullifier(
                &domain,
                &input.secret,
                &input.note.commitment(&domain),
                input.position,
            )
        } else {
            two_input::dummy_nf(&domain, &input.dummy_key, &input.dummy_seed, i as u8)
        }
    });
    let auth = Authorization {
        domain,
        count,
        anchor: tree.root(),
        nfs,
        outputs: outs.each_ref().map(|n| n.commitment(&domain)),
        mode: 1,
        payout: 0,
        fee,
        spk: [0; 36],
        deposit: 0,
        funding: [0; 36],
        funding_spk: [0; 36],
        bootstrap: 0,
        cipher_hash: label("cipher-hash-declaration-not-delivery-evidence"),
    };
    Ok(Circuit {
        auth,
        inputs,
        outputs: outs,
    })
}

fn case(name: &str) -> Result<Circuit> {
    let mut values = [400_000_000, 360_000_000];
    let mut outputs = [320_000_000, 400_000_000];
    let mut fee = FEE;
    let mut positions = [1, 3];
    let mut count = 5;
    let one = name == "baseline-one-real" || name.starts_with("padding-");
    if one {
        values = [120_000_000, 0];
        outputs = [80_000_000, 0];
    }
    match name {
        "aggregate-max" => {
            values = [MAX_SOMPI - NOTE_FLOOR, NOTE_FLOOR];
            outputs = [MAX_SOMPI - FEE - NOTE_FLOOR, NOTE_FLOOR];
        }
        "aggregate-max-plus-one" => {
            values = [MAX_SOMPI - NOTE_FLOOR + 1, NOTE_FLOOR];
            outputs = [MAX_SOMPI - FEE - NOTE_FLOOR + 1, NOTE_FLOOR];
        }
        "input-floor" => {
            values = [NOTE_FLOOR, NOTE_FLOOR];
            outputs = [2 * NOTE_FLOOR - FEE, 0];
        }
        "input-floor-minus-one" => {
            values = [NOTE_FLOOR - 1, NOTE_FLOOR];
            outputs = [2 * NOTE_FLOOR - FEE - 1, 0];
        }
        "output-floor" => {
            outputs = [NOTE_FLOOR, 720_000_000 - NOTE_FLOOR];
        }
        "output-floor-minus-one" => {
            outputs = [NOTE_FLOOR - 1, 720_000_000 - NOTE_FLOOR + 1];
        }
        "zero-output-padding" => {
            outputs = [0, 720_000_000];
        }
        "one-sompi-output" => {
            outputs = [1, 719_999_999];
        }
        "both-zero-outputs" => {
            outputs = [0, 0];
            fee = 760_000_000;
        }
        "fee-one" => {
            outputs = [759_999_999, 0];
            fee = 1;
        }
        "fee-zero" => {
            outputs = [760_000_000, 0];
            fee = 0;
        }
        "inflation-one" => {
            outputs[0] += 1;
        }
        "deflation-one" => {
            outputs[0] -= 1;
        }
        "last-16-bit-position" => {
            positions[0] = 65_535;
            count = 65_536;
        }
        "position-16-bit-alias" => {
            positions[0] = 65_536;
            count = 65_537;
        }
        "count-underflow" => {
            count = 3;
        }
        "count-u32-max" => {
            count = u32::MAX;
        }
        _ => {}
    }
    let mut c = fixture(values, outputs, fee, positions, count, !one)?;
    match name {
        "real-input-swap" => {
            c.inputs.swap(0, 1);
            c.auth.nfs.swap(0, 1);
        }
        "inactive-real-dummy-keys" => {
            for (i, input) in c.inputs.iter_mut().enumerate() {
                input.dummy_key = label(&format!("unused-real-key/{i}"));
                input.dummy_seed = label(&format!("unused-real-seed/{i}"));
            }
        }
        "padding-secret" => {
            c.inputs[1].secret[0] = 1;
        }
        "padding-owner" => {
            c.inputs[1].note.owner[0] = 1;
        }
        "padding-incoming" => {
            c.inputs[1].note.incoming[0] = 1;
        }
        "padding-rho" => {
            c.inputs[1].note.rho[0] = 1;
        }
        "padding-position" => {
            c.inputs[1].position = 1;
        }
        "padding-path" => {
            c.inputs[1].path[0][0] = 1;
        }
        "unsupported-mode" => {
            c.auth.mode = 3;
        }
        "path-short" => {
            c.inputs[1].path.pop();
        }
        "path-long" => {
            c.inputs[1].path.push([0; 32]);
        }
        _ => {}
    }
    Ok(c)
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["list"] {
        println!(
            "{}",
            json!({"format":"v6-boundary-case-manifest-v1", "public_test_only":true,
            "full_constraint_cases":28,"synthesis_shape_cases":2,
            "cases":CASES.iter().map(|(id,expected)|json!({"id":id,"expected":expected})).collect::<Vec<_>>() })
        );
        return Ok(());
    }
    if args.len() != 2 || args[0] != "check" {
        return Err("usage: kpi_v6_boundary_check list | check FIXED_CASE_ID".into());
    }
    let name = &args[1];
    let expected = CASES
        .iter()
        .find(|(id, _)| id == name)
        .ok_or("unknown fixed case")?
        .1;
    let c = case(name)?;
    let total = c
        .inputs
        .iter()
        .map(|i| u128::from(i.note.value))
        .sum::<u128>();
    let out = c.outputs.iter().map(|n| u128::from(n.value)).sum::<u128>() + u128::from(c.auth.fee);
    let auth_sha256 = hex::encode(hash(&c.auth.bytes()));
    let started = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let synthesis = c.generate_constraints(cs.clone());
    let (actual, diagnostic) = match synthesis {
        Ok(()) => {
            let why = cs.which_is_unsatisfied()?;
            (
                if why.is_none() {
                    "satisfied"
                } else {
                    "unsatisfied"
                },
                why,
            )
        }
        Err(error) => ("synthesis-error", Some(format!("{error:?}"))),
    };
    let constraints = cs.num_constraints();
    let passed =
        actual == expected && (expected == "synthesis-error" || constraints == CONSTRAINTS);
    println!(
        "{}",
        json!({"case":name,"expected":expected,"actual":actual,"passed":passed,
        "constraints":constraints,"constraint_seconds":started.elapsed().as_secs_f64(),
        "diagnostic":diagnostic,"authorization_sha256":auth_sha256,
        "input_sum_u128":total.to_string(),"output_plus_fee_u128":out.to_string(),
        "value_conservation_as_integers":total==out,"input_total_within_MAX":total<=u128::from(MAX_SOMPI),
        "constraint_only":true,"proof_generated":false,"native_acceptance_claim":false})
    );
    if !passed {
        return Err(format!("fixed expectation/count mismatch: {name}").into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("v6 boundary constraint check: {error}");
        std::process::exit(1);
    }
}
