//! Public synthetic relation fixtures, never accepted history or live keys.
use crate::{
    circuit::{ActionCircuit, InputWitness},
    *,
};
use serde::Deserialize;

type ParseResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const CLASS: &str = "PUBLIC_SYNTHETIC_DO_NOT_FUND";
pub const POSITIVES: &[&str] = &[
    "spend",
    "change",
    "owned-full",
    "terminal",
    "terminal-one",
    "terminal-full-count",
    "max-terminal",
];
pub const NEGATIVES: &[&str] = &[
    "wrong-s",
    "wrong-k",
    "copied-k-no-s",
    "all-dummy",
    "dummy-s",
    "real-dummy-seed",
    "wrong-path",
    "high-position",
    "wrong-nf",
    "wrong-dummy-slot",
    "duplicate-nf",
    "zero-nf",
    "output-cm",
    "subfloor-output",
    "out-of-range-input",
    "wrong-domain",
    "wrong-state-domain",
    "fee-reserve",
    "count-capacity",
    "payout-conservation",
    "p0-destination",
    "p-positive-zero-spk",
    "payout-version",
    "payout-prefix",
    "payout-opcode",
    "payout-subfloor",
    "payout-key-input0",
    "payout-key-input1",
    "subfloor-reserve",
    "terminal-rho",
    "terminal-value",
    "terminal-owner",
    "terminal-cm",
    "terminal-cipher-hash",
    "terminal-cm-root",
    "terminal-cm-count",
    "terminal-nf-count",
    "terminal-zero-payout",
    "spend-no-positive-output",
    "overflow-sum",
];

fn fixed<const N: usize>(value: &str) -> ParseResult<[u8; N]> {
    let raw = hex::decode(value)?;
    if hex::encode(&raw) != value {
        return Err("noncanonical hex".into());
    }
    raw.try_into().map_err(|_| "fixed width".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    real: bool,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
    dummy_key_hex32: String,
    dummy_seed_hex32: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    note_hex168: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    classification: String,
    auth_hex528: String,
    inputs: [Input; 2],
    outputs: [Output; 2],
}

pub fn from_bytes(raw: &[u8]) -> ParseResult<ActionCircuit> {
    let f: Fixture = serde_json::from_slice(raw)?;
    if f.classification != CLASS {
        return Err("public unfunded fixture required".into());
    }
    let mut inputs = Vec::new();
    for i in f.inputs {
        let mut path = [[0; 32]; 16];
        for (to, from) in path.iter_mut().zip(&i.cm_path_hex) {
            *to = fixed(from)?;
        }
        inputs.push(InputWitness {
            real: i.real,
            note: Note::parse(&fixed::<168>(&i.note_hex168)?)?,
            owner_secret: fixed(&i.s_hex32)?,
            nullifier_secret: fixed(&i.k_hex32)?,
            position: i.position,
            path,
            dummy_key: fixed(&i.dummy_key_hex32)?,
            dummy_seed: fixed(&i.dummy_seed_hex32)?,
        });
    }
    Ok(ActionCircuit {
        authorization: Authorization::parse(&fixed::<528>(&f.auth_hex528)?)?,
        inputs: inputs.try_into().map_err(|_| "input count")?,
        outputs: [
            Note::parse(&fixed::<168>(&f.outputs[0].note_hex168)?)?,
            Note::parse(&fixed::<168>(&f.outputs[1].note_hex168)?)?,
        ],
    })
}

pub fn to_value(c: &ActionCircuit) -> serde_json::Value {
    serde_json::json!({"classification":CLASS,"auth_hex528":hex::encode(c.authorization.bytes()),
      "inputs":c.inputs.iter().map(|i|serde_json::json!({"real":i.real,"note_hex168":hex::encode(i.note.bytes()),
        "s_hex32":hex::encode(i.owner_secret),"k_hex32":hex::encode(i.nullifier_secret),"position":i.position,
        "cm_path_hex":i.path.iter().map(hex::encode).collect::<Vec<_>>(),"dummy_key_hex32":hex::encode(i.dummy_key),
        "dummy_seed_hex32":hex::encode(i.dummy_seed)})).collect::<Vec<_>>(),
      "outputs":c.outputs.iter().map(|n|serde_json::json!({"note_hex168":hex::encode(n.bytes())})).collect::<Vec<_>>()})
}

fn note(index: u8, value: u64) -> (Note, H, H) {
    let s = [0x11 + index; 32];
    let k = [0x21 + index; 32];
    let incoming = [0x31 + index; 32];
    let native_pk = if index == 0 {
        fixed("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
    } else {
        fixed("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9").unwrap()
    };
    (
        Note {
            owner: owner(&DOMAIN, &s, &incoming),
            incoming,
            value,
            rho: hash(&[b"PUBLIC-UNFUNDED-input", &[index]]),
            key_commitment: key_commitment(&DOMAIN, &k),
            native_pk,
        },
        s,
        k,
    )
}
fn path_root(notes: &[Note]) -> (H, [[H; CM_DEPTH]; 2]) {
    let mut paths = [[[0; 32]; CM_DEPTH]; 2];
    let mut empty = hash(&[CM_EMPTY]);
    let first = notes[0].commitment(&DOMAIN);
    let second = notes.get(1).map(|n| n.commitment(&DOMAIN)).unwrap_or(empty);
    paths[0][0] = second;
    paths[1][0] = first;
    let mut root = hash(&[CM_NODE, &first, &second]);
    empty = hash(&[CM_NODE, &empty, &empty]);
    for level in 1..CM_DEPTH {
        paths[0][level] = empty;
        paths[1][level] = empty;
        root = hash(&[CM_NODE, &root, &empty]);
        empty = hash(&[CM_NODE, &empty, &empty]);
    }
    (root, paths)
}
fn output(index: u8, value: u64) -> Note {
    if value == 0 {
        let mut n = Note::zero();
        n.rho = hash(&[b"PUBLIC-UNFUNDED-dummy-rho", &[index]]);
        n
    } else {
        let mut n = note(index, value).0;
        n.rho = hash(&[b"PUBLIC-UNFUNDED-output", &[index]]);
        n
    }
}

/// Public R1CS-only roots/counts. NF/next-CM roots are transcript placeholders;
/// full-count case is a count boundary, not a proven historical ledger.
pub fn positive(kind: &str) -> ParseResult<ActionCircuit> {
    if !POSITIVES.contains(&kind) {
        return Err("unknown positive fixture".into());
    }
    let one_note = matches!(kind, "terminal-one" | "max-terminal");
    let input_value = if kind == "max-terminal" {
        MAX
    } else {
        1_000_000_000
    };
    let a = note(0, input_value);
    let b = note(1, 1_000_000_000);
    let (root, paths) = path_root(if one_note {
        std::slice::from_ref(&a.0)
    } else {
        &[a.0.clone(), b.0.clone()]
    });
    let first = InputWitness {
        real: true,
        note: a.0.clone(),
        owner_secret: a.1,
        nullifier_secret: a.2,
        position: 0,
        path: paths[0],
        dummy_key: [0; 32],
        dummy_seed: [0; 32],
    };
    let padding = InputWitness {
        real: false,
        note: Note::zero(),
        owner_secret: [0; 32],
        nullifier_secret: [0; 32],
        position: 0,
        path: [[0; 32]; CM_DEPTH],
        dummy_key: [0x73; 32],
        dummy_seed: [0x74; 32],
    };
    let second = if matches!(kind, "spend" | "terminal" | "terminal-full-count") {
        InputWitness {
            real: true,
            note: b.0.clone(),
            owner_secret: b.1,
            nullifier_secret: b.2,
            position: 1,
            path: paths[1],
            dummy_key: [0; 32],
            dummy_seed: [0; 32],
        }
    } else {
        padding
    };
    let reserve = if one_note { input_value } else { 2_000_000_000 };
    let fee = if kind == "max-terminal" {
        1
    } else {
        20_000_000
    };
    let payout = match kind {
        "spend" => 0,
        "change" => 400_000_000,
        "owned-full" => 980_000_000,
        "max-terminal" => MAX - 1,
        _ => reserve - fee,
    };
    let after = reserve - payout - fee;
    let terminal = after == 0;
    let outputs = if terminal {
        [Note::zero(), Note::zero()]
    } else if kind == "spend" {
        [output(2, 1_000_000_000), output(3, 980_000_000)]
    } else if kind == "change" {
        [output(2, 580_000_000), output(3, 0)]
    } else {
        [output(2, 0), output(3, 0)]
    };
    let n = if kind == "terminal-full-count" {
        MAX_NOTES
    } else if one_note {
        1
    } else {
        2
    };
    let prior = State {
        domain: DOMAIN,
        cm_root: root,
        n,
        nf_root: [0x31; 32],
        m: 1,
    };
    let next = State {
        domain: DOMAIN,
        cm_root: if terminal { root } else { [0x41; 32] },
        n: if terminal { n } else { n + 2 },
        nf_root: [0x42; 32],
        m: 3,
    };
    let nf0 = nullifier(&DOMAIN, &a.2, &a.0.commitment(&DOMAIN), 0);
    let nf1 = if second.real {
        nullifier(&DOMAIN, &b.2, &b.0.commitment(&DOMAIN), 1)
    } else {
        dummy_nullifier(&DOMAIN, &second.dummy_key, &second.dummy_seed, 1)
    };
    let mut spk = [0; 36];
    if payout > 0 {
        spk[..3].copy_from_slice(&[0, 0, 0x20]);
        spk[3..35].copy_from_slice(&fixed::<32>(
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )?);
        spk[35] = 0xac;
    }
    let auth = Authorization {
        domain: DOMAIN,
        previous_outpoint: [0x51; 36],
        prior,
        reserve,
        fee,
        nfs: [nf0, nf1],
        outputs: if terminal {
            [[0; 32]; 2]
        } else {
            outputs.each_ref().map(|n| n.commitment(&DOMAIN))
        },
        cipher_hash: if terminal {
            terminal_cipher_hash()
        } else {
            hash(&[b"PUBLIC-R1CS-cipher-placeholder"])
        },
        next,
        reserve_after: after,
        payout,
        payout_spk: spk,
    };
    Ok(ActionCircuit {
        authorization: auth,
        inputs: [first, second],
        outputs,
    })
}

pub fn negative(kind: &str) -> ParseResult<ActionCircuit> {
    if !NEGATIVES.contains(&kind) {
        return Err("unknown negative control".into());
    }
    let mut c = positive(if kind.starts_with("terminal-") {
        "terminal"
    } else if kind == "p0-destination" || kind == "spend-no-positive-output" {
        "spend"
    } else {
        "change"
    })?;
    match kind {
        "wrong-s" => c.inputs[0].owner_secret[0] ^= 1,
        "wrong-k" => c.inputs[0].nullifier_secret[0] ^= 1,
        "copied-k-no-s" => c.inputs[0].owner_secret = [0; 32],
        "all-dummy" => {
            c.inputs[0] = c.inputs[1].clone();
            c.authorization.nfs[0] =
                dummy_nullifier(&DOMAIN, &c.inputs[0].dummy_key, &c.inputs[0].dummy_seed, 0);
        }
        "dummy-s" => c.inputs[1].owner_secret[0] = 1,
        "real-dummy-seed" => c.inputs[0].dummy_seed[0] = 1,
        "wrong-path" => c.inputs[0].path[0][0] ^= 1,
        "high-position" => c.inputs[0].position = 65536,
        "wrong-nf" => c.authorization.nfs[0][0] ^= 1,
        "wrong-dummy-slot" => {
            c.authorization.nfs[1] =
                dummy_nullifier(&DOMAIN, &c.inputs[1].dummy_key, &c.inputs[1].dummy_seed, 0)
        }
        "duplicate-nf" => c.authorization.nfs[1] = c.authorization.nfs[0],
        "zero-nf" => c.authorization.nfs[0] = [0; 32],
        "output-cm" => c.authorization.outputs[0][0] ^= 1,
        "subfloor-output" => {
            c.outputs[0].value = NOTE_FLOOR - 1;
            c.outputs[1] = output(3, 580_000_000 - c.outputs[0].value);
            c.authorization.outputs = c.outputs.each_ref().map(|n| n.commitment(&DOMAIN));
        }
        "out-of-range-input" => c.inputs[0].note.value = MAX + 1,
        "wrong-domain" => c.authorization.domain[0] ^= 1,
        "wrong-state-domain" => c.authorization.prior.domain[0] ^= 1,
        "fee-reserve" => c.authorization.reserve_after += 1,
        "count-capacity" => {
            c.authorization.prior.n = 65534;
            c.authorization.next.n = 65536;
        }
        "payout-conservation" => {
            c.authorization.payout += 1;
            c.authorization.reserve_after -= 1;
        }
        "p0-destination" => c.authorization.payout_spk[3] = 1,
        "p-positive-zero-spk" => c.authorization.payout_spk = [0; 36],
        "payout-version" => c.authorization.payout_spk[0] = 1,
        "payout-prefix" => c.authorization.payout_spk[2] = 0x21,
        "payout-opcode" => c.authorization.payout_spk[35] = 0xab,
        "payout-subfloor" => {
            c.authorization.payout = PAYOUT_FLOOR - 1;
            c.authorization.reserve_after =
                c.authorization.reserve - c.authorization.payout - c.authorization.fee;
            c.outputs[0].value =
                c.inputs[0].note.value - c.authorization.payout - c.authorization.fee;
            c.authorization.outputs[0] = c.outputs[0].commitment(&DOMAIN);
        }
        "payout-key-input0" => {
            c.authorization.payout_spk[3..35].copy_from_slice(&c.inputs[0].note.native_pk)
        }
        "payout-key-input1" => {
            c = positive("terminal")?;
            c.authorization.payout_spk[3..35].copy_from_slice(&c.inputs[1].note.native_pk);
        }
        "subfloor-reserve" => {
            c = positive("owned-full")?;
            c.authorization.reserve_after = NOTE_FLOOR - 1;
            c.authorization.reserve = c.inputs[0].note.value + c.authorization.reserve_after;
        }
        "terminal-rho" => c.outputs[0].rho[0] = 1,
        "terminal-value" => c.outputs[0].value = NOTE_FLOOR,
        "terminal-owner" => c.outputs[0].owner[0] = 1,
        "terminal-cm" => c.authorization.outputs[0][0] = 1,
        "terminal-cipher-hash" => c.authorization.cipher_hash = [0; 32],
        "terminal-cm-root" => c.authorization.next.cm_root[0] ^= 1,
        "terminal-cm-count" => c.authorization.next.n += 2,
        "terminal-nf-count" => c.authorization.next.m -= 1,
        "terminal-zero-payout" => {
            c.authorization.fee = c.authorization.reserve;
            c.authorization.payout = 0;
            c.authorization.payout_spk = [0; 36];
        }
        "spend-no-positive-output" => {
            c = positive("owned-full")?;
            c.authorization.payout = 0;
            c.authorization.payout_spk = [0; 36];
            c.authorization.fee = 1_000_000_000;
        }
        "overflow-sum" => {
            let first = note(0, MAX);
            let second = note(1, MAX);
            let (root, paths) = path_root(&[first.0.clone(), second.0.clone()]);
            for (slot, source) in [first, second].into_iter().enumerate() {
                c.inputs[slot] = InputWitness {
                    real: true,
                    note: source.0,
                    owner_secret: source.1,
                    nullifier_secret: source.2,
                    position: slot as u32,
                    path: paths[slot],
                    dummy_key: [0; 32],
                    dummy_seed: [0; 32],
                };
            }
            c.authorization.prior.cm_root = root;
            c.authorization.reserve = MAX;
            c.authorization.reserve_after = MAX - c.authorization.payout - c.authorization.fee;
            c.authorization.nfs = std::array::from_fn(|i| {
                nullifier(
                    &DOMAIN,
                    &c.inputs[i].nullifier_secret,
                    &c.inputs[i].note.commitment(&DOMAIN),
                    i as u32,
                )
            });
            c.outputs = [
                output(2, MAX),
                output(3, MAX - c.authorization.payout - c.authorization.fee),
            ];
            c.authorization.outputs = c.outputs.each_ref().map(|n| n.commitment(&DOMAIN));
        }
        _ => unreachable!(),
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_domain_and_wire_roundtrip() {
        assert_eq!(
            DOMAIN,
            hash(&[b"KPI/private-exit/DO-NOT-FUND/v1/2026-10-23"])
        );
        for kind in POSITIVES {
            let c = positive(kind).unwrap();
            c.authorization.validate_public().unwrap();
            assert_eq!(
                Authorization::parse(&c.authorization.bytes()).unwrap(),
                c.authorization
            );
            assert_eq!(
                from_bytes(&serde_json::to_vec(&to_value(&c)).unwrap())
                    .unwrap()
                    .authorization,
                c.authorization
            );
        }
    }
    #[test]
    fn strict_parser_frames() {
        let c = positive("change").unwrap();
        let mut bytes = c.authorization.bytes().to_vec();
        bytes.push(0);
        assert_eq!(Authorization::parse(&bytes), Err(Error::Length));
        let mut f = to_value(&c);
        f["unexpected"] = 1.into();
        assert!(from_bytes(&serde_json::to_vec(&f).unwrap()).is_err());
        let mut f = to_value(&c);
        f["classification"] = "LIVE".into();
        assert!(from_bytes(&serde_json::to_vec(&f).unwrap()).is_err());
    }
    #[test]
    fn full_spk_and_terminal_encoding() {
        let c = positive("terminal").unwrap();
        let b = c.authorization.bytes();
        assert_eq!(&b[484..492], &c.authorization.payout.to_le_bytes());
        assert_eq!(&b[492..528], &c.authorization.payout_spk);
        assert_ne!(terminal_cipher_hash(), [0; 32]);
        for kind in [
            "p0-destination",
            "p-positive-zero-spk",
            "payout-version",
            "terminal-cm",
            "terminal-cipher-hash",
        ] {
            assert!(
                negative(kind)
                    .unwrap()
                    .authorization
                    .validate_public()
                    .is_err(),
                "{kind}"
            );
        }
    }
}
