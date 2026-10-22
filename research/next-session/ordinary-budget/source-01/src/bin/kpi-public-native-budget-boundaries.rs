//! Public-proof-only native budget boundary qualification.
//!
//! Prior commitment prefixes are genuine public data. Supplied NF sets, later
//! commitment suffixes, reserve outpoints and amounts are synthetic contexts.
//! A native success authenticates a predicate against that supplied context;
//! it does not authenticate an ancestor, chain acceptance, backing or ownership.
use kaspa_consensus_core::mass::ScriptUnits;
use kaspa_consensus_core::tx::ComputeCommit;
use kaspa_txscript::runtime_resource_meter::RuntimeResourceMeter;
use kpi_shared_pool::{
    Result,
    compact::tree::{NfLeaf, less},
    native,
    protocol::{H, hash},
    two_input::{
        self, Authorization, Bundle, FEE, NF_WIT, P_AUTH, P_CIPHER, P_STATE, P_WITNESS, W_NF,
        replay::{self, Descriptor},
        tree::{PublicState, Tree, cm_leaf},
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs,
};

const INPUT_SHA: &str = "7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1";
const LIMBS: [(usize, usize); 5] = [(0, 7), (7, 14), (14, 21), (21, 28), (28, 32)];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    descriptor: Descriptor,
    vk_hex: String,
    lineage: Vec<Value>,
    parents: Vec<Value>,
}

fn bundle(tx: &kaspa_consensus_core::tx::Transaction) -> Result<Bundle> {
    if tx.payload.len() != two_input::PAYLOAD_SIZE
        || tx.inputs[0].signature_script.len() != two_input::covenant::WITNESS_LEN
        || tx.inputs[0].signature_script[..2] != [0x4c, 128]
    {
        return Err("retained public bundle framing".into());
    }
    Ok(Bundle {
        authorization: hex::encode(&tx.payload[P_AUTH..P_CIPHER]),
        proof: hex::encode(&tx.inputs[0].signature_script[2..130]),
        ciphertexts: [
            hex::encode(&tx.payload[P_CIPHER..P_CIPHER + 185]),
            hex::encode(&tx.payload[P_CIPHER + 185..P_STATE]),
        ],
    })
}

fn shifted(mut h: H, delta: i8) -> Result<H> {
    let mut carry = i16::from(delta);
    for b in &mut h {
        let sum = i16::from(*b) + carry;
        *b = sum.rem_euclid(256) as u8;
        carry = sum.div_euclid(256);
    }
    if carry != 0 || h == [0; 32] {
        return Err("public neighbor overflow/zero".into());
    }
    Ok(h)
}

fn limb_neighbor(mut h: H, limb: usize, direction: i8) -> Result<H> {
    let (lo, hi) = LIMBS[limb];
    let position = (lo..hi)
        .find(|&i| if direction < 0 { h[i] > 0 } else { h[i] < 255 })
        .ok_or("selected public limb has no simple neighbor")?;
    h[position] = (i16::from(h[position]) + i16::from(direction)) as u8;
    Ok(h)
}

fn neighboring_values(a: &Authorization, shape: &str) -> Result<Vec<H>> {
    let (low, high) = if less(&a.nfs[0], &a.nfs[1]) {
        (a.nfs[0], a.nfs[1])
    } else {
        (a.nfs[1], a.nfs[0])
    };
    match shape {
        "sentinel_first" => Ok(vec![shifted(high, 1)?, shifted(high, 2)?]),
        "tail_end" => Ok(vec![shifted(low, -2)?, shifted(low, -1)?]),
        "middle_bracket" => a
            .nfs
            .iter()
            .flat_map(|h| [shifted(*h, -1), shifted(*h, 1)])
            .collect(),
        "mixed_all_limbs" => {
            let mut values = Vec::new();
            for nf in a.nfs {
                for direction in [-1i8, 1] {
                    let mut neighbor = nf;
                    for limb in 0..4 {
                        // Lower limbs deliberately disagree in the opposite
                        // direction; the highest unequal limb must decide.
                        let (lo, hi) = LIMBS[limb];
                        neighbor[lo..hi].fill(if direction < 0 { 255 } else { 0 });
                    }
                    neighbor = limb_neighbor(neighbor, 4, direction)?;
                    values.push(neighbor);
                }
            }
            Ok(values)
        }
        name if name.starts_with("limb_") => {
            let limb = name[5..].parse::<usize>()?;
            if limb >= LIMBS.len() {
                return Err("limb index".into());
            }
            a.nfs
                .iter()
                .flat_map(|h| [limb_neighbor(*h, limb, -1), limb_neighbor(*h, limb, 1)])
                .collect()
        }
        "index_127_128" | "index_32767_32768" | "near_capacity" => {
            neighboring_values(a, "middle_bracket")
        }
        _ => Err("unknown frozen shape".into()),
    }
}

fn linked_set(a: &Authorization, shape: &str, count: usize) -> Result<Vec<NfLeaf>> {
    let mut values = neighboring_values(a, shape)?;
    let mut seen: HashSet<H> = values.iter().copied().collect();
    if values.len() != seen.len() || values.iter().any(|x| *x == [0; 32] || a.nfs.contains(x)) {
        return Err("neighbor collision/retained nullifier".into());
    }
    for i in 0u64.. {
        if values.len() >= count {
            break;
        }
        let value = hash(
            &[
                b"KPI-unfunded-native-budget-NF-v1\0".as_slice(),
                &i.to_le_bytes(),
            ]
            .concat(),
        );
        if value != [0; 32] && !a.nfs.contains(&value) && seen.insert(value) {
            values.push(value);
        }
    }
    if values.len() != count || count % 2 != 0 {
        return Err("frozen NF count".into());
    }
    // Physical positions are deliberately independent from numeric ordering.
    // Pin exact predecessor indices around script-number encoding boundaries.
    values.reverse();
    if shape.starts_with("index_") || shape == "near_capacity" {
        let desired = match shape {
            "index_127_128" => [127usize, 128],
            "index_32767_32768" => [32767usize, 32768],
            _ => [count - 1, count],
        };
        for (nf, index) in a.nfs.iter().zip(desired) {
            let predecessor = shifted(*nf, -1)?;
            let current = values
                .iter()
                .position(|v| *v == predecessor)
                .ok_or("missing exact predecessor")?;
            values.swap(current, index - 1);
        }
    }
    let mut sorted = values.clone();
    sorted.sort_unstable_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let positions: HashMap<H, u32> = values
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, (i + 1) as u32))
        .collect();
    let mut leaves = vec![NfLeaf::default(); count + 1];
    leaves[0].next_index = *positions.get(&sorted[0]).ok_or("first position")?;
    leaves[0].next_value = sorted[0];
    for (i, value) in sorted.iter().enumerate() {
        let (next_index, next_value) = sorted
            .get(i + 1)
            .map_or((0, [0; 32]), |v| (positions[v], *v));
        leaves[positions[value] as usize] = NfLeaf {
            value: *value,
            next_index,
            next_value,
        };
    }
    // Independent full linked-list consistency check, beyond PublicState's
    // structural count checks: every leaf occurs once in increasing LE order.
    let mut index = 0usize;
    let mut traversed = HashSet::new();
    for expected in &sorted {
        let leaf = &leaves[index];
        if !less(&leaf.value, expected)
            || leaf.next_value != *expected
            || leaves.get(leaf.next_index as usize).map(|x| x.value) != Some(*expected)
        {
            return Err("synthetic linked-set edge".into());
        }
        index = leaf.next_index as usize;
        if !traversed.insert(index) {
            return Err("synthetic linked-set cycle".into());
        }
    }
    if traversed.len() != count
        || leaves[index].next_index != 0
        || leaves[index].next_value != [0; 32]
    {
        return Err("synthetic linked-set terminal".into());
    }
    Ok(leaves)
}

fn context(
    prior: &PublicState,
    a: &Authorization,
    shape: &str,
    cm_count: usize,
    nf_count: usize,
) -> Result<PublicState> {
    if cm_count < prior.commitments.len() || cm_count % 2 != 1 {
        return Err("synthetic prefix count".into());
    }
    let mut commitments = prior.commitments.clone();
    for i in commitments.len()..cm_count {
        commitments.push(hash(
            &[
                b"KPI-unfunded-native-budget-CM-v1\0".as_slice(),
                &(i as u64).to_le_bytes(),
            ]
            .concat(),
        ));
    }
    let mut tree = Tree::new(Vec::new(), 16)?;
    let mut roots = Vec::with_capacity((cm_count + 1) / 2);
    for (i, cm) in commitments.iter().enumerate() {
        tree.append(cm_leaf(cm))?;
        if i % 2 == 0 {
            roots.push(tree.root());
        }
    }
    if roots.get((a.count as usize - 1) / 2) != Some(&a.anchor)
        || roots[..prior.roots.len()] != prior.roots
    {
        return Err("genuine historical CM prefix/anchor changed".into());
    }
    let state = PublicState {
        commitments,
        nullifiers: linked_set(a, shape, nf_count)?,
        roots,
    };
    state.compact()?;
    Ok(state)
}

fn limb_vector(a: &H, b: &H) -> Vec<&'static str> {
    LIMBS
        .iter()
        .map(
            |&(lo, hi)| match a[lo..hi].iter().rev().cmp(b[lo..hi].iter().rev()) {
                std::cmp::Ordering::Less => "lt",
                std::cmp::Ordering::Equal => "eq",
                std::cmp::Ordering::Greater => "gt",
            },
        )
        .collect()
}

fn predecessors(witness: &[u8], a: &Authorization) -> Result<Vec<Value>> {
    (0..2).map(|slot|{
        let base=W_NF+slot*NF_WIT;
        let index=u32::from_le_bytes(witness[base..base+4].try_into()?);
        let value:H=witness[base+4..base+36].try_into()?;
        let next_index=u32::from_le_bytes(witness[base+36..base+40].try_into()?);
        let next:H=witness[base+40..base+72].try_into()?;
        if !less(&value,&a.nfs[slot]) || (next!=[0;32]&&!less(&a.nfs[slot],&next)) {
            return Err("witness predecessor comparison".into());
        }
        Ok(json!({"slot":slot,"predecessor_index":index,"predecessor_hex":hex::encode(value),
            "next_index":next_index,"next_hex":hex::encode(next),"sentinel_predecessor":index==0,
            "tail_insertion":next==[0;32],"predecessor_limb_comparisons":limb_vector(&value,&a.nfs[slot]),
            "successor_limb_comparisons":if next==[0;32]{None}else{Some(limb_vector(&a.nfs[slot],&next))}}))
    }).collect()
}

fn same_error_enum<E: Error + 'static>(got: &(dyn Error + 'static), _: &E) -> bool {
    got.downcast_ref::<E>().is_some()
}

fn native_case(
    prior: &PublicState,
    b: &Bundle,
    d: &H,
    vk: &[u8],
    name: &str,
    shape: &str,
    cm_count: usize,
    nf_count: usize,
    terminal: bool,
) -> Result<Value> {
    let a = b.auth()?;
    let state = context(prior, &a, shape, cm_count, nf_count)?;
    let compact = state.compact()?;
    let amount = a
        .payout
        .checked_add(a.fee)
        .and_then(|x| x.checked_add(if terminal { 0 } else { 2_000_000_000 }))
        .ok_or("synthetic reserve overflow")?;
    let utxo = native::Utxo {
        txid: hex::encode(hash(
            &[
                b"KPI-unfunded-native-budget-outpoint-v1\0".as_slice(),
                name.as_bytes(),
            ]
            .concat(),
        )),
        index: 0,
        amount,
        spk: hex::encode(native::encode_spk(&two_input::reserve_spk(d, &state, vk)?)),
        daa: 0,
        is_coinbase: false,
    };
    let (mut original, entries, next) = two_input::settle(d, &state, &utxo, vk, b, None)?;
    // This integrated helper retains its historical 3000-versus-1600 comparison
    // even after the transaction factory adopts 1600. The original frozen
    // experiment/source identities remain in the separate native worktree.
    original.inputs[0].compute_commit = ComputeCommit::ComputeBudget(3000u16.into());
    original.finalize();
    native::set_mass(&original, &entries)?;
    if original.payload[P_AUTH..P_CIPHER] != hex::decode(&b.authorization)?
        || original.inputs[0].signature_script[2..130] != hex::decode(&b.proof)?
        || original.payload[P_CIPHER..P_STATE] != b.ciphers()?
    {
        return Err("genuine public proof/authorization/cipher changed".into());
    }
    let preds = predecessors(&original.payload[P_WITNESS..], &a)?;
    if (terminal && original.outputs.len() != 1)
        || (terminal && original.payload[P_STATE..P_WITNESS] != [0; 105])
        || (!terminal && original.outputs[0].value != 2_000_000_000)
    {
        return Err("synthetic terminal/continuation framing".into());
    }
    let baseline = native::script_units_at(&original, &entries, 0)?;
    if native::validate(&original, &entries)? != FEE {
        return Err("baseline native fee".into());
    }
    let mut reduced = original.clone();
    reduced.inputs[0].compute_commit = ComputeCommit::ComputeBudget(1600u16.into());
    reduced.finalize();
    native::set_mass(&reduced, &entries)?;
    let parsed = native::parse_tx(&native::tx_json(&reduced))?;
    if native::tx_json(&parsed) != native::tx_json(&reduced)
        || native::script_units_at(&reduced, &entries, 0)? != baseline
        || native::validate(&reduced, &entries)? != FEE
    {
        return Err("budget1600 native result or canonical round trip".into());
    }
    let allowed = reduced.inputs[0].compute_commit.allowed_script_units().0;
    if allowed != 16_009_999 || baseline > 15_857_502 {
        return Err("frozen source upper bound contradicted".into());
    }
    let mut bad = reduced.clone();
    bad.payload[P_WITNESS] ^= 1;
    bad.finalize();
    native::set_mass(&bad, &entries)?;
    let bad = native::parse_tx(&native::tx_json(&bad))?;
    let error = native::script_units_at(&bad, &entries, 0)
        .err()
        .ok_or("bad anchor path accepted")?;
    let mut meter = RuntimeResourceMeter::new_script_units(ScriptUnits(0), ScriptUnits(0));
    let typed = meter.consume_script_units(ScriptUnits(1)).unwrap_err();
    if !same_error_enum(error.as_ref(), &typed)
        || format!("{error:?}") != "VerifyError"
        || error.to_string() != "script ran, but verification failed"
    {
        return Err(format!("wrong native bad-path error: {error:?}").into());
    }
    Ok(
        json!({"name":name,"shape":shape,"mode":a.mode,"terminal":terminal,
        "synthetic_context":true,"chain_acceptance_verified":false,"backing_verified":false,
        "prior_cm_count":compact.cm_count,"prior_nf_count":compact.nf_count,
        "prior_state_hex":hex::encode(compact.bytes()),"next_state_hex":hex::encode(next.compact()?.bytes()),
        "genuine_anchor_count":a.count,"genuine_anchor_hex":hex::encode(a.anchor),
        "genuine_authorization_sha256":hex::encode(hash(&hex::decode(&b.authorization)?)),
        "genuine_proof_sha256":hex::encode(hash(&hex::decode(&b.proof)?)),
        "genuine_ciphertexts_sha256":hex::encode(hash(&b.ciphers()?)),
        "synthetic_state_sha256":hex::encode(hash(&serde_json::to_vec(&state)?)),
        "supplied_utxo":utxo,"predecessors":preds,"used_units_budget3000":baseline,
        "used_units_budget1600":baseline,"allowance_budget1600":allowed,"margin_units":allowed-baseline,
        "source_upper_bound_units":15_857_502u64,"proof_authorization_ciphertexts_unchanged":true,
        "native_full_validation_budget3000":true,"native_full_validation_budget1600":true,
        "native_bad_anchor_path_control":{"rejected":true,"typed_variant":"VerifyError","error":error.to_string()},
        "budget1600_transaction":native::tx_json(&reduced),"metrics":native::metrics(&reduced,&entries)?}),
    )
}

fn run(bytes: &[u8]) -> Result<Value> {
    if hex::encode(hash(bytes)) != INPUT_SHA {
        return Err("allowlisted genuine input SHA mismatch".into());
    }
    let input: PublicInput = serde_json::from_slice(bytes)?;
    if input.lineage.len() != 14 || input.parents.len() != 1 {
        return Err("fixed genuine public input dimensions".into());
    }
    let vk = hex::decode(&input.vk_hex)?;
    let baseline = replay::replay(&input.descriptor, &vk, &input.lineage, &input.parents)?;
    if baseline.chain_acceptance_verified {
        return Err("unexpected baseline chain claim".into());
    }
    let mut prior = PublicState::initial(input.descriptor.initial_commitment)?;
    let mut selected = Vec::new();
    for (ordinal, body) in input.lineage.iter().skip(1).enumerate() {
        let tx = native::parse_tx(body)?;
        let b = bundle(&tx)?;
        if [4usize, 5, 7].contains(&ordinal) {
            selected.push((ordinal, prior.clone(), b.clone()));
        }
        prior = prior.witness(&b.auth()?)?.0;
    }
    if serde_json::to_value(&prior)? != serde_json::to_value(&baseline.state)? {
        return Err("independent retained prefix reconstruction".into());
    }
    let mut cases = Vec::new();
    for (ordinal, prior, b) in &selected {
        let a = b.auth()?;
        if a.bootstrap != 0 || ![1, 2].contains(&a.mode) {
            return Err("selected ordinary genuine proof mode".into());
        }
        let terminals: &[bool] = if a.mode == 2 {
            &[false, true]
        } else {
            &[false]
        };
        for terminal in terminals {
            for shape in [
                "sentinel_first",
                "tail_end",
                "middle_bracket",
                "limb_0",
                "limb_1",
                "limb_2",
                "limb_3",
                "limb_4",
                "mixed_all_limbs",
            ] {
                let n = if ["sentinel_first", "tail_end"].contains(&shape) {
                    2
                } else {
                    4
                };
                let name = format!(
                    "row{ordinal}_{shape}_{}",
                    if *terminal { "terminal" } else { "continuing" }
                );
                cases.push(native_case(
                    prior,
                    b,
                    &input.descriptor.domain,
                    &vk,
                    &name,
                    shape,
                    prior.commitments.len(),
                    n,
                    *terminal,
                )?);
            }
            for (shape, cm, nf) in [
                ("index_127_128", 129usize, 254usize),
                ("index_32767_32768", 32769, 65536),
                (
                    "near_capacity",
                    if a.mode == 2 { 65535 } else { 65533 },
                    if a.mode == 2 { 131068 } else { 131064 },
                ),
            ] {
                let name = format!(
                    "row{ordinal}_{shape}_{}",
                    if *terminal { "terminal" } else { "continuing" }
                );
                cases.push(native_case(
                    prior,
                    b,
                    &input.descriptor.domain,
                    &vk,
                    &name,
                    shape,
                    cm,
                    nf,
                    *terminal,
                )?);
            }
        }
    }
    if cases.len() != 48 {
        return Err("frozen boundary case count".into());
    }
    let maximum = cases
        .iter()
        .map(|x| x["used_units_budget1600"].as_u64().unwrap())
        .max()
        .ok_or("empty cases")?;
    Ok(
        json!({"schema":"kpi-public-native-budget-boundaries-v1","passed":true,"input_sha256":INPUT_SHA,
        "source_base_commit":"ec6aa15d586bcc8a90f7232b433fd48d8c73d509",
        "native_source":"01b532e8b553523216471682649693af92f0fd16","case_count":cases.len(),
        "real_proof_verification":true,"new_setup_or_proof":false,"private_inputs_read":false,
        "chain_acceptance_verified":false,"backing_verified":false,"default_changed":false,
        "maximum_units":maximum,"minimum_budget1600_margin":16_009_999-maximum,
        "cases":cases,"limits":["synthetic supplied UTXO and NF context, not an authenticated prior state or funded pool",
        "public commitment prefix and historical anchor remain genuine, later public commitments are deterministic synthetic values",
        "retained real proofs authenticate unchanged authorization but do not prove this synthetic context arose from valid prior operations",
        "finite boundary evidence corroborates the separate source upper bound; no cryptographic assurance or privacy qualification"]}),
    )
}

fn main() {
    let result = (|| -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() != 1 {
            return Err("PUBLIC_REHEARSAL_INPUT_JSON".into());
        }
        let data = fs::read(&args[0])?;
        println!("{}", serde_json::to_string_pretty(&run(&data)?)?);
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("public native budget boundaries: {error}");
        std::process::exit(1);
    }
}
