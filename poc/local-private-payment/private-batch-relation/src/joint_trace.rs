//! Joint financial construction over authenticated bit recipes.
//!
//! Owner inputs are exact declared model columns, not a clear combined witness.
//! All private sorting, arithmetic and state work stays in the shared trace.
//! Production output keys come only from fresh active RANDOM_BIT operations.
//! The caller must validate the COMPLETE assignment and private assertions in
//! the same checked context before any effect/prefix/proof-related opening.
use crate::{
    Context, EFFECT_BYTES, MAX, NOTE_FLOOR, OUTPUTS, OWNERS, OwnerColumns, cv,
    state_trace::{self, PublicHistory, SecretBytes},
    trace::{self, Lc, TraceBuilder},
    wire::EFFECT_TAG,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};

const NF_BITS: usize = 256;
const CV_BITS: usize = 512;
const TUPLE_BITS: usize = 4160;
const RANDOM_KEY_BITS: usize = 128;
const DELTA_BITS: usize = 251;

/// Recipes only: contains no clear witness values or owner attribution map.
pub struct PreparedJoint {
    pub effect_bytes: SecretBytes,
    /// One-hot selectors indexed [source owner][public destination].
    pub input_permutation: Vec<Vec<Lc>>,
    /// One-hot selectors indexed [source output][public destination].
    pub output_permutation: Vec<Vec<Lc>>,
    pub remainder_bits: Vec<Lc>,
    pub delta_quotient_bits: Vec<Lc>,
}

#[derive(Debug)]
pub enum Error {
    Shape(&'static str),
    Trace(trace::Error),
    State(state_trace::Error),
}
impl From<trace::Error> for Error {
    fn from(value: trace::Error) -> Self {
        Self::Trace(value)
    }
}
impl From<state_trace::Error> for Error {
    fn from(value: state_trace::Error) -> Self {
        Self::State(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape(code) => f.write_str(code),
            Self::Trace(error) => error.fmt(f),
            Self::State(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
struct Row {
    key: Vec<Lc>,
    payload: Vec<Lc>,
    sources: Vec<Lc>,
}

fn constant_bits(bytes: &[u8]) -> Vec<Lc> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| Lc::constant(Fr::from((byte >> bit) & 1))))
        .collect()
}
fn constant_u64(value: u64, width: usize) -> Vec<Lc> {
    (0..width)
        .map(|bit| Lc::constant(Fr::from(bit < 64 && ((value >> bit) & 1 != 0))))
        .collect()
}
fn bytes(bits: &[Lc]) -> Result<SecretBytes> {
    if bits.len() % 8 != 0 {
        return Err(Error::Shape("joint-byte-width"));
    }
    Ok(bits.chunks(8).map(<[Lc]>::to_vec).collect())
}
fn columns(indices: &[usize], length: usize) -> Result<Vec<Lc>> {
    if indices.len() != length {
        return Err(Error::Shape("joint-owner-column-shape"));
    }
    Ok(indices.iter().copied().map(Lc::wire).collect())
}
fn ensure_bits(builder: &mut TraceBuilder, bits: &[Lc]) -> Result<()> {
    for bit in bits {
        let residual =
            builder.muladd(bit.clone(), bit.minus(&Lc::constant(Fr::ONE)), Lc::zero())?;
        builder.assert_zero(residual)?;
    }
    Ok(())
}
fn require_true(builder: &mut TraceBuilder, bit: &Lc) -> Result<()> {
    builder.assert_zero(builder.bit_not(bit))?;
    Ok(())
}
fn range_u64(builder: &mut TraceBuilder, bits: &[Lc], minimum: u64, maximum: u64) -> Result<()> {
    if bits.len() != 64 || minimum > maximum {
        return Err(Error::Shape("joint-u64-shape"));
    }
    let below = builder.lt_bits(bits, &constant_u64(minimum, 64))?;
    builder.assert_zero(below)?;
    let above = builder.lt_bits(&constant_u64(maximum, 64), bits)?;
    builder.assert_zero(above)?;
    Ok(())
}
fn select_bits(
    builder: &mut TraceBuilder,
    condition: &Lc,
    yes: &[Lc],
    no: &[Lc],
) -> Result<Vec<Lc>> {
    if yes.len() != no.len() {
        return Err(Error::Shape("joint-select-width"));
    }
    yes.iter()
        .zip(no)
        .map(|(a, b)| builder.select(condition, a, b).map_err(Error::from))
        .collect()
}

/// Full subtraction with explicit final borrow. No truncated ADD_BITS or
/// secret-dependent host branch; every output is a Boolean expression.
fn subtract(builder: &mut TraceBuilder, left: &[Lc], right: &[Lc]) -> Result<(Vec<Lc>, Lc)> {
    if left.is_empty() || left.len() != right.len() {
        return Err(Error::Shape("joint-subtract-width"));
    }
    let mut borrow = Lc::zero();
    let mut difference = Vec::with_capacity(left.len());
    for (a, b) in left.iter().zip(right) {
        let different = builder.bit_xor(a, b)?;
        difference.push(builder.bit_xor(&different, &borrow)?);
        let not_a = builder.bit_not(a);
        let generated = builder.bit_and(&not_a, b)?;
        let equal = builder.bit_not(&different);
        let propagated = builder.bit_and(&equal, &borrow)?;
        borrow = builder.bit_or(&generated, &propagated)?;
    }
    Ok((difference, borrow))
}

fn swap_rows(builder: &mut TraceBuilder, rows: &mut [Row], a: usize, b: usize) -> Result<()> {
    let left = rows[a].clone();
    let right = rows[b].clone();
    let swap = builder.lt_bits(&right.key, &left.key)?;
    rows[a] = Row {
        key: select_bits(builder, &swap, &right.key, &left.key)?,
        payload: select_bits(builder, &swap, &right.payload, &left.payload)?,
        sources: select_bits(builder, &swap, &right.sources, &left.sources)?,
    };
    rows[b] = Row {
        key: select_bits(builder, &swap, &left.key, &right.key)?,
        payload: select_bits(builder, &swap, &left.payload, &right.payload)?,
        sources: select_bits(builder, &swap, &left.sources, &right.sources)?,
    };
    Ok(())
}
fn sort_rows(builder: &mut TraceBuilder, rows: &mut [Row]) -> Result<()> {
    // Fixed adjacent compare/exchange schedule; no secret addresses or loops.
    for pass in 0..rows.len().saturating_sub(1) {
        for at in 0..rows.len() - 1 - pass {
            swap_rows(builder, rows, at, at + 1)?;
        }
    }
    Ok(())
}
fn source_flags(source: usize, count: usize) -> Vec<Lc> {
    (0..count)
        .map(|index| Lc::constant(Fr::from(index == source)))
        .collect()
}
fn selectors(rows: &[Row]) -> Result<Vec<Vec<Lc>>> {
    if rows.is_empty() || rows.iter().any(|row| row.sources.len() != rows.len()) {
        return Err(Error::Shape("joint-selector-shape"));
    }
    Ok((0..rows.len())
        .map(|source| rows.iter().map(|row| row.sources[source].clone()).collect())
        .collect())
}

fn reduce_delta(
    builder: &mut TraceBuilder,
    deltas: &[Vec<Lc>],
    q: &[Lc],
) -> Result<(Vec<Lc>, Vec<Lc>)> {
    if deltas.len() != OWNERS
        || deltas.iter().any(|bits| bits.len() != DELTA_BITS)
        || q.len() != 256
    {
        return Err(Error::Shape("joint-delta-shape"));
    }
    //3*(2^251-1)<2^253, and caller-checked canonical inputs imply sum<3Q<P.
    let delta_sum = builder.add_bits(deltas, 253)?;
    let mut delta = delta_sum;
    delta.resize(256, Lc::zero());
    let mut flags = Vec::with_capacity(2);
    for _ in 0..2 {
        let (reduced, borrow) = subtract(builder, &delta, q)?;
        let at_least_q = builder.bit_not(&borrow);
        delta = select_bits(builder, &at_least_q, &reduced, &delta)?;
        flags.push(at_least_q);
    }
    let canonical = builder.lt_bits(&delta, q)?;
    require_true(builder, &canonical)?;
    let mut quotient = vec![builder.bit_xor(&flags[0], &flags[1])?, flags[1].clone()];
    quotient.resize(8, Lc::zero());
    Ok((delta, quotient))
}

/// Genuine production constructor: private output keys are generated here,
/// never supplied by an owner/caller, and never opened or placed in Effects.
pub fn construct(
    builder: &mut TraceBuilder,
    context: &Context,
    history: &PublicHistory,
    owners: &[OwnerColumns; OWNERS],
) -> Result<PreparedJoint> {
    history.validate(context)?;
    if !(NOTE_FLOOR..=MAX).contains(&context.old_reserve) {
        return Err(Error::Shape("joint-public-reserve-range"));
    }
    let mut keys = Vec::with_capacity(OUTPUTS);
    for _ in 0..OUTPUTS {
        keys.push(
            (0..RANDOM_KEY_BITS)
                .map(|_| builder.random_bit())
                .collect::<trace::Result<Vec<_>>>()?,
        );
    }
    construct_with_keys(builder, context, history, owners, &keys)
}

// Shared algorithm seam, private to this module. The public constructor always
// uses active random bits; generic sort controls exercise declared fixture keys.
fn construct_with_keys(
    builder: &mut TraceBuilder,
    context: &Context,
    history: &PublicHistory,
    owners: &[OwnerColumns; OWNERS],
    keys: &[Vec<Lc>],
) -> Result<PreparedJoint> {
    history.validate(context)?;
    if keys.len() != OUTPUTS || keys.iter().any(|key| key.len() != RANDOM_KEY_BITS) {
        return Err(Error::Shape("joint-private-key-shape"));
    }
    let mut input_rows = Vec::with_capacity(OWNERS);
    let mut output_rows = Vec::with_capacity(OUTPUTS);
    let mut fees = Vec::with_capacity(OWNERS);
    let mut values = Vec::with_capacity(OWNERS);
    let mut deltas = Vec::with_capacity(OWNERS);
    let q: Fr = cv::SCALAR_MODULUS_DECIMAL
        .parse()
        .map_err(|_| Error::Shape("joint-public-Q"))?;
    let q_full = q
        .into_bigint()
        .to_bits_le()
        .into_iter()
        .map(|bit| Lc::constant(Fr::from(bit)))
        .collect::<Vec<_>>();
    if q_full.len() != 256 {
        return Err(Error::Shape("joint-public-Q-width"));
    }
    for (source, owner) in owners.iter().enumerate() {
        let nf = columns(&owner.input_nf_bits, NF_BITS)?;
        let cv = columns(&owner.input_cv_bits, CV_BITS)?;
        let fee = columns(&owner.fee_bits, 64)?;
        let value = columns(&owner.input_value_bits, 64)?;
        let delta = columns(&owner.private_delta_bits, 256)?;
        for bits in [&nf, &cv, &fee, &value, &delta] {
            ensure_bits(builder, bits)?;
        }
        range_u64(builder, &fee, 0, MAX)?;
        range_u64(builder, &value, NOTE_FLOOR, MAX)?;
        for bit in &delta[DELTA_BITS..] {
            builder.assert_zero(bit.clone())?;
        }
        let canonical = builder.lt_bits(&delta, &q_full)?;
        require_true(builder, &canonical)?;
        let mut payload = nf.clone();
        payload.extend(cv);
        input_rows.push(Row {
            key: nf,
            payload,
            sources: source_flags(source, OWNERS),
        });
        for index in 0..2 {
            let output = source * 2 + index;
            let payload = columns(&owner.output_tuple_bits[index], TUPLE_BITS)?;
            ensure_bits(builder, &payload)?;
            ensure_bits(builder, &keys[output])?;
            // Numeric comparison treats random128 as the major key and the
            // fixed three-bit original index as a collision-only minor key.
            // Even equal random keys have unique total ordering: there is no
            // collision-triggered retry or caller-supplied comparator.
            let mut key = constant_u64(output as u64, 3);
            key.extend(keys[output].clone());
            output_rows.push(Row {
                key,
                payload,
                sources: source_flags(output, OUTPUTS),
            });
        }
        fees.push(fee);
        values.push(value);
        deltas.push(delta[..DELTA_BITS].to_vec());
    }
    sort_rows(builder, &mut input_rows)?;
    sort_rows(builder, &mut output_rows)?;
    let input_permutation = selectors(&input_rows)?;
    let output_permutation = selectors(&output_rows)?;

    // Both totals use66 bits: their structural maximum is3*(2^64-1)<2^66.
    let fee_sum = builder.add_bits(&fees, 66)?;
    for bit in &fee_sum[64..] {
        builder.assert_zero(bit.clone())?;
    }
    let total_fee = fee_sum[..64].to_vec();
    range_u64(builder, &total_fee, 1, MAX)?;
    let input_sum = builder.add_bits(&values, 66)?;
    let old_reserve = constant_u64(context.old_reserve, 66);
    let (remainder, borrow) = subtract(builder, &old_reserve, &input_sum)?;
    builder.assert_zero(borrow)?;
    for bit in &remainder[64..] {
        builder.assert_zero(bit.clone())?;
    }
    let remainder_bits = remainder[..64].to_vec();
    range_u64(builder, &remainder_bits, 0, MAX)?;
    let (new_reserve, borrow) = subtract(builder, &old_reserve, &fee_sum)?;
    builder.assert_zero(borrow)?;
    for bit in &new_reserve[64..] {
        builder.assert_zero(bit.clone())?;
    }
    let new_reserve = new_reserve[..64].to_vec();
    range_u64(builder, &new_reserve, NOTE_FLOOR, MAX)?;

    let (delta, delta_quotient_bits) = reduce_delta(builder, &deltas, &q_full)?;

    let nullifiers = input_rows
        .iter()
        .map(|row| bytes(&row.payload[..NF_BITS]))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| Error::Shape("joint-nf-count"))?;
    let commitments = output_rows
        .iter()
        .map(|row| bytes(&row.payload[..256]))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| Error::Shape("joint-cm-count"))?;
    let state =
        state_trace::build_state_trace(builder, context, history, &nullifiers, &commitments)?;
    let mut effect_bytes = bytes(&constant_bits(EFFECT_TAG))?;
    effect_bytes.extend(bytes(&constant_bits(&context.bytes()))?);
    effect_bytes.extend(state.new_cm_root);
    effect_bytes.extend(state.new_nf_root);
    effect_bytes.extend(bytes(&constant_bits(&state.new_cm_count.to_le_bytes()))?);
    effect_bytes.extend(bytes(&constant_bits(&state.new_nf_count.to_le_bytes()))?);
    effect_bytes.extend(bytes(&new_reserve)?);
    effect_bytes.extend(bytes(&total_fee)?);
    effect_bytes.extend(bytes(&delta)?);
    for row in input_rows.iter().chain(&output_rows) {
        effect_bytes.extend(bytes(&row.payload)?);
    }
    for witness in &state.nf_witnesses {
        effect_bytes.extend(witness.bytes());
    }
    for path in &state.cm_paths {
        for node in path {
            effect_bytes.extend(node.clone());
        }
    }
    if effect_bytes.len() != EFFECT_BYTES {
        return Err(Error::Shape("joint-effect-byte-shape"));
    }
    Ok(PreparedJoint {
        effect_bytes,
        input_permutation,
        output_permutation,
        remainder_bits,
        delta_quotient_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;
    use std::collections::BTreeMap;

    fn decode(bits: &[Lc], values: &[Fr]) -> u64 {
        bits.iter()
            .enumerate()
            .map(|(i, bit)| {
                let value = bit.0.iter().fold(Fr::ZERO, |sum, (coefficient, index)| {
                    sum + *coefficient * values[*index]
                });
                assert!(value == Fr::ZERO || value == Fr::ONE);
                u64::from(value == Fr::ONE) << i
            })
            .sum()
    }
    fn public_values(builder: &TraceBuilder, inputs: &BTreeMap<usize, Fr>) -> Vec<Fr> {
        builder.evaluate_public_fixture(inputs).unwrap()
    }
    #[test]
    fn subtraction_reports_borrow_without_truncating() {
        for a in 0..32u64 {
            for b in 0..32u64 {
                let mut builder = TraceBuilder::new(11, 1).unwrap();
                let mut fixture = BTreeMap::new();
                let left = (1..6)
                    .map(|index| {
                        fixture.insert(index, Fr::from((a >> (index - 1)) & 1));
                        builder.input(index).unwrap()
                    })
                    .collect::<Vec<_>>();
                let right = (6..11)
                    .map(|index| {
                        fixture.insert(index, Fr::from((b >> (index - 6)) & 1));
                        builder.input(index).unwrap()
                    })
                    .collect::<Vec<_>>();
                let (difference, borrow) = subtract(&mut builder, &left, &right).unwrap();
                let values = public_values(&builder, &fixture);
                assert_eq!(decode(&difference, &values), a.wrapping_sub(b) & 31);
                assert_eq!(decode(&[borrow], &values), u64::from(a < b));
            }
        }
    }
    #[test]
    fn fixed_sort_preserves_complete_rows_and_source_destination_orientation() {
        // Variable public fixtures exercise comparisons, complete payload muxes
        // and markers; equal random keys use the fixed original-index tie.
        for keys in [
            [8u64, 2, 9, 0, 4, 1],
            [0, 0, 0, 0, 0, 0],
            [5, 4, 3, 2, 1, 0],
        ] {
            let mut builder = TraceBuilder::new(1 + OUTPUTS * 8, 1).unwrap();
            let mut fixture = BTreeMap::new();
            let mut rows = Vec::new();
            for (source, key) in keys.iter().enumerate() {
                let mut bits = Vec::new();
                for at in 0..8 {
                    let index = 1 + source * 8 + at;
                    fixture.insert(index, Fr::from((key >> at) & 1));
                    bits.push(builder.input(index).unwrap());
                }
                let mut fullkey = constant_u64(source as u64, 3);
                fullkey.extend(bits);
                rows.push(Row {
                    key: fullkey,
                    payload: constant_u64(100 + source as u64, 16),
                    sources: source_flags(source, OUTPUTS),
                });
            }
            sort_rows(&mut builder, &mut rows).unwrap();
            let permutation = selectors(&rows).unwrap();
            let values = public_values(&builder, &fixture);
            let mut expected = (0..OUTPUTS).collect::<Vec<_>>();
            expected.sort_by_key(|source| (keys[*source], *source));
            for (destination, source) in expected.iter().enumerate() {
                assert_eq!(
                    decode(&rows[destination].payload, &values),
                    100 + *source as u64
                );
                for origin in 0..OUTPUTS {
                    assert_eq!(
                        decode(&[permutation[origin][destination].clone()], &values),
                        u64::from(origin == *source)
                    );
                }
            }
        }
    }
    #[test]
    fn exact_delta_reduction_covers_all_three_quotients_and_q_boundaries() {
        let q: Fr = cv::SCALAR_MODULUS_DECIMAL.parse().unwrap();
        let q_bits = q
            .into_bigint()
            .to_bits_le()
            .into_iter()
            .map(|bit| Lc::constant(Fr::from(bit)))
            .collect::<Vec<_>>();
        for (inputs, k, expected) in [
            ([Fr::ZERO; 3], 0, Fr::ZERO),
            ([q - Fr::ONE, Fr::ONE, Fr::ZERO], 1, Fr::ZERO),
            (
                [q - Fr::ONE, q - Fr::ONE, q - Fr::ONE],
                2,
                q - Fr::from(3u64),
            ),
            ([q - Fr::ONE, q - Fr::ONE, Fr::ONE], 1, q - Fr::ONE),
            ([Fr::ZERO, q - Fr::ONE, Fr::ZERO], 0, q - Fr::ONE),
        ] {
            let mut builder = TraceBuilder::new(1 + OWNERS * DELTA_BITS, 1).unwrap();
            let mut fixture = BTreeMap::new();
            let mut next = 1;
            let deltas = inputs
                .iter()
                .map(|value| {
                    value.into_bigint().to_bits_le()[..DELTA_BITS]
                        .iter()
                        .map(|bit| {
                            let index = next;
                            next += 1;
                            fixture.insert(index, Fr::from(*bit));
                            builder.input(index).unwrap()
                        })
                        .collect()
                })
                .collect::<Vec<_>>();
            let (delta, quotient) = reduce_delta(&mut builder, &deltas, &q_bits).unwrap();
            let values = public_values(&builder, &fixture);
            assert_eq!(decode(&quotient, &values), k);
            let mut actual = Fr::ZERO;
            let mut coefficient = Fr::ONE;
            for bit in delta {
                actual += coefficient * Fr::from(decode(&[bit], &values));
                coefficient.double_in_place();
            }
            assert_eq!(actual, expected);
        }
    }
    #[test]
    #[ignore = "full variable joint+state graph; explicit bounded public-fixture resource window required"]
    fn full_variable_joint_trace_matches_independent_oracle_across_changed_routing() {
        use crate::{H, Profile, state_trace::PublicNullifierLeaf};
        use sha2::{Digest, Sha256};
        use std::{
            io::Write,
            path::Path,
            process::{Command, Stdio},
        };
        let run = |variant: usize| {
            // Explicitly PUBLIC synthetic bytes, not valid owner authorization
            // or genuine Output proofs. This is a construction oracle control.
            let old_cms: [H; 3] = std::array::from_fn(|i| {
                Sha256::digest(format!("PUBLIC-JOINT-TRACE-OLD-{i}")).into()
            });
            let mut old_nf = [0u8; 32];
            old_nf[0] = 100;
            let history = PublicHistory {
                commitments: old_cms.to_vec(),
                nullifiers: vec![
                    PublicNullifierLeaf {
                        value: [0; 32],
                        successor: old_nf,
                        successor_index: 1,
                    },
                    PublicNullifierLeaf {
                        value: old_nf,
                        successor: [0; 32],
                        successor_index: 0,
                    },
                ],
            };
            let mut context = Context {
                profile: Profile {
                    chain_genesis: [1; 32],
                    pool_lineage: [2; 32],
                    wallet_profile: [3; 32],
                    domain: [4; 32],
                    service_policy: [5; 32],
                },
                reserve_outpoint: [6; 36],
                old_cm_root: [0; 32],
                old_nf_root: [0; 32],
                old_cm_count: 3,
                old_nf_count: 2,
                old_reserve: 1_000_000_000,
            };
            let q: Fr = cv::SCALAR_MODULUS_DECIMAL.parse().unwrap();
            let nf_numbers = if variant == 0 {
                [250u64, 20, 80]
            } else {
                [160u64, 180, 30]
            };
            let fees = if variant == 0 {
                [2u64, 3, 5]
            } else {
                [8u64, 13, 21]
            };
            let input_values = if variant == 0 {
                [100_000_000u64, 200_000_000, 150_000_000]
            } else {
                [110_000_000u64, 210_000_000, 160_000_000]
            };
            let delta_values = if variant == 0 {
                [q - Fr::ONE, Fr::from(2u64), Fr::from(3u64)]
            } else {
                [q - Fr::ONE, q - Fr::from(2u64), q - Fr::from(3u64)]
            };
            let key_values = if variant == 0 {
                [5u64, 1, 4, 0, 3, 2]
            } else {
                [0u64, 3, 3, 5, 1, 2]
            };
            let nfs: [H; OWNERS] = std::array::from_fn(|i| {
                let mut nf = [0; 32];
                nf[..8].copy_from_slice(&nf_numbers[i].to_le_bytes());
                nf
            });
            let cvs: [[u8; 64]; OWNERS] = std::array::from_fn(|i| [30 + i as u8; 64]);
            let tuples: [[u8; 520]; OUTPUTS] = std::array::from_fn(|i| {
                let mut row = std::array::from_fn(|at| {
                    (at as u8)
                        .wrapping_add(13 * i as u8)
                        .wrapping_add(variant as u8)
                });
                let cm: H = Sha256::digest(format!("PUBLIC-JOINT-TRACE-NEW-{variant}-{i}")).into();
                row[..32].copy_from_slice(&cm);
                row
            });
            let script = r#"
import hashlib,importlib.util,json,sys
spec=importlib.util.spec_from_file_location('public_trees',sys.argv[1]);t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
j=json.load(sys.stdin);s=t.PublicState([bytes.fromhex(x) for x in j['old_cms']]);s.insert((100).to_bytes(32,'little'))
oldcm=s.cm.root();oldnf=s.nf.root();ctx=bytes.fromhex(j['context_prefix'])+oldcm+oldnf+(3).to_bytes(4,'little')+(2).to_bytes(4,'little')+j['old_reserve'].to_bytes(8,'little')
nfs=[bytes.fromhex(x) for x in j['nfs']];cvs=[bytes.fromhex(x) for x in j['cvs']];outs=[bytes.fromhex(x) for x in j['tuples']]
ui=sorted(range(3),key=lambda i:int.from_bytes(nfs[i],'little'));vi=sorted(range(6),key=lambda i:(j['keys'][i],i))
nfpaths=[s.insert(nfs[i]) for i in ui];cmpaths=[s.append(outs[i][:32]) for i in vi]
fee=sum(j['fees']);d=sum(int(x) for x in j['deltas']);q=int(j['Q']);quotient,delta=divmod(d,q)
effects=b'KPBAEF01'+ctx+s.cm.root()+s.nf.root()+len(s.cms).to_bytes(4,'little')+len(s.entries).to_bytes(4,'little')+(j['old_reserve']-fee).to_bytes(8,'little')+fee.to_bytes(8,'little')+delta.to_bytes(32,'little')
effects+=b''.join(nfs[i]+cvs[i] for i in ui)+b''.join(outs[i] for i in vi)+b''.join(nfpaths)+b''.join(cmpaths);assert len(effects)==10364
u=bytes(int(source==ui[dest]) for source in range(3) for dest in range(3));v=bytes(int(source==vi[dest]) for source in range(6) for dest in range(6))
sys.stdout.buffer.write(oldcm+oldnf+effects+u+v+(j['old_reserve']-sum(j['values'])).to_bytes(8,'little')+bytes([quotient]))
"#;
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("owner-private-lifecycle/wallet/trees.py");
            let data = serde_json::json!({
                "old_cms":old_cms.iter().map(hex::encode).collect::<Vec<_>>(),"context_prefix":hex::encode(&context.bytes()[..196]),
                "old_reserve":context.old_reserve,"nfs":nfs.iter().map(hex::encode).collect::<Vec<_>>(),"cvs":cvs.iter().map(hex::encode).collect::<Vec<_>>(),
                "tuples":tuples.iter().map(hex::encode).collect::<Vec<_>>(),"fees":fees,"values":input_values,
                "deltas":delta_values.iter().map(ToString::to_string).collect::<Vec<_>>(),"keys":key_values,"Q":cv::SCALAR_MODULUS_DECIMAL,
            });
            let mut child = Command::new("/usr/bin/python3")
                .arg("-c")
                .arg(script)
                .arg(source)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(data.to_string().as_bytes())
                .unwrap();
            let oracle = child.wait_with_output().unwrap();
            assert!(
                oracle.status.success(),
                "public oracle refused: {}",
                String::from_utf8_lossy(&oracle.stderr)
            );
            let expected = oracle.stdout;
            context.old_cm_root.copy_from_slice(&expected[..32]);
            context.old_nf_root.copy_from_slice(&expected[32..64]);
            history.validate(&context).unwrap();
            let mut fixture = BTreeMap::new();
            let mut next = 1;
            let mut declare = |bytes: &[u8]| {
                bytes
                    .iter()
                    .flat_map(|byte| (0..8).map(move |at| Fr::from((byte >> at) & 1)))
                    .map(|bit| {
                        let index = next;
                        next += 1;
                        fixture.insert(index, bit);
                        index
                    })
                    .collect::<Vec<_>>()
            };
            let owners: [OwnerColumns; OWNERS] = std::array::from_fn(|i| {
                let nf = declare(&nfs[i]);
                let cv = declare(&cvs[i]);
                let output_tuple_bits = std::array::from_fn(|j| declare(&tuples[2 * i + j]));
                let fee_bits = declare(&fees[i].to_le_bytes());
                let delta_bytes = delta_values[i].into_bigint().to_bytes_le();
                let private_delta_bits = declare(&delta_bytes);
                let input_value_bits = declare(&input_values[i].to_le_bytes());
                OwnerColumns {
                    input_nf_bits: nf,
                    input_cv_bits: cv,
                    output_tuple_bits,
                    fee_bits,
                    private_delta_bits,
                    input_value_bits,
                }
            });
            let model_variables = next;
            let tape = key_values
                .iter()
                .flat_map(|key| (0..128).map(move |bit| bit < 64 && ((key >> bit) & 1 != 0)))
                .collect();
            let mut builder = TraceBuilder::new_public_fixture_with_random_tape(
                model_variables,
                1,
                fixture.clone(),
                tape,
            )
            .unwrap();
            for index in 1..model_variables {
                builder.input(index).unwrap();
            }
            let joint = construct(&mut builder, &context, &history, &owners).unwrap();
            builder.require_complete_model().unwrap();
            let values = builder.public_fixture_values(&fixture).unwrap();
            let bit = |lc: &Lc| {
                let x =
                    lc.0.iter()
                        .fold(Fr::ZERO, |sum, (c, i)| sum + *c * values[*i].unwrap());
                assert!(x == Fr::ZERO || x == Fr::ONE);
                u8::from(x == Fr::ONE)
            };
            let mut actual = joint
                .effect_bytes
                .iter()
                .map(|byte| {
                    byte.iter()
                        .enumerate()
                        .fold(0u8, |acc, (i, lc)| acc | (bit(lc) << i))
                })
                .collect::<Vec<_>>();
            for matrix in [&joint.input_permutation, &joint.output_permutation] {
                for row in matrix {
                    actual.extend(row.iter().map(&bit));
                }
            }
            actual.extend(joint.remainder_bits.chunks(8).map(|byte| {
                byte.iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, lc)| acc | (bit(lc) << i))
            }));
            actual.push(
                joint
                    .delta_quotient_bits
                    .iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, lc)| acc | (bit(lc) << i)),
            );
            assert_eq!(actual, expected[64..]);
            let graph = builder.public_fixture_graph_sha256().unwrap();
            println!(
                "PUBLIC variable-joint graph: {} wires, {} operations, sha256 {}",
                builder.variables(),
                builder.operation_count(),
                hex::encode(graph)
            );
            (
                graph,
                builder.variables(),
                builder.operation_count(),
                actual,
            )
        };
        let (first, second) = std::thread::scope(|scope| {
            let a = scope.spawn(|| run(0));
            let b = scope.spawn(|| run(1));
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_eq!(
            (first.0, first.1, first.2),
            (second.0, second.1, second.2),
            "private routing changed the symbolic graph"
        );
        assert_ne!(
            first.3, second.3,
            "changed inputs did not reach full effects/selectors/arithmetic"
        );
    }
}
