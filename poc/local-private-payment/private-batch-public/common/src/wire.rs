//! Canonical ADR0074 public 3/6 frame and established public tree updates.
use crate::{need, sha, Result, H};
pub const BODY_CORE_LEN: usize = 10364;
pub const BODY_LEN: usize = BODY_CORE_LEN + 128;
pub const PREFIX_LEN: usize = 193;
pub const PROJECTION_LEN: usize = PREFIX_LEN + BODY_LEN;
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const FLOOR: u64 = 60_000_000;
const ZERO: H = [0; 32];
fn n32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}
fn n64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}
fn h32(bytes: &[u8]) -> H {
    bytes.try_into().unwrap()
}

#[derive(Clone, Copy)]
pub struct Context {
    pub chain_genesis: H,
    pub pool_lineage: H,
    pub profile_id: H,
    pub domain: H,
    pub service_policy: H,
}
#[derive(Clone)]
pub struct State {
    pub raw: [u8; 112],
    pub cm: H,
    pub n: u32,
    pub nf: H,
    pub m: u32,
}
impl State {
    pub fn from_parts(domain: H, cm: H, n: u32, nf: H, m: u32) -> Result<Self> {
        need(
            (1..=65536).contains(&n) && (1..=131072).contains(&m),
            "state_counts",
        )?;
        let mut raw = [0; 112];
        raw[..8].copy_from_slice(b"KPBAST01");
        raw[8..40].copy_from_slice(&domain);
        raw[40..72].copy_from_slice(&cm);
        raw[72..76].copy_from_slice(&n.to_le_bytes());
        raw[76..108].copy_from_slice(&nf);
        raw[108..].copy_from_slice(&m.to_le_bytes());
        Ok(Self { raw, cm, n, nf, m })
    }
}
pub struct Spend {
    pub nf: H,
    pub cv: [u8; 64],
}
pub struct Output<'a> {
    pub cm: H,
    pub cv: [u8; 64],
    pub cf: &'a [u8],
    pub cfh: H,
    pub proof: &'a [u8],
    pub tuple: &'a [u8],
}
pub struct Body<'a> {
    pub raw: &'a [u8],
    pub point: &'a [u8],
    pub old: State,
    pub new: State,
    pub reserve: u64,
    pub remaining: u64,
    pub fee: u64,
    pub delta: H,
    pub spends: Vec<Spend>,
    pub outputs: Vec<Output<'a>>,
    pub nf_witnesses: &'a [u8],
    pub cm_paths: &'a [u8],
    pub aggregate_proof: &'a [u8],
}
impl<'a> Body<'a> {
    pub fn parse(raw: &'a [u8], context: &Context) -> Result<Self> {
        need(raw.len() == BODY_LEN, "body_width")?;
        need(
            &raw[..8] == b"KPBAEF01"
                && raw[8..40] == context.chain_genesis
                && raw[40..72] == context.pool_lineage
                && raw[72..104] == context.profile_id
                && raw[104..136] == context.domain
                && raw[136..168] == context.service_policy,
            "body_profile_context",
        )?;
        let old = State::from_parts(
            context.domain,
            h32(&raw[204..236]),
            n32(&raw[268..272]),
            h32(&raw[236..268]),
            n32(&raw[272..276]),
        )?;
        let new = State::from_parts(
            context.domain,
            h32(&raw[284..316]),
            n32(&raw[348..352]),
            h32(&raw[316..348]),
            n32(&raw[352..356]),
        )?;
        let reserve = n64(&raw[276..284]);
        let remaining = n64(&raw[356..364]);
        let fee = n64(&raw[364..372]);
        need(
            (FLOOR..=MAX).contains(&reserve)
                && (FLOOR..=MAX).contains(&remaining)
                && (1..=MAX).contains(&fee)
                && remaining.checked_add(fee) == Some(reserve),
            "body_money",
        )?;
        need(
            raw[168..200] != ZERO
                && old.n >= 3
                && old.n.checked_add(6) == Some(new.n)
                && old.m.checked_add(3) == Some(new.m),
            "body_point_or_counts",
        )?;
        let mut spends = Vec::<Spend>::new();
        for index in 0..3 {
            let offset = 404 + index * 96;
            let nf = h32(&raw[offset..offset + 32]);
            need(
                nf != ZERO && spends.last().map_or(true, |previous| lt(&previous.nf, &nf)),
                "sorted_distinct_nonzero_nf",
            )?;
            spends.push(Spend {
                nf,
                cv: raw[offset + 32..offset + 96].try_into().unwrap(),
            });
        }
        let mut outputs = Vec::<Output<'a>>::new();
        for index in 0..6 {
            let row = &raw[692 + index * 520..692 + (index + 1) * 520];
            let output = Output {
                cm: h32(&row[..32]),
                cv: row[32..96].try_into().unwrap(),
                cf: &row[96..360],
                cfh: h32(&row[360..392]),
                proof: &row[392..520],
                tuple: row,
            };
            need(
                output.cm != ZERO
                    && output.cm != sha(&[b"KPX1CME\0"])
                    && outputs
                        .iter()
                        .all(|previous| previous.cm != output.cm && previous.tuple != output.tuple),
                "distinct_output_components",
            )?;
            need(sha(&[output.cf]) == output.cfh, "ciphertext_hash")?;
            outputs.push(output);
        }
        Ok(Self {
            raw,
            point: &raw[168..204],
            old,
            new,
            reserve,
            remaining,
            fee,
            delta: h32(&raw[372..404]),
            spends,
            outputs,
            nf_witnesses: &raw[3812..7292],
            cm_paths: &raw[7292..10364],
            aggregate_proof: &raw[10364..10492],
        })
    }
}
pub struct Projection<'a> {
    pub raw: &'a [u8],
    pub prefix: &'a [u8],
    pub body: Body<'a>,
}
impl<'a> Projection<'a> {
    pub fn parse(raw: &'a [u8], context: &Context) -> Result<Self> {
        need(raw.len() == PROJECTION_LEN, "projection_width")?;
        let prefix = &raw[..PREFIX_LEN];
        need(
            &prefix[..8] == b"KPBAFX01"
                && prefix[8..12] == [1, 0, 1, 0]
                && prefix[48..56] == [255; 8]
                && prefix[64..66] == [37, 0]
                && prefix[103..105] == [1, 0]
                && prefix[113..115] == [37, 0]
                && prefix[152] == 0
                && prefix[153..189] == [0; 36]
                && n32(&prefix[189..193]) == BODY_LEN as u32,
            "projection_header",
        )?;
        for spk in [&prefix[66..103], &prefix[115..152]] {
            need(
                spk[..4] == [0, 0, 0xaa, 0x20] && spk[36] == 0x87,
                "projection_script",
            )?;
        }
        let body = Body::parse(&raw[PREFIX_LEN..], context)?;
        need(
            prefix[12..48] == *body.point
                && n64(&prefix[56..64]) == body.reserve
                && n64(&prefix[105..113]) == body.remaining,
            "projection_effects",
        )?;
        Ok(Self { raw, prefix, body })
    }
}
pub fn effects_digest(projection: &Projection<'_>) -> H {
    // The canonical core includes its KPBAEF01 tag. It is exactly the aggregate
    // relation's SHA input; prefix/actual effects are independently checked.
    sha(&[&projection.body.raw[..BODY_CORE_LEN]])
}
pub fn fold(mut leaf: H, index: u32, path: &[u8], tag: &[u8], depth: usize) -> Result<H> {
    need(
        path.len() == 32 * depth && u64::from(index) < (1u64 << depth),
        "merkle_path",
    )?;
    for (level, sibling) in path.chunks_exact(32).enumerate() {
        leaf = if (index >> level) & 1 == 0 {
            sha(&[tag, &leaf, sibling])
        } else {
            sha(&[tag, sibling, &leaf])
        };
    }
    Ok(leaf)
}
fn nf_leaf(value: &H, next: &H, index: u32) -> H {
    sha(&[b"KPX1NFL\0", value, next, &index.to_le_bytes()])
}
fn lt(a: &H, b: &H) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}
pub fn insert_nf(root: H, count: u32, nf: H, witness: &[u8]) -> Result<H> {
    need(
        witness.len() == 1160 && (1..131072).contains(&count),
        "nf_witness_count",
    )?;
    let index = n32(&witness[..4]);
    let value = h32(&witness[4..36]);
    let next = h32(&witness[36..68]);
    let next_index = n32(&witness[68..72]);
    need(
        index < count
            && next_index < count
            && (index == 0) == (value == ZERO)
            && (next_index == 0) == (next == ZERO)
            && nf != ZERO,
        "nf_indices",
    )?;
    need(
        lt(&value, &nf) && (next == ZERO || lt(&nf, &next)),
        "nf_interval",
    )?;
    need(
        fold(
            nf_leaf(&value, &next, next_index),
            index,
            &witness[72..616],
            b"KPX1NFN\0",
            17,
        )? == root,
        "nf_predecessor_root",
    )?;
    let middle = fold(
        nf_leaf(&value, &nf, count),
        index,
        &witness[72..616],
        b"KPX1NFN\0",
        17,
    )?;
    need(
        fold(
            sha(&[b"KPX1NFE\0"]),
            count,
            &witness[616..],
            b"KPX1NFN\0",
            17,
        )? == middle,
        "nf_empty_append",
    )?;
    fold(
        nf_leaf(&nf, &next, next_index),
        count,
        &witness[616..],
        b"KPX1NFN\0",
        17,
    )
}
pub fn validate_transition(projection: &Projection<'_>) -> Result<()> {
    let body = &projection.body;
    let (mut nf, mut count) = (body.old.nf, body.old.m);
    for (spend, witness) in body.spends.iter().zip(body.nf_witnesses.chunks_exact(1160)) {
        nf = insert_nf(nf, count, spend.nf, witness)?;
        count = count.checked_add(1).ok_or("nf_overflow")?;
    }
    need(nf == body.new.nf && count == body.new.m, "nf_successor")?;
    let (mut cm, mut count) = (body.old.cm, body.old.n);
    for (output, path) in body.outputs.iter().zip(body.cm_paths.chunks_exact(512)) {
        need(
            fold(sha(&[b"KPX1CME\0"]), count, path, b"KPX1CMN\0", 16)? == cm,
            "cm_empty_append",
        )?;
        cm = fold(output.cm, count, path, b"KPX1CMN\0", 16)?;
        count = count.checked_add(1).ok_or("cm_overflow")?;
    }
    need(cm == body.new.cm && count == body.new.n, "cm_successor")
}
