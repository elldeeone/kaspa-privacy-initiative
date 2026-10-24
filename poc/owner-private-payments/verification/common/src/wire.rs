//! Public canonical frame and authenticated sparse-tree updates, no owner data.
use crate::{need, sha, Result, H};
pub const BODY_LEN: usize = 10780;
pub const BODY_CORE_LEN: usize = 10396;
pub const PREFIX_LEN: usize = 193;
pub const PROJECTION_LEN: usize = PREFIX_LEN + BODY_LEN;
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const FLOOR: u64 = 60_000_000;
const ZERO: H = [0; 32];
fn n32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}
fn n64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}
fn h32(b: &[u8]) -> H {
    b.try_into().unwrap()
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
    pub fn parse(raw: &[u8]) -> Result<Self> {
        need(
            raw.len() == 112 && &raw[..8] == b"KPX7ST01" && raw[8..40] == crate::DOMAIN,
            "state_identity",
        )?;
        let n = n32(&raw[72..76]);
        let m = n32(&raw[108..112]);
        need(
            (1..=65536).contains(&n) && (1..=131072).contains(&m),
            "state_counts",
        )?;
        Ok(Self {
            raw: raw.try_into().unwrap(),
            cm: h32(&raw[40..72]),
            n,
            nf: h32(&raw[76..108]),
            m,
        })
    }
}
pub struct Spend<'a> {
    pub nf: H,
    pub cv: [u8; 64],
    pub proof: &'a [u8],
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
    pub session: H,
    pub roster: H,
    pub point: &'a [u8],
    pub old: State,
    pub new: State,
    pub reserve: u64,
    pub remaining: u64,
    pub fee: u64,
    pub delta: [u8; 32],
    pub spends: Vec<Spend<'a>>,
    pub outputs: Vec<Output<'a>>,
    pub nf_witnesses: &'a [u8],
    pub cm_paths: &'a [u8],
}
impl<'a> Body<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        need(raw.len() == BODY_LEN, "body_width")?;
        need(
            &raw[..8] == b"KPX7PB01"
                && raw[8..16] == [1, 0, 3, 0, 6, 0, 0, 0]
                && raw[16..48] == crate::DOMAIN,
            "body_identity",
        )?;
        let old = State::parse(&raw[148..260])?;
        let new = State::parse(&raw[268..380])?;
        let reserve = n64(&raw[260..268]);
        let remaining = n64(&raw[380..388]);
        let fee = n64(&raw[388..396]);
        need(
            (FLOOR..=MAX).contains(&reserve)
                && (FLOOR..=MAX).contains(&remaining)
                && (1..=MAX).contains(&fee)
                && remaining.checked_add(fee) == Some(reserve)
                && raw[396..404] == [0; 8],
            "body_money_or_payout",
        )?;
        need(
            raw[48..80] != ZERO && raw[80..112] != ZERO && raw[112..144] != ZERO,
            "body_context",
        )?;
        need(
            old.n >= 3
                && old.n.checked_add(6) == Some(new.n)
                && old.m.checked_add(3) == Some(new.m),
            "transition_counts",
        )?;
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        for i in 0..3 {
            let at = 436 + 96 * i;
            spends.push(Spend {
                nf: h32(&raw[at..at + 32]),
                cv: raw[at + 32..at + 96].try_into().unwrap(),
                proof: &raw[BODY_CORE_LEN + 128 * i..BODY_CORE_LEN + 128 * (i + 1)],
            });
        }
        for i in 0..6 {
            let row = &raw[724 + 520 * i..724 + 520 * (i + 1)];
            outputs.push(Output {
                cm: h32(&row[..32]),
                cv: row[32..96].try_into().unwrap(),
                cf: &row[96..360],
                cfh: h32(&row[360..392]),
                proof: &row[392..520],
                tuple: row,
            });
        }
        for (i, s) in spends.iter().enumerate() {
            need(
                s.nf != ZERO && spends[..i].iter().all(|p| p.nf != s.nf),
                "distinct_nonzero_nf",
            )?;
        }
        for (i, o) in outputs.iter().enumerate() {
            need(
                outputs[..i]
                    .iter()
                    .all(|p| p.cm != o.cm && p.tuple != o.tuple),
                "distinct_output_components",
            )?;
            need(sha(&[o.cf]) == o.cfh, "ciphertext_hash")?;
        }
        Ok(Self {
            raw,
            session: h32(&raw[48..80]),
            roster: h32(&raw[80..112]),
            point: &raw[112..148],
            old,
            new,
            reserve,
            remaining,
            fee,
            delta: raw[404..436].try_into().unwrap(),
            spends,
            outputs,
            nf_witnesses: &raw[3844..7324],
            cm_paths: &raw[7324..10396],
        })
    }
}
pub struct Projection<'a> {
    pub raw: &'a [u8],
    pub prefix: &'a [u8],
    pub body: Body<'a>,
}
impl<'a> Projection<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        need(raw.len() == PROJECTION_LEN, "projection_width")?;
        let p = &raw[..PREFIX_LEN];
        need(
            &p[..8] == b"KPX7FX01"
                && p[8..12] == [1, 0, 1, 0]
                && p[48..56] == [255; 8]
                && p[64..66] == [37, 0]
                && p[103..105] == [1, 0]
                && p[113..115] == [37, 0]
                && p[152] == 0
                && p[153..189] == [0; 36]
                && n32(&p[189..193]) == BODY_LEN as u32,
            "projection_header",
        )?;
        for spk in [&p[66..103], &p[115..152]] {
            need(
                spk[..4] == [0, 0, 0xaa, 0x20] && spk[36] == 0x87,
                "projection_script",
            )?;
        }
        let body = Body::parse(&raw[PREFIX_LEN..])?;
        need(
            p[12..48] == *body.point
                && n64(&p[56..64]) == body.reserve
                && n64(&p[105..113]) == body.remaining,
            "projection_effects",
        )?;
        Ok(Self {
            raw,
            prefix: p,
            body,
        })
    }
}
pub fn effects_digest(p: &Projection<'_>) -> H {
    sha(&[b"KPX7EF01", p.prefix, &p.body.raw[..BODY_CORE_LEN]])
}
fn fold(mut leaf: H, index: u32, path: &[u8], tag: &[u8], depth: usize) -> Result<H> {
    need(
        path.len() == 32 * depth && u64::from(index) < (1u64 << depth),
        "merkle_path",
    )?;
    for (i, s) in path.chunks_exact(32).enumerate() {
        leaf = if (index >> i) & 1 == 0 {
            sha(&[tag, &leaf, s])
        } else {
            sha(&[tag, s, &leaf])
        };
    }
    Ok(leaf)
}
fn nf_leaf(v: &H, next: &H, index: u32) -> H {
    sha(&[b"KPX1NFL\0", v, next, &index.to_le_bytes()])
}
fn lt(a: &H, b: &H) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}
fn insert(root: H, count: u32, nf: H, w: &[u8]) -> Result<H> {
    need(
        w.len() == 1160 && (1..131072).contains(&count),
        "nf_witness_count",
    )?;
    let i = n32(&w[..4]);
    let v = h32(&w[4..36]);
    let next = h32(&w[36..68]);
    let ni = n32(&w[68..72]);
    need(
        i < count
            && ni < count
            && (i == 0) == (v == ZERO)
            && (ni == 0) == (next == ZERO)
            && nf != ZERO,
        "nf_indices",
    )?;
    need(
        lt(&v, &nf) && (next == ZERO || lt(&nf, &next)),
        "nf_interval",
    )?;
    need(
        fold(nf_leaf(&v, &next, ni), i, &w[72..616], b"KPX1NFN\0", 17)? == root,
        "nf_predecessor_root",
    )?;
    let middle = fold(nf_leaf(&v, &nf, count), i, &w[72..616], b"KPX1NFN\0", 17)?;
    need(
        fold(sha(&[b"KPX1NFE\0"]), count, &w[616..], b"KPX1NFN\0", 17)? == middle,
        "nf_empty_append",
    )?;
    fold(nf_leaf(&nf, &next, ni), count, &w[616..], b"KPX1NFN\0", 17)
}
pub fn validate_transition(p: &Projection<'_>) -> Result<()> {
    let b = &p.body;
    let mut nf = b.old.nf;
    let mut count = b.old.m;
    for (s, w) in b.spends.iter().zip(b.nf_witnesses.chunks_exact(1160)) {
        nf = insert(nf, count, s.nf, w)?;
        count = count.checked_add(1).ok_or("nf_overflow")?;
    }
    need(nf == b.new.nf && count == b.new.m, "nf_successor")?;
    let mut cm = b.old.cm;
    let mut count = b.old.n;
    for (o, path) in b.outputs.iter().zip(b.cm_paths.chunks_exact(512)) {
        need(
            fold(sha(&[b"KPX1CME\0"]), count, path, b"KPX1CMN\0", 16)? == cm,
            "cm_empty_append",
        )?;
        cm = fold(o.cm, count, path, b"KPX1CMN\0", 16)?;
        count = count.checked_add(1).ok_or("cm_overflow")?;
    }
    need(cm == b.new.cm && count == b.new.n, "cm_successor")
}
