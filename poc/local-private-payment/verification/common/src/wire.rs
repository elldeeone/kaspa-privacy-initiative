//! Public canonical frame and authenticated sparse-tree updates, no owner data.
use crate::{need, sha, Result, H};
pub const BODY_LEN: usize = 3884;
pub const BODY_CORE_LEN: usize = 3756;
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
            raw.len() == 112 && &raw[..8] == b"KPXAST01" && raw[8..40] == crate::DOMAIN,
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
    pub action_id: H,
    pub reserved_zero: H,
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
            &raw[..8] == b"KPXAPB01"
                && raw[8..16] == [1, 0, 1, 0, 2, 0, 0, 0]
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
            raw[48..80] != ZERO && raw[80..112] == ZERO && raw[112..144] != ZERO,
            "body_context",
        )?;
        need(
            old.n >= 1
                && old.n.checked_add(2) == Some(new.n)
                && old.m.checked_add(1) == Some(new.m),
            "transition_counts",
        )?;
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        for i in 0..1 {
            let at = 436 + 96 * i;
            spends.push(Spend {
                nf: h32(&raw[at..at + 32]),
                cv: raw[at + 32..at + 96].try_into().unwrap(),
                proof: &raw[BODY_CORE_LEN + 128 * i..BODY_CORE_LEN + 128 * (i + 1)],
            });
        }
        for i in 0..2 {
            let row = &raw[532 + 520 * i..532 + 520 * (i + 1)];
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
                o.cm != ZERO
                    && o.cm != sha(&[b"KPX1CME\0"])
                    && outputs[..i]
                        .iter()
                        .all(|p| p.cm != o.cm && p.tuple != o.tuple),
                "distinct_output_components",
            )?;
            need(sha(&[o.cf]) == o.cfh, "ciphertext_hash")?;
        }
        Ok(Self {
            raw,
            action_id: h32(&raw[48..80]),
            reserved_zero: h32(&raw[80..112]),
            point: &raw[112..148],
            old,
            new,
            reserve,
            remaining,
            fee,
            delta: raw[404..436].try_into().unwrap(),
            spends,
            outputs,
            nf_witnesses: &raw[1572..2732],
            cm_paths: &raw[2732..3756],
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
            &p[..8] == b"KPXAFX01"
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
    sha(&[b"KPXAEF01", p.prefix, &p.body.raw[..BODY_CORE_LEN]])
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

pub const EXIT_BODY_LEN: usize = 1632;
pub const EXIT_CONTINUING_PREFIX_LEN: usize = 240;
pub const EXIT_TERMINAL_PREFIX_LEN: usize = 192;
pub const PAYOUT_FLOOR: u64 = 10_000_000;
pub struct ExitBody<'a> {
    pub raw: &'a [u8],
    pub point: &'a [u8],
    pub old: State,
    pub new: State,
    pub reserve: u64,
    pub remaining: u64,
    pub fee: u64,
    pub payout: u64,
    pub payout_spk: &'a [u8],
    pub nf: H,
    pub nf_witness: &'a [u8],
}
impl<'a> ExitBody<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        need(raw.len() == EXIT_BODY_LEN, "exit_body_width")?;
        need(
            &raw[..16] == b"KPXAXB01\x01\0\x01\0\0\0\x01\0"
                && raw[16..48] == crate::DOMAIN
                && raw[80..112] == ZERO,
            "exit_body_identity",
        )?;
        let old = State::parse(&raw[148..260])?;
        let new = State::parse(&raw[268..380])?;
        let reserve = n64(&raw[260..268]);
        let remaining = n64(&raw[380..388]);
        let fee = n64(&raw[388..396]);
        let payout = n64(&raw[396..404]);
        need(
            (FLOOR..=MAX).contains(&reserve)
                && (1..=MAX).contains(&fee)
                && (PAYOUT_FLOOR..=MAX).contains(&payout)
                && (remaining == 0 || (FLOOR..=MAX).contains(&remaining))
                && remaining
                    .checked_add(fee)
                    .and_then(|v| v.checked_add(payout))
                    == Some(reserve),
            "exit_money",
        )?;
        need(raw[48..80] != ZERO && raw[112..144] != ZERO, "exit_context")?;
        need(
            old.cm == new.cm && old.n == new.n && old.m.checked_add(1) == Some(new.m),
            "exit_state_counts_or_cm",
        )?;
        need(
            raw[404..407] == [0, 0, 0x20] && raw[439] == 0xac && raw[440..472] != ZERO,
            "exit_spk_or_nf",
        )?;
        Ok(Self {
            raw,
            point: &raw[112..148],
            old,
            new,
            reserve,
            remaining,
            fee,
            payout,
            payout_spk: &raw[404..440],
            nf: h32(&raw[440..472]),
            nf_witness: &raw[472..1632],
        })
    }
}
pub struct ExitProjection<'a> {
    pub raw: &'a [u8],
    pub prefix: &'a [u8],
    pub body: ExitBody<'a>,
}
impl<'a> ExitProjection<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        need(
            [
                EXIT_BODY_LEN + EXIT_CONTINUING_PREFIX_LEN,
                EXIT_BODY_LEN + EXIT_TERMINAL_PREFIX_LEN,
            ]
            .contains(&raw.len()),
            "exit_projection_width",
        )?;
        let width = raw.len() - EXIT_BODY_LEN;
        let p = &raw[..width];
        let b = ExitBody::parse(&raw[width..])?;
        need(
            &p[..8] == b"KPXAFX01"
                && p[8..12] == [1, 0, 1, 0]
                && p[48..56] == [255; 8]
                && p[64..66] == [37, 0]
                && p[66..70] == [0, 0, 0xaa, 0x20]
                && p[102] == 0x87,
            "exit_projection_header",
        )?;
        let count = u16::from_le_bytes(p[103..105].try_into().unwrap());
        need(
            count == if b.remaining == 0 { 1 } else { 2 },
            "exit_output_count",
        )?;
        let mut at = 105;
        let mut outputs = Vec::new();
        for _ in 0..count {
            need(at + 10 <= width, "exit_output_frame")?;
            let value = n64(&p[at..at + 8]);
            let len = u16::from_le_bytes(p[at + 8..at + 10].try_into().unwrap()) as usize;
            need(
                [36, 37].contains(&len) && at + 11 + len <= width,
                "exit_output_width",
            )?;
            need(p[at + 10 + len] == 0, "exit_output_covenant")?;
            outputs.push((value, &p[at + 10..at + 10 + len]));
            at += 11 + len;
        }
        need(
            at + 40 == width
                && p[at..at + 36] == [0; 36]
                && n32(&p[at + 36..at + 40]) == EXIT_BODY_LEN as u32,
            "exit_projection_tail",
        )?;
        need(
            p[12..48] == *b.point && n64(&p[56..64]) == b.reserve,
            "exit_projection_input",
        )?;
        need(
            *outputs.last().unwrap() == (b.payout, b.payout_spk),
            "exit_projection_payout",
        )?;
        if b.remaining != 0 {
            let (v, s) = outputs[0];
            need(
                v == b.remaining && s.len() == 37 && s[..4] == [0, 0, 0xaa, 0x20] && s[36] == 0x87,
                "exit_projection_continuation",
            )?;
        }
        let sum = outputs
            .iter()
            .try_fold(0u64, |a, (v, _)| a.checked_add(*v))
            .ok_or("exit_output_sum")?;
        need(
            b.reserve.checked_sub(sum) == Some(b.fee),
            "exit_projection_fee",
        )?;
        Ok(Self {
            raw,
            prefix: p,
            body: b,
        })
    }
}
pub fn exit_effects_digest(p: &ExitProjection<'_>) -> H {
    sha(&[b"KPXAEF01", p.prefix, p.body.raw])
}
pub fn validate_exit_transition(p: &ExitProjection<'_>) -> Result<()> {
    let b = &p.body;
    need(
        insert(b.old.nf, b.old.m, b.nf, b.nf_witness)? == b.new.nf,
        "exit_nf_successor",
    )
}
