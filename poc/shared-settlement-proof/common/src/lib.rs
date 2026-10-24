//! ADR59 public settlement predicate. No note openings, PK, signing or network.
//! Native independently authenticates the current wrapper/state/body projection;
//! a supplied UTXO is not an accepted-chain authority or funding proof.
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_accelerated_bn254::Verifier;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const JOURNAL_LEN: usize = 424;
pub const PAYLOAD_LEN: usize = 8108;
pub const PROJECTION_LEN: usize = 8301;
pub const RECORD_LEN: usize = 4048;
const MAX: u64 = 2_870_000_000_000_000_000;
const FLOOR: u64 = 60_000_000;
const ZERO: [u8; 32] = [0; 32];
pub type H = [u8; 32];
pub type Result<T> = std::result::Result<T, &'static str>;
fn need(v: bool, e: &'static str) -> Result<()> {
    if v {
        Ok(())
    } else {
        Err(e)
    }
}
pub fn sha(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn n32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}
fn n64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}
fn h32(b: &[u8]) -> H {
    b.try_into().unwrap()
}
fn decode<const N: usize>(s: &str) -> Result<[u8; N]> {
    need(
        s.len() == N * 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "profile_hex",
    )?;
    let mut out = [0; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| "profile_hex")?;
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    schema: String,
    selected: bool,
    classification: String,
    trial_id: String,
    wrapper_domain_hex32: String,
    child_domain_hex32: String,
    child_role: String,
    child_mode: u8,
    child_count: u16,
    child_vk_hex328: Option<String>,
    child_vk_sha256: Option<String>,
    child_template_tail_hex: Option<String>,
    child_parameter_manifest_sha256: Option<String>,
    journal_bytes: usize,
    payload_bytes: usize,
    owner_witness_or_funding_authority: bool,
}
pub struct Profile {
    pub wrapper: H,
    pub domain: H,
    pub vk: VerifyingKey<Bn254>,
    pub vk_sha: H,
    pub tail: Vec<u8>,
}
impl Profile {
    pub fn installed() -> Result<Self> {
        let f: ProfileFile = serde_json::from_slice(include_bytes!("../../child-profile.json"))
            .map_err(|_| "profile_json")?;
        need(f.selected, "profile_unselected")?;
        need(
            f.schema == "kpx5-public-virtual-settlement-child-profile/v1"
                && f.classification == "PUBLIC_SYNTHETIC_DO_NOT_FUND_UNFUNDED_BENCHMARK_ONLY"
                && !f.trial_id.is_empty()
                && f.child_role == "compact2"
                && f.child_mode == 2
                && f.child_count == 2
                && f.journal_bytes == JOURNAL_LEN
                && f.payload_bytes == PAYLOAD_LEN
                && !f.owner_witness_or_funding_authority,
            "profile_identity",
        )?;
        let wrapper = decode(&f.wrapper_domain_hex32)?;
        let domain = decode(&f.child_domain_hex32)?;
        need(
            wrapper != domain && wrapper != ZERO && domain != ZERO,
            "profile_domains",
        )?;
        let raw = decode::<328>(&f.child_vk_hex328.ok_or("profile_vk_missing")?)?;
        let vk_sha = decode(&f.child_vk_sha256.ok_or("profile_vk_missing")?)?;
        need(sha(&[&raw]) == vk_sha, "profile_vk_digest")?;
        decode::<32>(
            &f.child_parameter_manifest_sha256
                .ok_or("profile_manifest_missing")?,
        )?;
        let mut remaining = raw.as_slice();
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut remaining)
            .map_err(|_| "profile_vk_decode")?;
        let mut canonical = Vec::new();
        vk.serialize_compressed(&mut canonical)
            .map_err(|_| "profile_vk_encode")?;
        need(
            remaining.is_empty()
                && canonical == raw
                && vk.gamma_abc_g1.len() == 3
                && !vk.alpha_g1.is_zero()
                && !vk.beta_g2.is_zero()
                && !vk.gamma_g2.is_zero()
                && !vk.delta_g2.is_zero()
                && vk.gamma_abc_g1.iter().all(|p| !p.is_zero()),
            "profile_vk_encoding",
        )?;
        let tail_hex = f
            .child_template_tail_hex
            .ok_or("profile_template_missing")?;
        need(
            tail_hex.len() % 2 == 0
                && tail_hex.len() <= 130_000
                && tail_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "profile_template_hex",
        )?;
        let tail = hex::decode(tail_hex).map_err(|_| "profile_template_hex")?;
        need(
            !tail.is_empty()
                && tail.len() + 114 <= u16::MAX as usize
                && tail.windows(raw.len()).filter(|w| *w == raw).count() == 1,
            "profile_template_key",
        )?;
        Ok(Self {
            wrapper,
            domain,
            vk,
            vk_sha,
            tail,
        })
    }
    pub fn verifier(&self) -> Verifier {
        Verifier::from_validated_program_key(&self.vk, self.vk_sha)
    }
    pub fn crypto(&self, auth: &[u8], proof: &[u8]) -> Result<()> {
        need(
            auth.len() == 528
                && auth[..40] == [b"KPX4AU01".as_slice(), self.domain.as_slice()].concat(),
            "auth_domain",
        )?;
        let d = sha(&[auth]);
        let inputs = [
            Fr::from_le_bytes_mod_order(&d[..16]),
            Fr::from_le_bytes_mod_order(&d[16..]),
        ];
        self.verifier().verify_inputs(proof, &inputs)
    }
    fn child_spk(&self, state: &[u8]) -> Vec<u8> {
        let mut redeem = b"\x4c\x70".to_vec();
        redeem.extend(state);
        redeem.extend(&self.tail);
        let hash = blake2b_simd::Params::new().hash_length(32).hash(&redeem);
        [
            b"\x00\x00\xaa\x20".as_slice(),
            hash.as_bytes(),
            b"\x87".as_slice(),
        ]
        .concat()
    }
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("wire_length")?;
        let out = self.raw.get(self.at..end).ok_or("wire_length")?;
        self.at = end;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(n64(self.bytes(8)?))
    }
}
pub struct Projection<'a> {
    pub point: &'a [u8],
    pub reserve: u64,
    pub remaining: u64,
    pub payload: &'a [u8],
}
impl<'a> Projection<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        need(raw.len() == PROJECTION_LEN, "projection_width")?;
        let mut r = Reader { raw, at: 0 };
        need(
            r.bytes(8)? == b"KPX5FB01" && r.u16()? == 1 && r.u16()? == 1,
            "projection_header",
        )?;
        let point = r.bytes(36)?;
        need(r.bytes(8)? == [255; 8], "projection_sequence")?;
        let reserve = r.u64()?;
        need(r.u16()? == 37, "projection_input_spk_width")?;
        let input_spk = r.bytes(37)?;
        need(
            input_spk[..4] == [0, 0, 0xaa, 0x20] && input_spk[36] == 0x87,
            "projection_input_spk",
        )?;
        need(r.u16()? == 1, "projection_outputs")?;
        let remaining = r.u64()?;
        need(r.u16()? == 37, "projection_output_spk_width")?;
        let output_spk = r.bytes(37)?;
        need(
            output_spk[..4] == [0, 0, 0xaa, 0x20] && output_spk[36] == 0x87,
            "projection_output_spk",
        )?;
        need(
            r.bytes(1)? == [0] && r.u64()? == 0 && r.bytes(20)? == [0; 20] && r.u64()? == 0,
            "projection_covenant_or_header",
        )?;
        need(
            n32(r.bytes(4)?) == PAYLOAD_LEN as u32,
            "projection_payload_width",
        )?;
        let payload = r.bytes(PAYLOAD_LEN)?;
        need(
            r.at == raw.len()
                && (FLOOR..=MAX).contains(&reserve)
                && (FLOOR..=MAX).contains(&remaining)
                && remaining < reserve,
            "projection_money_or_exhaustion",
        )?;
        need(
            &payload[..8] == b"KPX5VP01" && payload[8..12] == [1, 0, 2, 0],
            "aggregate_frame",
        )?;
        Ok(Self {
            point,
            reserve,
            remaining,
            payload,
        })
    }
}

#[derive(Clone)]
struct State {
    cm: H,
    n: u32,
    nf: H,
    m: u32,
}
fn state(raw: &[u8], d: &H) -> Result<State> {
    need(
        raw.len() == 112 && &raw[..8] == b"KPX2ST01" && raw[8..40] == *d,
        "state_identity",
    )?;
    let n = n32(&raw[72..76]);
    let m = n32(&raw[108..112]);
    need(
        (1..=65535).contains(&n)
            && (1..=131071).contains(&m)
            && u64::from(m) <= 2 * u64::from(n) + 1,
        "state_counts",
    )?;
    Ok(State {
        cm: h32(&raw[40..72]),
        n,
        nf: h32(&raw[76..108]),
        m,
    })
}
fn node(tag: &[u8], l: &H, r: &H) -> H {
    sha(&[tag, l, r])
}
fn fold(mut leaf: H, index: u32, path: &[u8], tag: &[u8]) -> Result<H> {
    need(
        path.len() % 32 == 0
            && path.len() / 32 < 32
            && u64::from(index) < (1u64 << (path.len() / 32)),
        "merkle_width_or_index",
    )?;
    for (i, s) in path.chunks_exact(32).enumerate() {
        let sibling = h32(s);
        leaf = if (index >> i) & 1 == 0 {
            node(tag, &leaf, &sibling)
        } else {
            node(tag, &sibling, &leaf)
        };
    }
    Ok(leaf)
}
fn lt(a: &H, b: &H) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}
fn nf_leaf(value: &H, next: &H, index: u32) -> H {
    sha(&[b"KPX1NFL\0", value, next, &index.to_le_bytes()])
}
fn insert(root: H, count: u32, nf: H, w: &[u8]) -> Result<H> {
    need(
        w.len() == 1160 && (1..131071).contains(&count),
        "nf_width_or_count",
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
        "nf_indices_or_sentinel",
    )?;
    need(
        fold(nf_leaf(&v, &next, ni), i, &w[72..616], b"KPX1NFN\0")? == root,
        "nf_predecessor_root",
    )?;
    need(
        lt(&v, &nf) && (next == ZERO || lt(&nf, &next)),
        "nf_strict_interval",
    )?;
    let middle = fold(nf_leaf(&v, &nf, count), i, &w[72..616], b"KPX1NFN\0")?;
    need(
        fold(sha(&[b"KPX1NFE\0"]), count, &w[616..], b"KPX1NFN\0")? == middle,
        "nf_empty_append",
    )?;
    fold(nf_leaf(&nf, &next, ni), count, &w[616..], b"KPX1NFN\0")
}
fn child_public(payload: &[u8], p: &Profile) -> Result<()> {
    need(payload.len() == 3920, "child_payload_width")?;
    let a = &payload[..528];
    need(
        &a[..8] == b"KPX4AU01"
            && a[8..40] == p.domain
            && a[300] == 2
            && a[301..304] == [0; 3]
            && a[308..332] == [0; 24]
            && a[484..528] == [0; 44],
        "child_domain_mode_or_P0",
    )?;
    let old = state(&a[76..188], &p.domain)?;
    let new = state(&a[364..476], &p.domain)?;
    let reserve = n64(&a[188..196]);
    let fee = n64(&a[196..204]);
    let after = n64(&a[476..484]);
    need(
        (FLOOR..=MAX).contains(&reserve)
            && (1..=MAX).contains(&fee)
            && (FLOOR..=MAX).contains(&after)
            && after.checked_add(fee) == Some(reserve),
        "child_reserve",
    )?;
    let start = n32(&a[304..308]);
    let aligned = old.n.checked_add(1).ok_or("cm_count")? / 2 * 2;
    need(
        start == aligned
            && start.checked_add(2) == Some(new.n)
            && old.m.checked_add(2) == Some(new.m),
        "child_counts",
    )?;
    let nf0 = h32(&a[204..236]);
    let nf1 = h32(&a[236..268]);
    need(
        nf0 != ZERO && nf1 != ZERO && nf0 != nf1,
        "child_nf_distinct",
    )?;
    let root = insert(old.nf, old.m, nf0, &payload[528..1688])?;
    need(
        insert(root, old.m + 1, nf1, &payload[1688..2848])? == new.nf,
        "nf_successor",
    )?;
    need(
        sha(&[&payload[2848..2912]]) == a[268..300] && sha(&[&payload[2912..3440]]) == a[332..364],
        "child_CM_CF_digest",
    )?;
    let empty = sha(&[b"KPX1CME\0"]);
    let empty_block = node(b"KPX1CMN\0", &empty, &empty);
    need(
        fold(empty_block, start / 2, &payload[3440..], b"KPX1CMN\0")? == old.cm,
        "cm_empty_block",
    )?;
    let block = node(
        b"KPX1CMN\0",
        &h32(&payload[2848..2880]),
        &h32(&payload[2880..2912]),
    );
    need(
        fold(block, start / 2, &payload[3440..], b"KPX1CMN\0")? == new.cm,
        "cm_successor",
    )
}

fn keyed(tag: &[u8], parts: &[&[u8]]) -> H {
    let mut key = [0; 32];
    key[..tag.len()].copy_from_slice(tag);
    let mut h = blake3::Hasher::new_keyed(&key);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}
/// Exact pinned Kaspa v1 preimage subset. BLAKE3 is the established library,
/// domain padding/encoding mirrors upstream hashing/tx.rs and hashers.rs.
pub fn virtual_id(p: &Profile, payload: &[u8]) -> Result<H> {
    need(payload.len() == 3920, "virtual_payload")?;
    let a = &payload[..528];
    let spk = p.child_spk(&a[364..476]);
    let mut rest = Vec::new();
    rest.extend(1u16.to_le_bytes());
    rest.extend(1u64.to_le_bytes());
    rest.extend(&a[40..76]);
    rest.extend(0u64.to_le_bytes());
    rest.extend(u64::MAX.to_le_bytes());
    rest.extend(1u64.to_le_bytes());
    rest.extend(&a[476..484]);
    rest.extend(0u16.to_le_bytes());
    rest.extend(35u64.to_le_bytes());
    rest.extend(&spk[2..]);
    rest.push(0);
    rest.extend(0u64.to_le_bytes());
    rest.extend([0; 20]);
    rest.extend(0u64.to_le_bytes());
    rest.extend(0u64.to_le_bytes());
    let ph = keyed(b"PayloadDigest", &[payload]);
    let rh = keyed(b"TransactionRest", &[&rest]);
    Ok(keyed(b"TransactionV1Id", &[&ph, &rh]))
}

pub fn evaluate(input: &[u8]) -> Result<[u8; JOURNAL_LEN]> {
    let p = Profile::installed()?;
    let body = Projection::parse(input)?;
    let records = &body.payload[12..];
    let first = &records[..RECORD_LEN];
    let second = &records[RECORD_LEN..];
    let a0 = &first[..528];
    let a1 = &second[..528];
    child_public(&first[..3920], &p)?;
    child_public(&second[..3920], &p)?;
    need(
        a0[40..76] == *body.point && n64(&a0[188..196]) == body.reserve,
        "actual_start_binding",
    )?;
    need(
        a1[40..72] == virtual_id(&p, &first[..3920])?
            && a1[72..76] == [0; 4]
            && a1[76..188] == a0[364..476]
            && a1[188..196] == a0[476..484],
        "virtual_continuity",
    )?;
    for x in [&a0[204..236], &a0[236..268]] {
        for y in [&a1[204..236], &a1[236..268]] {
            need(x != y, "cross_child_nf")?;
        }
    }
    let fee = n64(&a0[196..204])
        .checked_add(n64(&a1[196..204]))
        .ok_or("total_fee")?;
    need(
        n64(&a1[476..484]) == body.remaining
            && body.remaining.checked_add(fee) == Some(body.reserve),
        "actual_fee_or_final_reserve",
    )?;
    p.crypto(a0, &first[3920..])?;
    p.crypto(a1, &second[3920..])?;
    let mut j = Vec::with_capacity(JOURNAL_LEN);
    j.extend(b"KPX5VS01");
    j.extend(1u16.to_le_bytes());
    j.extend(p.wrapper);
    j.extend(p.domain);
    j.extend(2u16.to_le_bytes());
    j.extend(body.point);
    j.extend(&a0[76..188]);
    j.extend(body.reserve.to_le_bytes());
    j.extend(&a1[364..476]);
    j.extend(body.remaining.to_le_bytes());
    j.extend(fee.to_le_bytes());
    j.extend(sha(&[records]));
    j.extend(sha(&[input]));
    j.try_into().map_err(|_| "journal_width")
}
