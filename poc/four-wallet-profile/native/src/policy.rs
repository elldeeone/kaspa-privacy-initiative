//! UNFUNDED scheduled-settlement wrapper, with separately selected diagnostic template.
//! The private helpers below adapt ADR58 capacity policy; its mode0 no-CM semantics
//! are independent of terminal reserve and retain the original shared real NF.
//! No admission, revealing exit, admin withdrawal or funded-profile migration exists.
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
use sha2::{Digest, Sha256};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const DOMAIN: [u8; 32] = [
    38, 48, 237, 74, 51, 138, 250, 96, 211, 225, 116, 122, 13, 136, 117, 186, 5, 244, 182, 105, 78, 239, 195, 69, 169, 119, 222, 248, 0, 196, 184, 158,
];
pub const STATE_MAGIC: &[u8; 8] = b"KPX2ST01";
pub const AUTH_MAGIC: &[u8; 8] = b"KPX4AU01";
pub const REVEAL_MAGIC: &[u8; 8] = b"KPX2RV01";
pub const MAX: i64 = 2_870_000_000_000_000_000;
pub const NOTE_FLOOR: i64 = 60_000_000;
pub const PAYOUT_FLOOR: i64 = 10_000_000;
pub const REDEEM_START: usize = 199;
pub const PRIVATE_PAYLOAD: usize = 3920;
pub const WIDE_PAYLOAD: usize = 12672;
pub const TERMINAL_PAYLOAD: usize = 2848;
pub const REVEAL_PAYLOAD: usize = 2029;
pub const PRIVATE_BUDGET: u16 = 1600;
pub const REVEAL_BUDGET: u16 = 200;
const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
const LEAF_TAG: &[u8; 8] = b"KPX1NFL\0";
const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
const NF_NODE: &[u8; 8] = b"KPX1NFN\0";
const O: usize = 9;
const INC: usize = 41;
const VALUE: usize = 73;
const RHO: usize = 81;
const KEY: usize = 113;
const PK: usize = 145;
const POS: usize = 177;
const KC: usize = 181;
const CM: usize = 213;
const CMPATH: usize = 245;
const NF: usize = 1917;
const NEWROOT: usize = 1981;
const FEE: usize = 2013;
const PAY: usize = 2021;
fn op(b: &mut ScriptBuilder, c: u8) {
    b.add_op(c).unwrap();
}
fn num(b: &mut ScriptBuilder, n: i64) {
    b.add_i64(n).unwrap();
}
fn data(b: &mut ScriptBuilder, d: &[u8]) {
    b.add_data(d).unwrap();
}
fn cat(b: &mut ScriptBuilder) {
    op(b, OpCat)
}
fn verify(b: &mut ScriptBuilder) {
    op(b, OpVerify)
}
fn pl(b: &mut ScriptBuilder, o: usize, l: usize) {
    num(b, o as i64);
    num(b, (o + l) as i64);
    op(b, OpTxPayloadSubstr)
}
fn ss(b: &mut ScriptBuilder, o: usize, l: usize) {
    num(b, 0);
    num(b, o as i64);
    num(b, (o + l) as i64);
    op(b, OpTxInputScriptSigSubstr)
}
fn st(b: &mut ScriptBuilder, o: usize, l: usize) {
    ss(b, REDEEM_START + 2 + o, l)
}
fn unum(b: &mut ScriptBuilder, o: usize, l: usize) {
    pl(b, o, l);
    if l < 8 {
        data(b, &[0]);
        cat(b)
    }
    op(b, OpBin2Num)
}
fn snum(b: &mut ScriptBuilder, o: usize) {
    st(b, o, 4);
    data(b, &[0]);
    cat(b);
    op(b, OpBin2Num)
}
fn eqn(b: &mut ScriptBuilder, c: u8, n: i64) {
    op(b, c);
    num(b, n);
    op(b, OpNumEqualVerify)
}
fn eqdata(b: &mut ScriptBuilder, o: usize, d: &[u8]) {
    pl(b, o, d.len());
    data(b, d);
    op(b, OpEqualVerify)
}
fn range(b: &mut ScriptBuilder, o: usize, l: usize, lo: i64, hi: i64) {
    unum(b, o, l);
    num(b, lo);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    unum(b, o, l);
    num(b, hi);
    op(b, OpLessThanOrEqual);
    verify(b)
}
fn state_count_bounds(b: &mut ScriptBuilder) {
    for (o, hi) in [(72, 65535), (108, 131071)] {
        snum(b, o);
        num(b, 1);
        op(b, OpGreaterThanOrEqual);
        verify(b);
        snum(b, o);
        num(b, hi);
        op(b, OpLessThanOrEqual);
        verify(b)
    }
    snum(b, 108);
    snum(b, 72);
    num(b, 2);
    op(b, OpMul);
    num(b, 1);
    op(b, OpAdd);
    op(b, OpLessThanOrEqual);
    verify(b)
}
#[derive(Copy, Clone)]
enum Index {
    Payload(usize),
    State { offset: usize, add: i64 },
}
fn index(b: &mut ScriptBuilder, i: Index) {
    match i {
        Index::Payload(o) => unum(b, o, 4),
        Index::State { offset, add } => {
            snum(b, offset);
            if add != 0 {
                num(b, add);
                op(b, OpAdd)
            }
        }
    }
}
fn path(b: &mut ScriptBuilder, start: usize, depth: usize, i: Index, tag: &[u8]) {
    for j in 0..depth {
        index(b, i);
        num(b, 1 << j);
        op(b, OpDiv);
        num(b, 2);
        op(b, OpMod);
        op(b, OpIf);
        pl(b, start + 32 * j, 32);
        op(b, OpSwap);
        op(b, OpElse);
        pl(b, start + 32 * j, 32);
        op(b, OpEndIf);
        cat(b);
        data(b, tag);
        op(b, OpSwap);
        cat(b);
        op(b, OpSHA256)
    }
}
fn lt256(b: &mut ScriptBuilder, a: usize, c: usize) {
    num(b, 0);
    for (start, len) in [(0, 7), (7, 7), (14, 7), (21, 7), (28, 4)] {
        unum(b, a + start, len);
        unum(b, c + start, len);
        op(b, OpEqual);
        op(b, OpBoolAnd);
        unum(b, a + start, len);
        unum(b, c + start, len);
        op(b, OpLessThan);
        op(b, OpBoolOr)
    }
}
fn leaf(b: &mut ScriptBuilder, v: usize, next: usize, nexti: Index) {
    data(b, LEAF_TAG);
    pl(b, v, 32);
    cat(b);
    pl(b, next, 32);
    cat(b);
    match nexti {
        Index::Payload(o) => pl(b, o, 4),
        i => {
            index(b, i);
            num(b, 4);
            op(b, OpNum2Bin)
        }
    }
    cat(b);
    op(b, OpSHA256)
}
fn empty(tag: &[u8]) -> [u8; 32] {
    Sha256::digest(tag).into()
}
// Stack currentNFroot -> exact newNFroot. The authenticated predecessor path
// and append index are reused; there is no independent old/new path walk.
fn insert_nf(b: &mut ScriptBuilder, nf: usize, w: usize, slot: i64, mid: Option<usize>) {
    let pi = w;
    let pv = w + 4;
    let pn = w + 36;
    let pni = w + 68;
    let pp = w + 72;
    let ap = w + 616;
    let append = Index::State {
        offset: 108,
        add: slot,
    };
    for off in [pi, pni] {
        unum(b, off, 4);
        index(b, append);
        op(b, OpLessThan);
        verify(b)
    }
    unum(b, pi, 4);
    num(b, 0);
    op(b, OpNumEqual);
    pl(b, pv, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpEqualVerify);
    unum(b, pni, 4);
    num(b, 0);
    op(b, OpNumEqual);
    pl(b, pn, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpEqualVerify);
    pl(b, nf, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    verify(b);
    op(b, OpToAltStack);
    leaf(b, pv, pn, Index::Payload(pni));
    path(b, pp, 17, Index::Payload(pi), NF_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    lt256(b, pv, nf);
    verify(b);
    pl(b, pn, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    op(b, OpIf);
    lt256(b, nf, pn);
    verify(b);
    op(b, OpEndIf);
    leaf(b, pv, nf, append);
    path(b, pp, 17, Index::Payload(pi), NF_NODE);
    if let Some(o) = mid {
        op(b, OpDup);
        pl(b, o, 32);
        op(b, OpEqualVerify)
    }
    op(b, OpToAltStack);
    data(b, &empty(b"KPX1NFE\0"));
    path(b, ap, 17, append, NF_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    leaf(b, nf, pn, Index::Payload(pni));
    path(b, ap, 17, append, NF_NODE)
}
// Stack currentCMroot -> newCMroot, with current empty-slot authentication.
fn append_cm(b: &mut ScriptBuilder, cm: usize, w: usize, slot: i64) {
    let at = Index::State {
        offset: 72,
        add: slot,
    };
    op(b, OpToAltStack);
    data(b, &empty(b"KPX1CME\0"));
    path(b, w, 16, at, CM_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    pl(b, cm, 32);
    path(b, w, 16, at, CM_NODE)
}
fn native_amount(b: &mut ScriptBuilder, code: u8, which: i64) {
    num(b, which);
    op(b, code)
}
fn amount_bytes(b: &mut ScriptBuilder, code: u8, which: i64) {
    native_amount(b, code, which);
    num(b, 8);
    op(b, OpNum2Bin)
}
fn successor(b: &mut ScriptBuilder, len: usize, private: bool) {
    ss(b, REDEEM_START, 2);
    if private {
        pl(b, 364, 112)
    } else {
        st(b, 0, 76);
        pl(b, NEWROOT, 32);
        cat(b);
        snum(b, 108);
        num(b, 1);
        op(b, OpAdd);
        num(b, 4);
        op(b, OpNum2Bin);
        cat(b)
    }
    cat(b);
    ss(b, REDEEM_START + 114, len - 114);
    cat(b);
    op(b, OpBlake2b);
    data(b, &[0, 0, OpBlake2b, OpData32]);
    op(b, OpSwap);
    cat(b);
    data(b, &[OpEqual]);
    cat(b);
    num(b, 0);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify)
}
// New Auth528: array digest@268, mode byte@300, aligned start@304,
// reserved bytes@301..304 and308..332, existing cipher digest@332.
// Public NF paths immediately follow Auth at528 and1688 in every mode.
fn subtree_path(b: &mut ScriptBuilder, start: usize, depth: usize, slots: i64) {
    for j in 0..depth {
        unum(b, 304, 4);
        num(b, slots);
        op(b, OpDiv);
        num(b, 1 << j);
        op(b, OpDiv);
        num(b, 2);
        op(b, OpMod);
        op(b, OpIf);
        pl(b, start + 32 * j, 32);
        op(b, OpSwap);
        op(b, OpElse);
        pl(b, start + 32 * j, 32);
        op(b, OpEndIf);
        cat(b);
        data(b, CM_NODE);
        op(b, OpSwap);
        cat(b);
        op(b, OpSHA256);
    }
}
fn cm_subroot(b: &mut ScriptBuilder, first: usize, slots: usize) {
    if slots == 1 {
        pl(b, 2848 + 32 * first, 32);
    } else {
        cm_subroot(b, first, slots / 2);
        cm_subroot(b, first + slots / 2, slots / 2);
        cat(b);
        data(b, CM_NODE);
        op(b, OpSwap);
        cat(b);
        op(b, OpSHA256);
    }
}
fn cm_mode(b: &mut ScriptBuilder, slots: usize) {
    let level = slots.trailing_zeros() as usize;
    let start = 2848 + 296 * slots;
    let payload = start + 32 * (16 - level);
    eqn(b, OpTxPayloadLen, payload as i64);
    eqdata(b, 300, &[slots as u8]);
    eqdata(b, 301, &[0; 3]);
    eqdata(b, 308, &[0; 24]);
    // Inductive empty suffix; only target-block emptiness is authenticated here.
    unum(b, 148, 4);
    num(b, (slots - 1) as i64);
    op(b, OpAdd);
    num(b, slots as i64);
    op(b, OpDiv);
    num(b, slots as i64);
    op(b, OpMul);
    unum(b, 304, 4);
    op(b, OpNumEqualVerify);
    unum(b, 304, 4);
    num(b, slots as i64);
    op(b, OpAdd);
    op(b, OpDup);
    num(b, 65535);
    op(b, OpLessThanOrEqual);
    verify(b);
    unum(b, 436, 4);
    op(b, OpNumEqualVerify);
    if slots == 32 {
        eqdata(b, 484, &[0; 8]);
    }
    pl(b, 2848, 32 * slots);
    op(b, OpSHA256);
    pl(b, 268, 32);
    op(b, OpEqualVerify);
    pl(b, 2848 + 32 * slots, 264 * slots);
    op(b, OpSHA256);
    pl(b, 332, 32);
    op(b, OpEqualVerify);
    let mut empty_root = empty(b"KPX1CME\0");
    for _ in 0..level {
        let mut h = Sha256::new();
        h.update(CM_NODE);
        h.update(empty_root);
        h.update(empty_root);
        empty_root = h.finalize().into();
    }
    st(b, 40, 32);
    op(b, OpToAltStack);
    data(b, &empty_root);
    subtree_path(b, start, 16 - level, slots as i64);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    cm_subroot(b, 0, slots);
    subtree_path(b, start, 16 - level, slots as i64);
    pl(b, 404, 32);
    op(b, OpEqualVerify);
    // N-way distinctness and exact private outputs are NEW proof obligations.
    // The new-domain matched role relations bind every ordered output.
}
fn private_branch(b: &mut ScriptBuilder, len: usize, compact_vk: &[u8], wide_vk: &[u8]) {
    data(b, &[0; 65]);
    op(b, OpEqualVerify);
    eqn(b, OpTxInputCount, 1);
    eqdata(b, 8, &DOMAIN);
    st(b, 0, 112);
    pl(b, 76, 112);
    op(b, OpEqualVerify);
    num(b, 0);
    op(b, OpOutpointTxId);
    pl(b, 40, 32);
    op(b, OpEqualVerify);
    num(b, 0);
    op(b, OpOutpointIndex);
    num(b, 8);
    op(b, OpNum2Bin);
    num(b, 0);
    num(b, 4);
    op(b, OpSubstr);
    pl(b, 72, 4);
    op(b, OpEqualVerify);
    amount_bytes(b, OpTxInputAmount, 0);
    pl(b, 188, 8);
    op(b, OpEqualVerify);
    range(b, 188, 8, NOTE_FLOOR, MAX);
    range(b, 196, 8, 1, MAX);
    range(b, 476, 8, 0, MAX);
    range(b, 484, 8, 0, MAX);
    unum(b, 188, 8);
    unum(b, 196, 8);
    op(b, OpSub);
    unum(b, 484, 8);
    op(b, OpSub);
    unum(b, 476, 8);
    op(b, OpNumEqualVerify);
    eqdata(b, 364, STATE_MAGIC);
    eqdata(b, 372, &DOMAIN);
    unum(b, 484, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqdata(b, 492, &[0; 36]);
    op(b, OpElse);
    range(b, 484, 8, PAYOUT_FLOOR, MAX);
    eqdata(b, 492, &[0, 0, OpData32]);
    eqdata(b, 527, &[OpCheckSig]);
    op(b, OpEndIf);
    // Output omission is independent of whether another owner's reserve remains.
    // The matched private mode0 relation proves all output bytes zero/full input.
    pl(b, 300, 1);
    data(b, &[0]);
    op(b, OpEqual);
    op(b, OpIf);
    eqn(b, OpTxPayloadLen, TERMINAL_PAYLOAD as i64);
    range(b, 484, 8, PAYOUT_FLOOR, MAX);
    eqdata(b, 268, &[0; 64]);
    eqdata(b, 332, &Sha256::digest([0u8; 528]));
    st(b, 40, 32);
    pl(b, 404, 32);
    op(b, OpEqualVerify);
    snum(b, 72);
    unum(b, 436, 4);
    op(b, OpNumEqualVerify);
    op(b, OpElse);
    pl(b, 300, 1);
    data(b, &[32]);
    op(b, OpEqual);
    op(b, OpIf);
    cm_mode(b, 32);
    op(b, OpElse);
    cm_mode(b, 2);
    op(b, OpEndIf);
    op(b, OpEndIf);
    // Only Rprime chooses continuation/output count. No admin or rollover path.
    unum(b, 476, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqdata(b, 300, &[0]);
    range(b, 484, 8, PAYOUT_FLOOR, MAX);
    eqn(b, OpTxOutputCount, 1);
    op(b, OpElse);
    range(b, 476, 8, NOTE_FLOOR, MAX);
    amount_bytes(b, OpTxOutputAmount, 0);
    pl(b, 476, 8);
    op(b, OpEqualVerify);
    successor(b, len, true);
    unum(b, 484, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqn(b, OpTxOutputCount, 1);
    op(b, OpElse);
    eqn(b, OpTxOutputCount, 2);
    num(b, 1);
    eqn(b, OpOutputAuthorizingInput, -1);
    op(b, OpEndIf);
    op(b, OpEndIf);
    snum(b, 108);
    num(b, 2);
    op(b, OpAdd);
    op(b, OpDup);
    num(b, 131071);
    op(b, OpLessThanOrEqual);
    verify(b);
    unum(b, 472, 4);
    op(b, OpNumEqualVerify);
    unum(b, 472, 4);
    unum(b, 436, 4);
    num(b, 2);
    op(b, OpMul);
    num(b, 1);
    op(b, OpAdd);
    op(b, OpLessThanOrEqual);
    verify(b);
    pl(b, 204, 32);
    pl(b, 236, 32);
    op(b, OpEqual);
    op(b, OpNot);
    verify(b);
    st(b, 76, 32);
    insert_nf(b, 204, 528, 0, None);
    insert_nf(b, 236, 1688, 1, None);
    pl(b, 440, 32);
    op(b, OpEqualVerify);
    unum(b, 484, 8);
    num(b, 0);
    op(b, OpGreaterThan);
    op(b, OpIf);
    private_payout_index(b);
    op(b, OpTxOutputAmount);
    unum(b, 484, 8);
    op(b, OpNumEqualVerify);
    private_payout_index(b);
    op(b, OpTxOutputSpk);
    pl(b, 492, 36);
    op(b, OpEqualVerify);
    op(b, OpEndIf);
    pl(b, 0, 528);
    op(b, OpSHA256);
    op(b, OpDup);
    num(b, 16);
    num(b, 32);
    op(b, OpSubstr);
    data(b, &[0; 16]);
    cat(b);
    op(b, OpSwap);
    num(b, 0);
    num(b, 16);
    op(b, OpSubstr);
    data(b, &[0; 16]);
    cat(b);
    num(b, 2);
    op(b, OpFromAltStack);
    pl(b, 300, 1);
    data(b, &[32]);
    op(b, OpEqual);
    op(b, OpIf);
    data(b, wide_vk);
    op(b, OpElse);
    data(b, compact_vk);
    op(b, OpEndIf);
    data(b, &[0x20]);
    op(b, OpZkPrecompile)
}

fn private_payout_index(b: &mut ScriptBuilder) {
    unum(b, 476, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf)
}

// W-only additions. The helpers above preserve the reviewed ADR58 private
// fallback, including mode0 with a remaining reserve. No old funded code changes.
pub const AGGREGATE_PAYLOAD: usize = 8108;
pub const RECORD_BYTES: usize = 4048;
pub const RECORD0: usize = 12;
pub const RECORD1: usize = RECORD0 + RECORD_BYTES;
pub const FINAL_STATE: usize = RECORD1 + 364;
pub const FINAL_RESERVE: usize = RECORD1 + 476;
pub const JOURNAL_BYTES: usize = 424;
pub const IMAGE_AT: usize = 184;
pub const KIND_AT: usize = 218;
pub const METADATA_PREFIX: usize = 227;

#[derive(Clone)]
pub struct Profile {
    pub wrapper_domain: [u8; 32],
    pub compact_vk: [u8; 328],
    pub child_template_sha256: [u8; 32],
}

impl Profile {
    pub fn selected() -> Result<Self> {
        // This shared source profile contains no outer image/selection. The
        // image is obtained only after guest compilation, then pinned into W.
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../proof/child-profile.json"
        ))?;
        if value["selected"] != true
            || value["classification"] != "TESTNET_REHEARSAL_ONLY_ADR0060"
            || value["trial_id"] != "68312927-f203-4317-9816-c47c020eed16"
            || value["owner_witness_or_funding_authority"] != false
            || value["unused_wide_virtual_key_policy"] != "UNSELECTED_WIDE_VIRTUAL_ONLY"
            || value["schema"] != "kpx5-public-virtual-settlement-child-profile/v1"
            || value["child_role"] != "compact2"
            || value["child_mode"] != 2
            || value["child_count"] != 2
            || value["journal_bytes"] != JOURNAL_BYTES
            || value["payload_bytes"] != AGGREGATE_PAYLOAD
        {
            return Err("PUBLIC_CHILD_PROFILE_UNSELECTED_OR_WRONG_SHAPE".into());
        }
        let decode = |name: &str| -> Result<Vec<u8>> {
            let text = value[name].as_str().ok_or("public profile bytes absent")?;
            if text.len() % 2 != 0
                || !text
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err("public profile canonical hex".into());
            }
            Ok(hex::decode(text)?)
        };
        let child: [u8; 32] = decode("child_domain_hex32")?
            .try_into()
            .map_err(|_| "child domain width")?;
        if child != DOMAIN {
            return Err("capacity fallback and guest child domains differ".into());
        }
        let wrapper_domain = decode("wrapper_domain_hex32")?
            .try_into()
            .map_err(|_| "wrapper domain width")?;
        if wrapper_domain == DOMAIN {
            return Err("wrapper/child instance domains must differ".into());
        }
        let compact_vk: [u8; 328] = decode("child_vk_hex328")?
            .try_into()
            .map_err(|_| "compact VK width")?;
        if Sha256::digest(compact_vk).as_slice() != decode("child_vk_sha256")? {
            return Err("selected compact VK identity".into());
        }
        let tail = decode("child_template_tail_hex")?;
        if tail.is_empty() || tail.len() + 114 > u16::MAX as usize
            || tail.windows(328).filter(|w| *w == compact_vk).count() != 1
            || tail.windows(328).filter(|w| *w == [0u8; 328]).count() != 1 {
            return Err("selected child template shape".into());
        }
        let _: [u8; 32] = decode("child_parameter_manifest_sha256")?
            .try_into()
            .map_err(|_| "parameter identity width")?;
        Ok(Self {
            wrapper_domain,
            compact_vk,
            child_template_sha256: Sha256::digest(tail).into(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Receipt,
    HashOracle,
}
impl Kind {
    pub fn marker(self) -> &'static [u8; 8] {
        match self {
            Self::Receipt => b"KPX5WS01",
            Self::HashOracle => b"KPX5WO01",
        }
    }
    pub fn from_marker(raw: &[u8]) -> Result<Self> {
        if raw == b"KPX5WS01" {
            Ok(Self::Receipt)
        } else if raw == b"KPX5WO01" {
            Ok(Self::HashOracle)
        } else {
            Err("wrapper template marker".into())
        }
    }
}

fn payload_equal(b: &mut ScriptBuilder, first: usize, second: usize, length: usize) {
    pl(b, first, length);
    pl(b, second, length);
    op(b, OpEqualVerify);
}
fn point_bytes(b: &mut ScriptBuilder) {
    num(b, 0);
    op(b, OpOutpointTxId);
    num(b, 0);
    op(b, OpOutpointIndex);
    num(b, 8);
    op(b, OpNum2Bin);
    num(b, 0);
    num(b, 4);
    op(b, OpSubstr);
    cat(b);
}
fn actual_fee(b: &mut ScriptBuilder) {
    native_amount(b, OpTxInputAmount, 0);
    native_amount(b, OpTxOutputAmount, 0);
    op(b, OpSub);
}
fn wrapper_successor(b: &mut ScriptBuilder, len: usize) {
    ss(b, REDEEM_START, 2);
    pl(b, FINAL_STATE, 112);
    cat(b);
    ss(b, REDEEM_START + 114, len - 114);
    cat(b);
    op(b, OpBlake2b);
    data(b, &[0, 0, OpBlake2b, OpData32]);
    op(b, OpSwap);
    cat(b);
    data(b, &[OpEqual]);
    cat(b);
    num(b, 0);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify);
}

/// SHA256(KPX5FB01 projection), reconstructed entirely from introspection.
/// Counts/header/SPK widths/covenant absence are independently checked first.
/// The expected journal/hash and outer proof are never part of this projection.
fn projection_hash(b: &mut ScriptBuilder) {
    data(b, b"KPX5FB01\x01\x00\x01\x00");
    point_bytes(b);
    cat(b);
    num(b, 0);
    op(b, OpTxInputSeq);
    cat(b);
    amount_bytes(b, OpTxInputAmount, 0);
    cat(b);
    data(b, &37u16.to_le_bytes());
    cat(b);
    num(b, 0);
    op(b, OpTxInputSpk);
    cat(b);
    data(b, &1u16.to_le_bytes());
    cat(b);
    amount_bytes(b, OpTxOutputAmount, 0);
    cat(b);
    data(b, &37u16.to_le_bytes());
    cat(b);
    num(b, 0);
    op(b, OpTxOutputSpk);
    cat(b);
    data(b, &[0]);
    cat(b); // output covenant absent, checked via authorizing index.
    data(b, &[0; 8]);
    cat(b); // actual locktime is independently fixed zero.
    op(b, OpTxSubnetId);
    cat(b);
    data(b, &[0; 8]);
    cat(b); // actual gas is independently fixed zero.
    data(b, &(AGGREGATE_PAYLOAD as u32).to_le_bytes());
    cat(b);
    pl(b, 0, AGGREGATE_PAYLOAD);
    cat(b);
    op(b, OpSHA256);
}

/// The SAME builder is used by real W and the distinct unfunded hash oracle.
fn journal_hash(b: &mut ScriptBuilder, p: &Profile) {
    data(b, b"KPX5VS01\x01\x00");
    data(b, &p.wrapper_domain);
    cat(b);
    data(b, &DOMAIN);
    cat(b);
    data(b, &2u16.to_le_bytes());
    cat(b);
    point_bytes(b);
    cat(b);
    st(b, 0, 112);
    cat(b);
    amount_bytes(b, OpTxInputAmount, 0);
    cat(b);
    pl(b, FINAL_STATE, 112);
    cat(b);
    amount_bytes(b, OpTxOutputAmount, 0);
    cat(b);
    actual_fee(b);
    num(b, 8);
    op(b, OpNum2Bin);
    cat(b);
    pl(b, 12, 2 * RECORD_BYTES);
    op(b, OpSHA256);
    cat(b);
    projection_hash(b);
    cat(b);
    op(b, OpSHA256);
}

// Adapted field-for-field from the already checked vProgs/public-state-native
// successful assumption-free receipt claim. ISC provenance is retained in NOTICE.
fn receipt_claim(b: &mut ScriptBuilder, c: &crate::receipt::Constants) {
    op(b, OpToAltStack);
    data(b, &c.output_tag);
    op(b, OpSwap);
    cat(b);
    data(b, &[0; 32]);
    cat(b);
    data(b, &2u16.to_le_bytes());
    cat(b);
    op(b, OpSHA256);
    data(b, &c.claim_tag);
    data(b, &[0; 32]);
    cat(b);
    op(b, OpFromAltStack);
    cat(b);
    data(b, &c.post);
    cat(b);
    op(b, OpSwap);
    cat(b);
    data(b, &[0, 0, 0, 0, 0, 0, 0, 0, 4, 0]);
    cat(b);
    op(b, OpSHA256);
}
fn split_claim(b: &mut ScriptBuilder) {
    op(b, OpSize);
    num(b, 2);
    op(b, OpDiv);
    op(b, Op2Dup);
    num(b, 0);
    op(b, OpSwap);
    op(b, OpSubstr);
    op(b, OpRot);
    op(b, OpRot);
    op(b, OpDup);
    num(b, 2);
    op(b, OpMul);
    op(b, OpSubstr);
}
fn verify_outer(b: &mut ScriptBuilder, image: &[u8; 32], c: &crate::receipt::Constants) {
    // [proof128,Jhash] -> exact successful receipt claim -> standard five inputs.
    data(b, image);
    op(b, OpRot);
    op(b, OpToAltStack);
    receipt_claim(b, c);
    op(b, OpToAltStack);
    data(b, &c.id);
    op(b, OpFromAltStack);
    split_claim(b);
    data(b, &[0; 16]);
    cat(b);
    op(b, OpSwap);
    data(b, &[0; 16]);
    cat(b);
    data(b, &c.root[1]);
    data(b, &c.root[0]);
    num(b, 5);
    op(b, OpFromAltStack);
    data(b, &c.vk);
    data(b, &[0x20]);
    op(b, OpZkPrecompile);
    verify(b);
}

fn aggregate_branch(
    b: &mut ScriptBuilder,
    p: &Profile,
    image: &[u8; 32],
    c: &crate::receipt::Constants,
    len: usize,
    kind: Kind,
) {
    data(b, &[0; 65]);
    op(b, OpEqualVerify);
    eqn(b, OpTxOutputCount, 1);
    eqn(b, OpTxPayloadLen, AGGREGATE_PAYLOAD as i64);
    num(b, 0);
    eqn(b, OpTxOutputSpkLen, 37);
    eqdata(b, 0, b"KPX5VP01\x01\x00\x02\x00");
    for base in [RECORD0, RECORD1] {
        eqdata(b, base, AUTH_MAGIC);
        eqdata(b, base + 8, &DOMAIN);
        eqdata(b, base + 300, &[2]);
        eqdata(b, base + 301, &[0; 3]);
        eqdata(b, base + 308, &[0; 24]);
        eqdata(b, base + 484, &[0; 44]);
        range(b, base + 188, 8, NOTE_FLOOR, MAX);
        range(b, base + 196, 8, 1, MAX);
        range(b, base + 476, 8, NOTE_FLOOR, MAX);
    }
    st(b, 0, 112);
    pl(b, RECORD0 + 76, 112);
    op(b, OpEqualVerify);
    point_bytes(b);
    pl(b, RECORD0 + 40, 36);
    op(b, OpEqualVerify);
    amount_bytes(b, OpTxInputAmount, 0);
    pl(b, RECORD0 + 188, 8);
    op(b, OpEqualVerify);
    payload_equal(b, RECORD0 + 364, RECORD1 + 76, 112);
    payload_equal(b, RECORD0 + 476, RECORD1 + 188, 8);
    amount_bytes(b, OpTxOutputAmount, 0);
    pl(b, FINAL_RESERVE, 8);
    op(b, OpEqualVerify);
    for code in [OpTxInputAmount, OpTxOutputAmount] {
        native_amount(b, code, 0);
        num(b, NOTE_FLOOR);
        op(b, OpGreaterThanOrEqual);
        verify(b);
        native_amount(b, code, 0);
        num(b, MAX);
        op(b, OpLessThanOrEqual);
        verify(b);
    }
    actual_fee(b);
    unum(b, RECORD0 + 196, 8);
    unum(b, RECORD1 + 196, 8);
    op(b, OpAdd);
    op(b, OpNumEqualVerify);
    wrapper_successor(b, len);
    journal_hash(b, p);
    op(b, OpFromAltStack);
    match kind {
        Kind::Receipt => {
            op(b, OpSwap);
            verify_outer(b, image, c);
        }
        Kind::HashOracle => {
            // Diagnostic expected hash is in SS, not its own SPK/projection.
            // This distinct program can never spend an actual W output.
            ss(b, 100, 96);
            data(b, &[0; 96]);
            op(b, OpEqualVerify);
            num(b, 0);
            num(b, 32);
            op(b, OpSubstr);
            op(b, OpEqualVerify);
        }
    }
    op(b, OpTrue);
}

fn wrapper_build(
    p: &Profile,
    state: &[u8; 112],
    image: &[u8; 32],
    c: &crate::receipt::Constants,
    len: usize,
    kind: Kind,
) -> Vec<u8> {
    let mut b = ScriptBuilder::new();
    data(&mut b, state);
    op(&mut b, OpDrop);
    data(&mut b, &p.wrapper_domain);
    op(&mut b, OpDrop);
    data(&mut b, &p.child_template_sha256);
    op(&mut b, OpDrop);
    data(&mut b, image);
    op(&mut b, OpDrop);
    data(&mut b, kind.marker());
    op(&mut b, OpDrop);
    assert_eq!(b.script().len(), METADATA_PREFIX);
    eqn(&mut b, OpDepth, 2);
    eqn(&mut b, OpSize, 128);
    op(&mut b, OpToAltStack);
    eqn(&mut b, OpSize, 65);
    for (code, value) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxInputCount, 1),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
    ] {
        eqn(&mut b, code, value);
    }
    op(&mut b, OpTxSubnetId);
    data(&mut b, &[0; 20]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    op(&mut b, OpTxInputSeq);
    data(&mut b, &u64::MAX.to_le_bytes());
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputIsCoinbase, 0);
    // Opcode uses ZERO as None sentinel. Canonical W output0 always has no
    // covenant; body oracle also requires exactNone. Reachability is external.
    num(&mut b, 0);
    op(&mut b, OpInputCovenantId);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqn(&mut b, OpOutputAuthorizingInput, -1);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputSpkLen, 37);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputScriptSigLen, (REDEEM_START + len) as i64);
    ss(&mut b, 0, 1);
    data(&mut b, &[65]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 66, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 196, 3);
    data(&mut b, &[OpPushData2, (len & 255) as u8, (len >> 8) as u8]);
    op(&mut b, OpEqualVerify);
    st(&mut b, 0, 8);
    data(&mut b, STATE_MAGIC);
    op(&mut b, OpEqualVerify);
    st(&mut b, 8, 32);
    data(&mut b, &DOMAIN);
    op(&mut b, OpEqualVerify);
    state_count_bounds(&mut b);
    pl(&mut b, 0, 8);
    data(&mut b, b"KPX5VP01");
    op(&mut b, OpEqual);
    op(&mut b, OpIf);
    aggregate_branch(&mut b, p, image, c, len, kind);
    op(&mut b, OpElse);
    eqdata(&mut b, 0, AUTH_MAGIC);
    pl(&mut b, 300, 1);
    data(&mut b, &[0]);
    op(&mut b, OpEqual);
    pl(&mut b, 300, 1);
    data(&mut b, &[2]);
    op(&mut b, OpEqual);
    op(&mut b, OpBoolOr);
    verify(&mut b);
    // Both operands deliberately identical: mode32 is forbidden above. Keep
    // the reviewed compact fallback body unchanged rather than rewriting it.
    private_branch(&mut b, len, &p.compact_vk, &p.compact_vk);
    op(&mut b, OpEndIf);
    b.drain()
}

pub fn wrapper_redeem(
    p: &Profile,
    state: &[u8; 112],
    image: &[u8; 32],
    c: &crate::receipt::Constants,
    kind: Kind,
) -> Result<Vec<u8>> {
    if &state[..8] != STATE_MAGIC || state[8..40] != DOMAIN {
        return Err("wrapper child state identity".into());
    }
    let n = u32::from_le_bytes(state[72..76].try_into()?);
    let m = u32::from_le_bytes(state[108..112].try_into()?);
    if n == 0 || n > 65535 || m == 0 || m > 131071 || u64::from(m) > 2 * u64::from(n) + 1 {
        return Err("wrapper state count bounds".into());
    }
    let mut len = 16384;
    for _ in 0..8 {
        let result = wrapper_build(p, state, image, c, len, kind);
        if result.len() == len {
            return Ok(result);
        }
        len = result.len();
        if !(METADATA_PREFIX..=u16::MAX as usize).contains(&len) {
            return Err("wrapper PUSHDATA2 length".into());
        }
    }
    Err("wrapper selflength did not converge".into())
}

pub fn witness(proof: &[u8; 128], redeem: &[u8]) -> Result<Vec<u8>> {
    let mut builder = ScriptBuilder::new();
    builder
        .add_data(&[0; 65])?
        .add_data(proof)?
        .add_data(redeem)?;
    let result = builder.drain();
    if result.len() != REDEEM_START + redeem.len() {
        return Err("canonical wrapper witness".into());
    }
    Ok(result)
}
