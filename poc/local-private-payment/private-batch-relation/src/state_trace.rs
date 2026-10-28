//! Private construction of the public indexed-NF/CM transition witnesses.
//!
//! This ports the algorithms in owner-private-lifecycle/wallet/trees.py to the
//! authenticated trace builder. Accepted old leaves are public. New NFs and CMs
//! remain bit LCs throughout predecessor selection, updates, paths and hashes.
//! No host branch, memory address or diagnostic depends on a secret value.
//!
//! The caller must authenticate the accepted history/head and execute every
//! emitted assertion before any proof-related opening. Recomputed old roots
//! bind the supplied leaf prefix to Context; they do not establish consensus,
//! currentness or independent data availability. R0 transition verification
//! and the native actual-effects checks remain mandatory.
use crate::{Context, H, OUTPUTS, OWNERS, trace::{self, Lc, TraceBuilder}};
use ark_bn254::Fr;
use ark_ff::Field;
use sha2::{Digest, Sha256};

const NF_DEPTH: usize = 17;
const CM_DEPTH: usize = 16;
const NF_NODE: &[u8; 8] = b"KPX1NFN\0";
const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
const NF_LEAF: &[u8; 8] = b"KPX1NFL\0";

/// Byte order is canonical wire order; each byte contains eight LE bits.
pub type SecretBytes = Vec<Vec<Lc>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicNullifierLeaf {
    pub value: H,
    pub successor: H,
    pub successor_index: u32,
}

/// Full occupied prefixes reconstructed from accepted PUBLIC history only.
#[derive(Clone, Debug)]
pub struct PublicHistory {
    pub commitments: Vec<H>,
    pub nullifiers: Vec<PublicNullifierLeaf>,
}

#[derive(Debug)]
pub enum Error {
    PublicHistory(&'static str),
    Shape(&'static str),
    Trace(trace::Error),
}
impl From<trace::Error> for Error { fn from(value: trace::Error) -> Self { Self::Trace(value) } }
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicHistory(code) | Self::Shape(code) => f.write_str(code),
            Self::Trace(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct SecretNullifierWitness {
    pub predecessor_index: SecretBytes,
    pub predecessor: SecretBytes,
    pub successor: SecretBytes,
    pub successor_index: SecretBytes,
    pub predecessor_path: Vec<SecretBytes>,
    pub append_path: Vec<SecretBytes>,
}
impl SecretNullifierWitness {
    pub fn bytes(&self) -> SecretBytes {
        let mut bytes = self.predecessor_index.clone();
        bytes.extend(self.predecessor.clone());
        bytes.extend(self.successor.clone());
        bytes.extend(self.successor_index.clone());
        for hash in self.predecessor_path.iter().chain(&self.append_path) {
            bytes.extend(hash.clone());
        }
        debug_assert_eq!(bytes.len(), 1160);
        bytes
    }
}

#[derive(Clone)]
pub struct PrivateStateTrace {
    pub new_cm_root: SecretBytes,
    pub new_nf_root: SecretBytes,
    pub new_cm_count: u32,
    pub new_nf_count: u32,
    pub nf_witnesses: [SecretNullifierWitness; OWNERS],
    pub cm_paths: [Vec<SecretBytes>; OUTPUTS],
}

#[derive(Clone)]
struct SecretLeaf {
    value: SecretBytes,
    successor: SecretBytes,
    successor_index: SecretBytes,
}

fn sha(parts: &[&[u8]]) -> H {
    let mut hasher = Sha256::new();
    for part in parts { hasher.update(part); }
    hasher.finalize().into()
}
fn public_leaf(leaf: &PublicNullifierLeaf) -> H {
    sha(&[NF_LEAF, &leaf.value, &leaf.successor, &leaf.successor_index.to_le_bytes()])
}
fn public_defaults(depth: usize, tag: &[u8], empty: H) -> Vec<H> {
    let mut defaults = vec![empty];
    for level in 0..depth { defaults.push(sha(&[tag, &defaults[level], &defaults[level]])); }
    defaults
}
fn public_levels(leaves: &[H], depth: usize, tag: &[u8], defaults: &[H]) -> Vec<Vec<H>> {
    let mut levels = vec![leaves.to_vec()];
    for level in 0..depth {
        let mut next = Vec::with_capacity(levels[level].len().div_ceil(2));
        for chunk in levels[level].chunks(2) {
            let right = chunk.get(1).unwrap_or(&defaults[level]);
            next.push(sha(&[tag, &chunk[0], right]));
        }
        levels.push(next);
    }
    levels
}
fn root_or_default(levels: &[Vec<H>], defaults: &[H]) -> H {
    levels.last().and_then(|nodes| nodes.first()).copied().unwrap_or(*defaults.last().unwrap())
}
impl PublicHistory {
    /// Only public structure/root checks happen on the host. Secret transition
    /// checks are emitted as trace assertions, with no per-NF public verdict.
    pub fn validate(&self, context: &Context) -> Result<()> {
        let cm = self.commitments.len();
        let nf = self.nullifiers.len();
        if cm != context.old_cm_count as usize || nf != context.old_nf_count as usize {
            return Err(Error::PublicHistory("state-history-count"));
        }
        if cm == 0 || cm > (1 << CM_DEPTH) - OUTPUTS || nf == 0 || nf > (1 << NF_DEPTH) - OWNERS {
            return Err(Error::PublicHistory("state-history-capacity"));
        }
        let mut ordered = self.nullifiers.iter().enumerate().collect::<Vec<_>>();
        ordered.sort_by(|(_, a), (_, b)| a.value.iter().rev().cmp(b.value.iter().rev()));
        if ordered[0].0 != 0 || ordered[0].1.value != [0; 32]
            || ordered.windows(2).any(|pair| pair[0].1.value == pair[1].1.value)
        {
            return Err(Error::PublicHistory("state-history-nullifiers"));
        }
        for (at, (_, entry)) in ordered.iter().enumerate() {
            let (next_index, next_value) = ordered.get(at + 1)
                .map(|(index, next)| (*index as u32, next.value))
                .unwrap_or((0, [0; 32]));
            if entry.successor != next_value || entry.successor_index != next_index {
                return Err(Error::PublicHistory("state-history-linked-list"));
            }
        }
        let cm_defaults = public_defaults(CM_DEPTH, CM_NODE, sha(&[b"KPX1CME\0"]));
        let cm_levels = public_levels(&self.commitments, CM_DEPTH, CM_NODE, &cm_defaults);
        let nf_defaults = public_defaults(NF_DEPTH, NF_NODE, sha(&[b"KPX1NFE\0"]));
        let nf_leaves = self.nullifiers.iter().map(public_leaf).collect::<Vec<_>>();
        let nf_levels = public_levels(&nf_leaves, NF_DEPTH, NF_NODE, &nf_defaults);
        if root_or_default(&cm_levels, &cm_defaults) != context.old_cm_root {
            return Err(Error::PublicHistory("state-history-cm-root"));
        }
        if root_or_default(&nf_levels, &nf_defaults) != context.old_nf_root {
            return Err(Error::PublicHistory("state-history-nf-root"));
        }
        Ok(())
    }
}

fn constants(builder: &TraceBuilder, bytes: &[u8]) -> SecretBytes {
    bytes.iter().map(|byte| (0..8).map(|bit| builder.bit_constant((byte >> bit) & 1 != 0)).collect()).collect()
}
fn flat(bytes: &SecretBytes) -> Vec<Lc> { bytes.iter().flatten().cloned().collect() }
fn shape(bytes: &SecretBytes, length: usize) -> Result<()> {
    if bytes.len() != length || bytes.iter().any(|byte| byte.len() != 8) {
        return Err(Error::Shape("state-secret-byte-shape"));
    }
    Ok(())
}
fn assert_true(builder: &mut TraceBuilder, bit: &Lc) -> Result<()> {
    builder.assert_zero(builder.bit_not(bit))?; Ok(())
}
fn assert_equal(builder: &mut TraceBuilder, a: &SecretBytes, b: &SecretBytes) -> Result<()> {
    shape(a, b.len())?;
    for (x, y) in a.iter().flatten().zip(b.iter().flatten()) { builder.assert_zero(x.minus(y))?; }
    Ok(())
}
fn ensure_bits(builder: &mut TraceBuilder, bytes: &SecretBytes) -> Result<()> {
    for bit in bytes.iter().flatten() {
        let check = builder.muladd(bit.clone(), bit.minus(&Lc::constant(Fr::ONE)), Lc::zero())?;
        builder.assert_zero(check)?;
    }
    Ok(())
}
fn equal(builder: &mut TraceBuilder, a: &SecretBytes, b: &SecretBytes) -> Result<Lc> {
    Ok(builder.eq_bits(&flat(a), &flat(b))?)
}
fn less(builder: &mut TraceBuilder, a: &SecretBytes, b: &SecretBytes) -> Result<Lc> {
    Ok(builder.lt_bits(&flat(a), &flat(b))?)
}
fn select_bytes(builder: &mut TraceBuilder, bit: &Lc, yes: &SecretBytes, no: &SecretBytes) -> Result<SecretBytes> {
    if yes.len() != no.len() { return Err(Error::Shape("state-select-shape")); }
    yes.iter().zip(no).map(|(a,b)| {
        if a.len() != 8 || b.len() != 8 { return Err(Error::Shape("state-select-byte-shape")); }
        a.iter().zip(b).map(|(a,b)| builder.select(bit,a,b).map_err(Error::from)).collect()
    }).collect()
}
fn select_one(builder: &mut TraceBuilder, flags: &[Lc], choices: &[SecretBytes]) -> Result<SecretBytes> {
    if flags.is_empty() || flags.len() != choices.len() { return Err(Error::Shape("state-lookup-shape")); }
    let mut result = constants(builder, &vec![0; choices[0].len()]);
    for (flag, choice) in flags.iter().zip(choices) { result = select_bytes(builder, flag, choice, &result)?; }
    Ok(result)
}
fn hash(builder: &mut TraceBuilder, tag: &[u8], parts: &[&SecretBytes]) -> Result<SecretBytes> {
    let mut message = constants(builder, tag);
    for part in parts { message.extend((*part).clone()); }
    let result = builder.sha256_bytes(&message)?;
    shape(&result, 32)?;
    Ok(result)
}
fn secret_leaf(builder: &mut TraceBuilder, leaf: &SecretLeaf) -> Result<SecretBytes> {
    hash(builder, NF_LEAF, &[&leaf.value, &leaf.successor, &leaf.successor_index])
}
fn private_levels(builder: &mut TraceBuilder, leaves: &[SecretBytes], depth: usize, tag: &[u8], defaults: &[SecretBytes]) -> Result<Vec<Vec<SecretBytes>>> {
    if leaves.is_empty() { return Err(Error::Shape("state-empty-prefix")); }
    let mut levels = vec![leaves.to_vec()];
    for level in 0..depth {
        let mut next = Vec::with_capacity(levels[level].len().div_ceil(2));
        for chunk in levels[level].chunks(2) {
            let right = chunk.get(1).unwrap_or(&defaults[level]);
            next.push(hash(builder, tag, &[&chunk[0], right])?);
        }
        levels.push(next);
    }
    Ok(levels)
}
fn path_at(levels: &[Vec<SecretBytes>], defaults: &[SecretBytes], index: usize, depth: usize) -> Vec<SecretBytes> {
    (0..depth).map(|level| levels[level].get((index >> level) ^ 1).unwrap_or(&defaults[level]).clone()).collect()
}
fn private_path(builder: &mut TraceBuilder, levels: &[Vec<SecretBytes>], defaults: &[SecretBytes], flags: &[Lc]) -> Result<Vec<SecretBytes>> {
    let mut path = Vec::with_capacity(NF_DEPTH);
    for level in 0..NF_DEPTH {
        let choices = (0..flags.len()).map(|index| levels[level].get((index >> level) ^ 1).unwrap_or(&defaults[level]).clone()).collect::<Vec<_>>();
        path.push(select_one(builder, flags, &choices)?);
    }
    Ok(path)
}
fn fold_public_index(builder: &mut TraceBuilder, leaf: &SecretBytes, index: usize, path: &[SecretBytes], tag: &[u8]) -> Result<SecretBytes> {
    let mut root = leaf.clone();
    for (level, sibling) in path.iter().enumerate() {
        root = if (index >> level) & 1 == 0 {
            hash(builder, tag, &[&root, sibling])?
        } else { hash(builder, tag, &[sibling, &root])? };
    }
    Ok(root)
}

/// Emit the private tree transition. All loops/addresses depend only on public
/// history lengths and fixed three/six shapes. Inputs are final sorted NF rows
/// and final independently permuted output CMs, already secret-shared as bits.
pub fn build_state_trace(
    builder: &mut TraceBuilder,
    context: &Context,
    history: &PublicHistory,
    nullifiers: &[SecretBytes; OWNERS],
    commitments: &[SecretBytes; OUTPUTS],
) -> Result<PrivateStateTrace> {
    history.validate(context)?;
    for value in nullifiers.iter().chain(commitments) { shape(value, 32)?; ensure_bits(builder, value)?; }
    let zero = constants(builder, &[0; 32]);
    for (i, nf) in nullifiers.iter().enumerate() {
        let is_zero = equal(builder, nf, &zero)?; builder.assert_zero(is_zero)?;
        if i > 0 { let ordered = less(builder, &nullifiers[i-1], nf)?; assert_true(builder, &ordered)?; }
    }
    let nf_defaults = public_defaults(NF_DEPTH, NF_NODE, sha(&[b"KPX1NFE\0"]));
    let nf_defaults = nf_defaults.iter().map(|h| constants(builder,h)).collect::<Vec<_>>();
    let mut entries = history.nullifiers.iter().map(|leaf| SecretLeaf {
        value: constants(builder,&leaf.value), successor: constants(builder,&leaf.successor),
        successor_index: constants(builder,&leaf.successor_index.to_le_bytes()),
    }).collect::<Vec<_>>();
    let old_nf_leaves = history.nullifiers.iter().map(public_leaf).collect::<Vec<_>>();
    let public_nf_defaults = public_defaults(NF_DEPTH, NF_NODE, sha(&[b"KPX1NFE\0"]));
    let public_nf_levels = public_levels(&old_nf_leaves,NF_DEPTH,NF_NODE,&public_nf_defaults);
    let mut levels = public_nf_levels.iter().map(|level| level.iter().map(|node| constants(builder,node)).collect()).collect::<Vec<Vec<_>>>();
    let mut witnesses = Vec::with_capacity(OWNERS);
    for nf in nullifiers {
        let count = entries.len(); // public append position, never secret indexing.
        let mut flags = Vec::with_capacity(count);
        for leaf in &entries {
            let after = less(builder,&leaf.value,nf)?;
            let before = less(builder,nf,&leaf.successor)?;
            let terminal = equal(builder,&leaf.successor,&zero)?;
            let upper = builder.bit_or(&before,&terminal)?;
            flags.push(builder.bit_and(&after,&upper)?);
        }
        let mut any = Lc::zero();
        for flag in &flags {
            let duplicate = builder.bit_and(&any,flag)?; builder.assert_zero(duplicate)?;
            any = builder.bit_or(&any,flag)?;
        }
        assert_true(builder,&any)?;
        let indices = (0..count).map(|i| constants(builder,&(i as u32).to_le_bytes())).collect::<Vec<_>>();
        let predecessor_index = select_one(builder,&flags,&indices)?;
        let predecessor = select_one(builder,&flags,&entries.iter().map(|e|e.value.clone()).collect::<Vec<_>>())?;
        let successor = select_one(builder,&flags,&entries.iter().map(|e|e.successor.clone()).collect::<Vec<_>>())?;
        let successor_index = select_one(builder,&flags,&entries.iter().map(|e|e.successor_index.clone()).collect::<Vec<_>>())?;
        let predecessor_path = private_path(builder,&levels,&nf_defaults,&flags)?;
        let new_index = constants(builder,&(count as u32).to_le_bytes());
        for (entry,flag) in entries.iter_mut().zip(&flags) {
            entry.successor = select_bytes(builder,flag,nf,&entry.successor)?;
            entry.successor_index = select_bytes(builder,flag,&new_index,&entry.successor_index)?;
        }
        let middle_leaves = entries.iter().map(|entry|secret_leaf(builder,entry)).collect::<Result<Vec<_>>>()?;
        let middle = private_levels(builder,&middle_leaves,NF_DEPTH,NF_NODE,&nf_defaults)?;
        let append_path = path_at(&middle,&nf_defaults,count,NF_DEPTH);
        let empty_root = fold_public_index(builder,&nf_defaults[0],count,&append_path,NF_NODE)?;
        assert_equal(builder,&empty_root,&middle[NF_DEPTH][0])?;
        entries.push(SecretLeaf { value:nf.clone(), successor:successor.clone(), successor_index:successor_index.clone() });
        let leaves = entries.iter().map(|entry|secret_leaf(builder,entry)).collect::<Result<Vec<_>>>()?;
        levels = private_levels(builder,&leaves,NF_DEPTH,NF_NODE,&nf_defaults)?;
        witnesses.push(SecretNullifierWitness { predecessor_index, predecessor, successor, successor_index, predecessor_path, append_path });
    }
    let new_nf_root = levels[NF_DEPTH][0].clone();

    let empty_cm = sha(&[b"KPX1CME\0"]);
    let cm_defaults = public_defaults(CM_DEPTH,CM_NODE,empty_cm);
    let old_cm_levels = public_levels(&history.commitments,CM_DEPTH,CM_NODE,&cm_defaults);
    let mut frontier = (0..CM_DEPTH).map(|level| {
        let old_count = history.commitments.len();
        let index = (old_count >> level).saturating_sub(1);
        constants(builder,old_cm_levels[level].get(index).unwrap_or(&cm_defaults[level]))
    }).collect::<Vec<_>>();
    let cm_defaults = cm_defaults.iter().map(|h|constants(builder,h)).collect::<Vec<_>>();
    let mut cm_root = constants(builder,&context.old_cm_root);
    let mut paths = Vec::with_capacity(OUTPUTS);
    let mut prior_cms = history.commitments.iter().map(|h|constants(builder,h)).collect::<Vec<_>>();
    for (offset,cm) in commitments.iter().enumerate() {
        for forbidden in prior_cms.iter().chain([&zero,&cm_defaults[0]]) {
            let reused = equal(builder,cm,forbidden)?; builder.assert_zero(reused)?;
        }
        let index = history.commitments.len()+offset;
        let path = (0..CM_DEPTH).map(|level| {
            if (index >> level) & 1 == 0 { cm_defaults[level].clone() } else { frontier[level].clone() }
        }).collect::<Vec<_>>();
        let before = fold_public_index(builder,&cm_defaults[0],index,&path,CM_NODE)?;
        assert_equal(builder,&before,&cm_root)?;
        let mut node = cm.clone();
        for (level,sibling) in path.iter().enumerate() {
            if (index >> level) & 1 == 0 {
                frontier[level] = node.clone();
                node = hash(builder,CM_NODE,&[&node,sibling])?;
            } else { node = hash(builder,CM_NODE,&[sibling,&node])?; }
        }
        cm_root = node; paths.push(path); prior_cms.push(cm.clone());
    }
    Ok(PrivateStateTrace {
        new_cm_root:cm_root, new_nf_root,
        new_cm_count:context.old_cm_count+OUTPUTS as u32,
        new_nf_count:context.old_nf_count+OWNERS as u32,
        nf_witnesses:witnesses.try_into().map_err(|_|Error::Shape("state-witness-count"))?,
        cm_paths:paths.try_into().map_err(|_|Error::Shape("state-path-count"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;
    use crate::{Profile, trace::Error as TraceError};
    use std::{collections::BTreeMap, io::Write, path::Path, process::{Command, Stdio}};

    fn number(value: u64) -> H {
        let mut hash = [0; 32]; hash[..8].copy_from_slice(&value.to_le_bytes()); hash
    }
    fn commitment(label: u64) -> H { sha(&[b"PUBLIC-STATE-TRACE-FIXTURE", &label.to_le_bytes()]) }
    fn fixture(old_values: &[H], cm_count: usize) -> (Context,PublicHistory) {
        let mut values = vec![[0; 32]]; values.extend(old_values);
        let mut indexed = values.iter().copied().enumerate().collect::<Vec<_>>();
        indexed.sort_by(|(_,a),(_,b)|a.iter().rev().cmp(b.iter().rev()));
        let mut leaves = vec![PublicNullifierLeaf { value:[0;32],successor:[0;32],successor_index:0 };values.len()];
        for (at,(index,value)) in indexed.iter().enumerate() {
            let (next_i,next) = indexed.get(at+1).copied().unwrap_or((0,[0;32]));
            leaves[*index] = PublicNullifierLeaf { value:*value,successor:next,successor_index:next_i as u32 };
        }
        let history = PublicHistory { commitments:(0..cm_count).map(|i|commitment(i as u64)).collect(), nullifiers:leaves };
        let cm_defaults = public_defaults(CM_DEPTH,CM_NODE,sha(&[b"KPX1CME\0"]));
        let cm_levels = public_levels(&history.commitments,CM_DEPTH,CM_NODE,&cm_defaults);
        let nf_defaults = public_defaults(NF_DEPTH,NF_NODE,sha(&[b"KPX1NFE\0"]));
        let nf_levels = public_levels(&history.nullifiers.iter().map(public_leaf).collect::<Vec<_>>(),NF_DEPTH,NF_NODE,&nf_defaults);
        let context = Context {
            profile:Profile {chain_genesis:[1;32],pool_lineage:[2;32],wallet_profile:[3;32],domain:[4;32],service_policy:[5;32]},
            reserve_outpoint:[6;36],old_cm_root:root_or_default(&cm_levels,&cm_defaults),old_nf_root:root_or_default(&nf_levels,&nf_defaults),
            old_cm_count:cm_count as u32,old_nf_count:history.nullifiers.len() as u32,old_reserve:1_000_000_000,
        };
        (context,history)
    }
    fn decode(bytes: &SecretBytes, values: &[Fr]) -> Vec<u8> {
        bytes.iter().map(|byte| {
            let mut result = 0;
            for (i,lc) in byte.iter().enumerate() {
                let bit = lc.0.iter().fold(Fr::ZERO,|sum,(coefficient,index)|sum+*coefficient*values[*index]);
                assert!(bit==Fr::ZERO || bit==Fr::ONE);
                if bit==Fr::ONE {result|=1<<i;}
            }
            result
        }).collect()
    }
    fn serialize(result: &PrivateStateTrace, values: &[Fr]) -> Vec<u8> {
        let mut bytes = decode(&result.new_nf_root,values);
        bytes.extend(decode(&result.new_cm_root,values));
        bytes.extend(result.new_nf_count.to_le_bytes()); bytes.extend(result.new_cm_count.to_le_bytes());
        for witness in &result.nf_witnesses {bytes.extend(decode(&witness.bytes(),values));}
        for path in &result.cm_paths {for hash in path {bytes.extend(decode(hash,values));}}
        bytes
    }
    fn serialize_borrowed(result:&PrivateStateTrace,values:&[Option<Fr>])->Vec<u8> {
        // Output decoding only; operation semantics stay in the shared oracle.
        let decode=|bytes:&SecretBytes|->Vec<u8>{bytes.iter().map(|byte|{
            let mut result=0;
            for (at,lc) in byte.iter().enumerate() {
                let bit=lc.0.iter().fold(Fr::ZERO,|sum,(c,i)|sum+*c*values[*i].expect("assigned public fixture output"));
                assert!(bit==Fr::ZERO || bit==Fr::ONE);
                if bit==Fr::ONE {result|=1<<at;}
            }
            result
        }).collect()};
        let mut bytes=decode(&result.new_nf_root);bytes.extend(decode(&result.new_cm_root));
        bytes.extend(result.new_nf_count.to_le_bytes());bytes.extend(result.new_cm_count.to_le_bytes());
        for witness in &result.nf_witnesses {bytes.extend(decode(&witness.bytes()));}
        for path in &result.cm_paths {for hash in path {bytes.extend(decode(hash));}}
        bytes
    }
    fn legacy_public_oracle(history: &PublicHistory, nfs: &[H;OWNERS], cms: &[H;OUTPUTS]) -> Vec<u8> {
        // Independent, previously retained Python sparse-tree constructor.
        // This helper takes only explicitly public synthetic fixture bytes.
        let script = r#"
import importlib.util,sys
spec=importlib.util.spec_from_file_location('retained_public_trees',sys.argv[1])
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
b=sys.stdin.buffer.read();at=0
def take(n):
 global at
 assert at+n<=len(b)
 x=b[at:at+n];at+=n;return x
def u32():return int.from_bytes(take(4),'little')
cms=[take(32) for _ in range(u32())]
entries=[(take(32),take(32),u32()) for _ in range(u32())]
nfs=[take(32) for _ in range(3)];newcms=[take(32) for _ in range(6)];assert at==len(b)
s=object.__new__(t.PublicState);s.cms=cms
s.cm=t.SparseTree(16,b'KPX1CMN\0',t.CM_EMPTY,enumerate(cms));s.entries=entries
s.nf=t.SparseTree(17,b'KPX1NFN\0',t.NF_EMPTY,[(i,s.nf_leaf(*e)) for i,e in enumerate(entries)])
old=s.cm.root()+s.nf.root()
w=[s.insert(nf) for nf in nfs];p=[s.append(cm) for cm in newcms]
sys.stdout.buffer.write(old+s.nf.root()+s.cm.root()+len(s.entries).to_bytes(4,'little')+len(s.cms).to_bytes(4,'little')+b''.join(w)+b''.join(p))
"#;
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("owner-private-lifecycle/wallet/trees.py");
        let mut child = Command::new("/usr/bin/python3").arg("-c").arg(script).arg(source)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut input = (history.commitments.len() as u32).to_le_bytes().to_vec();
        for cm in &history.commitments {input.extend(cm);}
        input.extend((history.nullifiers.len() as u32).to_le_bytes());
        for leaf in &history.nullifiers {input.extend(leaf.value);input.extend(leaf.successor);input.extend(leaf.successor_index.to_le_bytes());}
        for nf in nfs {input.extend(nf);} for cm in cms {input.extend(cm);}
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(),"retained public oracle refused: {}",String::from_utf8_lossy(&result.stderr));
        result.stdout
    }
    fn public_trace(context: &Context, history: &PublicHistory, nfs: &[H;OWNERS], cms: &[H;OUTPUTS]) -> Result<(TraceBuilder,PrivateStateTrace)> {
        let mut builder = TraceBuilder::new(1,1)?;
        let nf_bits = nfs.each_ref().map(|value|constants(&builder,value));
        let cm_bits = cms.each_ref().map(|value|constants(&builder,value));
        let result = build_state_trace(&mut builder,context,history,&nf_bits,&cm_bits)?;
        Ok((builder,result))
    }
    #[test]
    fn full_private_algorithm_matches_retained_independent_public_constructor() {
        let cases = [
            (vec![],3,[number(20),number(80),number(250)]),
            (vec![number(70),number(4),number(180)],9,[number(2),number(85),number(255)]),
        ];
        for (old,count,nfs) in cases {
            let (context,history) = fixture(&old,count);
            let cms = std::array::from_fn(|i|commitment(100+i as u64));
            let expected = legacy_public_oracle(&history,&nfs,&cms);
            assert_eq!(&expected[..32],&context.old_cm_root);
            assert_eq!(&expected[32..64],&context.old_nf_root);
            let (builder,result) = public_trace(&context,&history,&nfs,&cms).unwrap();
            let values = builder.evaluate_public_fixture(&BTreeMap::new()).unwrap();
            assert_eq!(serialize(&result,&values),expected[64..]);
        }
    }
    #[test]
    fn full_256_bit_little_endian_nf_order_is_preserved() {
        let (context,history) = fixture(&[number(5)],3);
        let mut middle = [0;32];middle[19]=1;
        let mut high = [0;32];high[31]=1;
        let nfs = [number(256),middle,high];
        let cms = std::array::from_fn(|i|commitment(200+i as u64));
        let expected = legacy_public_oracle(&history,&nfs,&cms);
        let (builder,result) = public_trace(&context,&history,&nfs,&cms).unwrap();
        let values = builder.evaluate_public_fixture(&BTreeMap::new()).unwrap();
        assert_eq!(serialize(&result,&values),expected[64..]);
    }
    #[test]
    #[ignore="complete variable-input state graph; run explicitly with the recorded resource window"]
    fn full_variable_state_trace_matches_oracle_with_identical_ir_across_values() {
        let (context,history)=fixture(&[],3);
        let run=|nfs:[H;OWNERS],cms:[H;OUTPUTS]| {
            let mut fixtures=BTreeMap::new();
            for (offset,byte) in nfs.iter().chain(&cms).flatten().enumerate() {
                for bit in 0..8 {fixtures.insert(1+offset*8+bit,Fr::from((byte>>bit)&1));}
            }
            let model_variables=1+(OWNERS+OUTPUTS)*32*8;
            let mut builder=TraceBuilder::new_public_fixture(model_variables,1,fixtures.clone()).unwrap();
            let mut next=1;
            let mut secret_bytes=|| (0..32).map(|_|(0..8).map(|_| {let value=builder.input(next).unwrap();next+=1;value}).collect()).collect();
            let nf_bits:[SecretBytes;OWNERS]=std::array::from_fn(|_|secret_bytes());
            let cm_bits:[SecretBytes;OUTPUTS]=std::array::from_fn(|_|secret_bytes());
            assert_eq!(next,model_variables);
            let result=build_state_trace(&mut builder,&context,&history,&nf_bits,&cm_bits).unwrap();
            builder.require_complete_model().unwrap();
            let actual=serialize_borrowed(&result,builder.public_fixture_values(&fixtures).unwrap());
            let expected=legacy_public_oracle(&history,&nfs,&cms);
            assert_eq!(actual,expected[64..]);
            let graph=builder.public_fixture_graph_sha256().unwrap();
            println!("PUBLIC variable-state graph: {} wires, {} operations, sha256 {}",builder.variables(),builder.operation_count(),graph.iter().map(|b|format!("{b:02x}")).collect::<String>());
            (graph,builder.variables(),builder.operation_count(),actual)
        };
        let first_nfs=[number(20),number(80),number(250)];
        let first_cms=std::array::from_fn(|i|commitment(500+i as u64));
        let mut second_nfs=first_nfs;second_nfs[0][0]^=1;
        let mut second_cms=first_cms;second_cms[0][0]^=1;
        let (a,b)=std::thread::scope(|scope| {
            let first=scope.spawn(||run(first_nfs,first_cms));
            let second=scope.spawn(||run(second_nfs,second_cms));
            (first.join().unwrap(),second.join().unwrap())
        });
        assert_eq!((a.0,a.1,a.2),(b.0,b.1,b.2),"public fixture values changed the generated symbolic IR");
        assert_ne!(a.3,b.3,"changed inputs did not reach the derived state witnesses");
    }
    fn refused(context: &Context, history: &PublicHistory, nfs: &[H;OWNERS], cms: &[H;OUTPUTS]) {
        match public_trace(context,history,nfs,cms) {
            Err(_) => (),
            Ok((builder,_)) => assert!(matches!(builder.evaluate_public_fixture(&BTreeMap::new()),Err(TraceError::Shape(_)))),
        }
    }
    #[test]
    fn replay_order_empty_and_commitment_reuse_refuse_before_release() {
        let (context,history) = fixture(&[number(10)],3);
        let nfs = [number(20),number(30),number(40)];
        let cms = std::array::from_fn(|i|commitment(300+i as u64));
        refused(&context,&history,&[number(20),number(20),number(40)],&cms);
        refused(&context,&history,&[number(10),number(30),number(40)],&cms);
        refused(&context,&history,&[number(30),number(20),number(40)],&cms);
        refused(&context,&history,&[[0;32],number(30),number(40)],&cms);
        let mut bad = cms;bad[3]=bad[1];refused(&context,&history,&nfs,&bad);
        let mut bad = cms;bad[0]=history.commitments[0];refused(&context,&history,&nfs,&bad);
        let mut bad = cms;bad[0]=sha(&[b"KPX1CME\0"]);refused(&context,&history,&nfs,&bad);
    }
    #[test]
    fn malformed_or_stale_public_history_is_not_admitted() {
        let (context,history) = fixture(&[number(10)],3);
        let mut wrong = context.clone();wrong.old_nf_root[0]^=1;
        assert!(matches!(history.validate(&wrong),Err(Error::PublicHistory("state-history-nf-root"))));
        let mut wrong = context.clone();wrong.old_cm_root[0]^=1;
        assert!(matches!(history.validate(&wrong),Err(Error::PublicHistory("state-history-cm-root"))));
        let mut wrong = context.clone();wrong.old_nf_count+=1;
        assert!(matches!(history.validate(&wrong),Err(Error::PublicHistory("state-history-count"))));
        let mut wrong = history.clone();wrong.nullifiers[0].successor_index=0;
        assert!(matches!(wrong.validate(&context),Err(Error::PublicHistory("state-history-linked-list"))));
    }
    #[test]
    fn capacity_refuses_before_any_large_trace_is_allocated() {
        let (mut context,mut history) = fixture(&[],3);
        history.commitments.resize((1<<CM_DEPTH)-OUTPUTS+1,[0;32]);context.old_cm_count=history.commitments.len() as u32;
        assert!(matches!(history.validate(&context),Err(Error::PublicHistory("state-history-capacity"))));
        let (mut context,mut history) = fixture(&[],3);
        history.nullifiers.resize((1<<NF_DEPTH)-OWNERS+1,PublicNullifierLeaf { value:[0;32],successor:[0;32],successor_index:0 });
        context.old_nf_count=history.nullifiers.len() as u32;
        assert!(matches!(history.validate(&context),Err(Error::PublicHistory("state-history-capacity"))));
    }
}
