//! Standard fixed-depth SHA-256 Merkle trees and indexed set insertion.
//! Full public leaves are reconstructible wallet data, never trusted by script.
use super::*;
pub const DEPTH: usize = 16;
pub const LIMIT: usize = 1 << DEPTH;
pub type Path = [H; DEPTH];
pub fn node(l: &H, r: &H) -> H { hash(&[&[1][..], l, r].concat()) }
pub fn cm_leaf(cm: &H) -> H { hash(&[&[0][..], cm].concat()) }
pub fn history_leaf(count: u32, root: &H) -> H {
    hash(&[&[3][..], &count.to_le_bytes(), root].concat())
}
pub fn root_from(mut h: H, index: u32, path: &Path) -> H {
    for (i, s) in path.iter().enumerate() {
        h = if index & (1 << i) == 0 { node(&h, s) } else { node(s, &h) };
    }
    h
}
pub fn empty_path() -> Path {
    let mut p = [[0; 32]; DEPTH];
    for i in 1..DEPTH { p[i] = node(&p[i-1], &p[i-1]); }
    p
}
#[derive(Clone)]
pub struct Tree { levels: Vec<Vec<H>>, empty: Path }
impl Tree {
    pub fn new(leaves: Vec<H>) -> Result<Self> {
        if leaves.len() > LIMIT { return Err("Merkle capacity".into()); }
        let empty = empty_path();
        let mut levels = vec![leaves];
        for level in 0..DEPTH {
            let next = levels[level].chunks(2).map(|c| node(&c[0], c.get(1).unwrap_or(&empty[level]))).collect();
            levels.push(next);
        }
        Ok(Self { levels, empty })
    }
    pub fn root(&self) -> H { self.levels[DEPTH].first().copied().unwrap_or_else(||node(&self.empty[DEPTH-1], &self.empty[DEPTH-1])) }
    pub fn path(&self, index: u32) -> Result<Path> {
        if index as usize >= LIMIT { return Err("Merkle position".into()); }
        Ok(std::array::from_fn(|i| self.levels[i].get(((index as usize) >> i)^1).copied().unwrap_or(self.empty[i])))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NfLeaf { pub value: H, pub next_index: u32, pub next_value: H }
impl NfLeaf {
    pub fn bytes(&self) -> Vec<u8> { [&self.value[..], &self.next_index.to_le_bytes(), &self.next_value].concat() }
    pub fn digest(&self) -> H { hash(&[&[2][..], &self.bytes()].concat()) }
}
pub fn less(a: &H, b: &H) -> bool { a.iter().rev().cmp(b.iter().rev()).is_lt() }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub cm_count: u32, pub nf_count: u32,
    pub cm_root: H, pub nf_root: H, pub history_root: H,
}
impl State {
    pub fn check(&self) -> Result<()> {
        if self.cm_count == 0 || self.cm_count as usize >= LIMIT || self.cm_count % 2 != 1 || self.nf_count > self.cm_count {
            return Err("compact state counts".into());
        }
        Ok(())
    }
    pub fn bytes(&self) -> Vec<u8> {
        [&[4][..], &self.cm_count.to_le_bytes(), &self.nf_count.to_le_bytes(), &self.cm_root, &self.nf_root, &self.history_root].concat()
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len()!=STATE_LEN || b[0]!=4 { return Err("compact state framing".into()); }
        let s=Self { cm_count:u32::from_le_bytes(b[1..5].try_into()?), nf_count:u32::from_le_bytes(b[5..9].try_into()?), cm_root:b[9..41].try_into()?, nf_root:b[41..73].try_into()?, history_root:b[73..105].try_into()? };
        s.check()?; Ok(s)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicState {
    pub commitments: Vec<H>, pub nullifiers: Vec<NfLeaf>, pub roots: Vec<H>,
}
impl PublicState {
    pub fn initial(cm: H) -> Result<Self> {
        let root=Tree::new(vec![cm_leaf(&cm)])?.root();
        Ok(Self {commitments:vec![cm], nullifiers:vec![NfLeaf::default()], roots:vec![root]})
    }
    pub fn cm_tree(&self) -> Result<Tree> { Tree::new(self.commitments.iter().map(cm_leaf).collect()) }
    pub fn nf_tree(&self) -> Result<Tree> { Tree::new(self.nullifiers.iter().map(NfLeaf::digest).collect()) }
    pub fn history_tree(&self) -> Result<Tree> {
        Tree::new(self.roots.iter().enumerate().map(|(i,r)|history_leaf((2*i+1) as u32,r)).collect())
    }
    pub fn compact(&self) -> Result<State> {
        let s=State {cm_count:self.commitments.len().try_into()?, nf_count:self.nullifiers.len().checked_sub(1).ok_or("missing sentinel")?.try_into()?, cm_root:self.cm_tree()?.root(), nf_root:self.nf_tree()?.root(), history_root:self.history_tree()?.root()};
        s.check()?;
        if self.roots.len()!=(self.commitments.len()+1)/2 || self.roots.last()!=Some(&s.cm_root) { return Err("public root history".into()); }
        Ok(s)
    }
    pub fn spent(&self,nf:&H)->bool { self.nullifiers.iter().any(|l|l.value==*nf) }
    pub fn witness(&self,a:&Authorization)->Result<(Self,Vec<u8>)> {
        self.compact()?;
        if a.count==0 || a.count%2!=1 || a.count as usize>self.commitments.len() || self.roots.get((a.count as usize-1)/2)!=Some(&a.anchor) {
            return Err("unknown historical anchor".into());
        }
        if ![1,2].contains(&a.mode) || a.nullifier==[0;32] || self.spent(&a.nullifier) { return Err("mode/nullifier already spent".into()); }
        let mut next=self.clone(); let mut w=vec![0;W_LEN];
        let put=|w:&mut Vec<u8>,off:usize,p:Path|{for (i,h) in p.iter().enumerate(){w[off+i*32..off+(i+1)*32].copy_from_slice(h)}};
        put(&mut w,W_ANCHOR,self.history_tree()?.path((a.count-1)/2)?);
        let pred=self.nullifiers.iter().position(|l|less(&l.value,&a.nullifier)&&(l.next_value==[0;32]||less(&a.nullifier,&l.next_value))).ok_or("nullifier predecessor")?;
        let old=&self.nullifiers[pred];
        w[W_PRED_INDEX..W_PRED_INDEX+4].copy_from_slice(&(pred as u32).to_le_bytes());
        w[W_PRED..W_PRED+68].copy_from_slice(&old.bytes());
        put(&mut w,W_PRED_PATH,self.nf_tree()?.path(pred as u32)?);
        let index=next.nullifiers.len() as u32;
        next.nullifiers[pred].next_index=index; next.nullifiers[pred].next_value=a.nullifier;
        put(&mut w,W_NF_APPEND,next.nf_tree()?.path(index)?);
        next.nullifiers.push(NfLeaf {value:a.nullifier,next_index:old.next_index,next_value:old.next_value});
        if a.mode==1 {
            if a.outputs.iter().any(|h|*h==[0;32]) {return Err("zero output commitment".into());}
            for (i,h) in a.outputs.iter().enumerate(){
                put(&mut w,W_CM_APPEND+i*PATH_LEN,next.cm_tree()?.path(next.commitments.len() as u32)?);
                next.commitments.push(*h);
            }
            put(&mut w,W_HISTORY_APPEND,self.history_tree()?.path(self.roots.len() as u32)?);
            next.roots.push(next.cm_tree()?.root());
        } else if a.outputs!=[[0;32];2] {return Err("exit commitment padding".into());}
        next.compact()?; Ok((next,w))
    }
}
