//! SOURCE-ONLY full-matrix seam; no proof/setup/MPC or host signature verdict.
use ark_bn254::Fr;
use ark_ff::Field;
pub type Row=Vec<(Fr,usize)>;
#[derive(Clone)] pub struct R1cs { pub instances:usize, pub witnesses:usize, pub matrices:[Vec<Row>;3] }
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Boundary { Shape, Column, One, Length, Overflow, Inverse, Predicate, Synthesis }
fn plus(a:usize,b:usize)->Result<usize,Boundary>{a.checked_add(b).ok_or(Boundary::Overflow)}
impl R1cs {
 pub fn constraints(&self)->usize {self.matrices[0].len()}
 pub fn variables(&self)->Result<usize,Boundary>{plus(self.instances,self.witnesses)}
 pub fn validate(&self)->Result<(),Boundary>{
  if self.instances==0 || self.matrices.iter().any(|m|m.len()!=self.constraints()){return Err(Boundary::Shape)}
  let n=self.variables()?; if self.matrices.iter().flat_map(|m|m.iter()).flat_map(|r|r.iter()).any(|(_,i)|*i>=n){return Err(Boundary::Column)} Ok(())
 }
}
#[derive(Clone)] pub struct Joined { pub cs:R1cs, pub native_rows:usize, pub signature_rows:usize, pub native_private:usize, pub signature_private:usize }
fn relabel(rows:&[Row],f:&impl Fn(usize)->usize)->Vec<Row>{rows.iter().map(|r|r.iter().map(|(c,i)|(*c,f(*i))).collect()).collect()}
fn equality(a:usize,b:usize)->[Row;3]{[vec![(Fr::ONE,a),(-Fr::ONE,b)],vec![(Fr::ONE,0)],vec![]]}
pub fn join(native:&R1cs,signature:&R1cs)->Result<Joined,Boundary>{
 native.validate()?;signature.validate()?;
 if native.instances!=67 || signature.instances!=67{return Err(Boundary::Shape)}
 let wn=native.witnesses; let ws=signature.witnesses; let sigshift=plus(68,wn)?;
 let totalw=plus(132,plus(wn,ws)?)?; let _=plus(3,totalw)?; let expected_rows=plus(68,plus(native.constraints(),signature.constraints())?)?;
 let nf=|i|if i==0{0}else{i+2}; let sf=|i|if i==0{0}else{i+sigshift};
 let native_end=plus(native.variables()?,2)?;let signature_end=plus(signature.variables()?,sigshift)?;
 let ni=|j|if j==0{Some(0)}else if j>=3&&j<native_end{Some(j-2)}else{None};
 let si=|j|if j==0{Some(0)}else if j>=sigshift+1&&j<signature_end{Some(j-sigshift)}else{None};
 let mut matrices:[Vec<Row>;3]=core::array::from_fn(|k|{let mut a=relabel(&native.matrices[k],&nf);a.extend(relabel(&signature.matrices[k],&sf));a});
 for j in 0..2 {let r=equality(3+j,1+j);for k in 0..3{matrices[k].push(r[k].clone())}}
 for j in 0..2 {let r=equality(69+wn+j,1+j);for k in 0..3{matrices[k].push(r[k].clone())}}
 for j in 0..64 {let r=equality(5+j,71+wn+j);for k in 0..3{matrices[k].push(r[k].clone())}}
 let result=Joined{cs:R1cs{instances:3,witnesses:totalw,matrices},native_rows:native.constraints(),signature_rows:signature.constraints(),native_private:wn,signature_private:ws};
 result.cs.validate()?;
 // Exact inverse recovery of EVERY component row/term/coefficient, no sorting/dropping.
 for k in 0..3 {
  for (i,row) in native.matrices[k].iter().enumerate(){let lifted=&result.cs.matrices[k][i];if lifted.len()!=row.len()||lifted.iter().zip(row).any(|((a,j),(b,l))|a!=b||ni(*j)!=Some(*l)){return Err(Boundary::Inverse)}}
  for (i,row) in signature.matrices[k].iter().enumerate(){let lifted=&result.cs.matrices[k][native.constraints()+i];if lifted.len()!=row.len()||lifted.iter().zip(row).any(|((a,j),(b,l))|a!=b||si(*j)!=Some(*l)){return Err(Boundary::Inverse)}}
 }
 if result.cs.constraints()!=expected_rows{return Err(Boundary::Shape)} Ok(result)
}
pub fn assignment(joined:&Joined,native:&[Fr],signature:&[Fr],outer:[Fr;2])->Result<Vec<Fr>,Boundary>{
 if native.len()!=plus(67,joined.native_private)?||signature.len()!=plus(67,joined.signature_private)?{return Err(Boundary::Length)}
 if native[0]!=Fr::ONE||signature[0]!=Fr::ONE{return Err(Boundary::One)}
 // Deliberately keep two independent copies. Mismatched edges are actual link negatives.
 let mut z=Vec::with_capacity(joined.cs.variables()?);z.extend([Fr::ONE,outer[0],outer[1]]);z.extend_from_slice(&native[1..]);z.extend_from_slice(&signature[1..]);Ok(z)
}
#[derive(Clone,Debug)] pub struct Evaluation {pub checked:usize,pub native_failures:usize,pub signature_failures:usize,pub link_failures:usize,pub first_failure:Option<usize>}
fn dot(row:&Row,z:&[Fr])->Fr{row.iter().fold(Fr::ZERO,|v,(c,i)|v+*c*z[*i])}
pub fn evaluate(joined:&Joined,z:&[Fr])->Result<Evaluation,Boundary>{
 joined.cs.validate()?;if z.len()!=joined.cs.variables()?{return Err(Boundary::Length)}if z[0]!=Fr::ONE{return Err(Boundary::One)}
 let mut e=Evaluation{checked:0,native_failures:0,signature_failures:0,link_failures:0,first_failure:None};
 for i in 0..joined.cs.constraints(){let r=dot(&joined.cs.matrices[0][i],z)*dot(&joined.cs.matrices[1][i],z)-dot(&joined.cs.matrices[2][i],z);e.checked+=1;
  if r!=Fr::ZERO{if e.first_failure.is_none(){e.first_failure=Some(i)}if i<joined.native_rows{e.native_failures+=1}else if i<joined.native_rows+joined.signature_rows{e.signature_failures+=1}else{e.link_failures+=1}}
 }Ok(e)
}

/// Stream an exact local source-matrix identity; not a setup or VK identifier.
pub fn fingerprint(cs:&R1cs)->Result<String,Boundary>{
 use ark_serialize::CanonicalSerialize;use sha2::{Digest,Sha256};cs.validate()?;let mut h=Sha256::new();h.update(b"KPINAS/R1CS/v1\0");
 for n in [cs.instances,cs.witnesses,cs.constraints()]{h.update((n as u64).to_le_bytes())}
 for m in &cs.matrices{for row in m{h.update((row.len()as u64).to_le_bytes());for(c,i)in row{let mut b=[0;32];c.serialize_compressed(b.as_mut_slice()).map_err(|_|Boundary::Shape)?;h.update(b);h.update((*i as u64).to_le_bytes())}}}
 Ok(hex::encode(h.finalize()))
}
