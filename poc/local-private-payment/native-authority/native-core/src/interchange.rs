//! Plain canonical adapter schema agreement; no field normalization or host valid bit.
use ark_bn254::Fr;
use ark_ff::{Field,PrimeField};
use serde_json::Value;
use sha2::{Digest,Sha256};
use core::str::FromStr;
use crate::join::{R1cs,Row};
pub const FIELD_P:&str="21888242871839275222246405745257275088548364400416034343698204186575808495617";
type R<T>=Result<T,&'static str>;
fn need(b:bool,c:&'static str)->R<()>{if b{Ok(())}else{Err(c)}}
fn text(v:&Value)->R<&str>{v.as_str().ok_or("STRING")}
fn num(v:&Value)->R<usize>{usize::try_from(v.as_u64().ok_or("UINT")?).map_err(|_|"UINT_OVERFLOW")}
fn at<'a>(v:&'a Value,k:&str)->R<&'a Value>{v.get(k).ok_or("MISSING_FIELD")}
fn keys(v:&Value,allowed:&[&str])->R<()>{let o=v.as_object().ok_or("OBJECT")?;need(o.len()==allowed.len()&&allowed.iter().all(|k|o.contains_key(*k)),"OBJECT_KEYS")}
fn list(v:&Value)->R<&Vec<Value>>{v.as_array().ok_or("ARRAY")}
fn pin(raw:&[u8],expected:&str)->R<()>{need(expected.len()==64&&expected.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"PIN_FORMAT")?;need(hex::encode(Sha256::digest(raw))==expected,"BODY_SHA256")}
fn uint_text(s:&str)->R<()>{need(!s.is_empty()&&s.bytes().all(|b|b.is_ascii_digit())&&(s=="0"||!s.starts_with('0')),"CANONICAL_DECIMAL")}
fn fr(v:&Value)->R<Fr>{let s=text(v)?;uint_text(s)?;let x=Fr::from_str(s).map_err(|_|"FR_PARSE")?;need(x.to_string()==s,"NONCANONICAL_FIELD")?;Ok(x)}
/// Expected hashes are from the separately frozen POST-BUILD selection, never
/// trusted merely because arbitrary JSON includes matching-looking hash fields.
pub fn signature_matrix(raw:&[u8],expected_body:&str,expected_map:&str)->R<R1cs>{
 pin(raw,expected_body)?;let v:Value=serde_json::from_slice(raw).map_err(|_|"JSON")?;
 keys(&v,&["schema","field","n8","nVars","nInstances","nWitnesses","nOutputs","nPublicInputs","nDeclaredPrivateInputs","nLabels","nConstraints","rows","wireToLabel","mappingSha256"])?;
 need(text(at(&v,"schema")?)?=="kpi-signature-normalized-r1cs/v1"&&text(at(&v,"field")?)?==FIELD_P&&Fr::MODULUS.to_string()==FIELD_P,"SCHEMA_FIELD")?;
 need(num(at(&v,"n8")?)?==32&&num(at(&v,"nInstances")?)?==67&&num(at(&v,"nOutputs")?)?==0&&num(at(&v,"nPublicInputs")?)?==66,"PUBLIC_PREFIX")?;
 need(text(at(&v,"mappingSha256")?)?==expected_map,"MAPPING_SHA256")?;
 let n=num(at(&v,"nVars")?)?;let w=num(at(&v,"nWitnesses")?)?;need(w.checked_add(67)==Some(n),"VARIABLE_COUNT")?;
 let declared=num(at(&v,"nDeclaredPrivateInputs")?)?;need(declared<=w,"DECLARED_PRIVATE_COUNT")?;
 let nl=text(at(&v,"nLabels")?)?;uint_text(nl)?;let nl=nl.parse::<u64>().map_err(|_|"LABEL_COUNT")?;
 let labels=list(at(&v,"wireToLabel")?)?;need(labels.len()==n,"LABEL_LENGTH")?;let mut used=std::collections::BTreeSet::new();
 for (i,l) in labels.iter().enumerate(){let t=text(l)?;uint_text(t)?;let l=t.parse::<u64>().map_err(|_|"LABEL")?;need(l<nl&&used.insert(l),"LABEL_RANGE_DUPLICATE")?;if i==0{need(l==0,"ONE_LABEL")?}}
 let rows=list(at(&v,"rows")?)?;need(rows.len()==num(at(&v,"nConstraints")?)?&& !rows.is_empty(),"ROW_COUNT")?;
 let mut matrices:[Vec<Row>;3]=core::array::from_fn(|_|Vec::with_capacity(rows.len()));
 for row in rows{let r=list(row)?;need(r.len()==3,"MATRIX_ARITY")?;for k in 0..3{let mut rr=Vec::new();let mut terms=std::collections::BTreeSet::new();for term in list(&r[k])?{let t=list(term)?;need(t.len()==2,"TERM")?;let i=num(&t[0])?;need(i<n&&terms.insert(i),"TERM_INDEX_DUPLICATE")?;rr.push((fr(&t[1])?,i))}matrices[k].push(rr)}}
 let cs=R1cs{instances:67,witnesses:w,matrices};cs.validate().map_err(|_|"MATRIX_SHAPE")?;Ok(cs)
}
pub fn signature_witness(raw:&[u8],expected_body:&str,expected_matrix:&str,expected_map:&str,n:usize)->R<Vec<Fr>>{
 pin(raw,expected_body)?;let v:Value=serde_json::from_slice(raw).map_err(|_|"JSON")?;
 keys(&v,&["schema","field","nVars","nInstances","nWitnesses","mappingSha256","normalizedMatrixSha256","values"])?;
 need(text(at(&v,"schema")?)?=="kpi-signature-normalized-witness/v1"&&text(at(&v,"field")?)?==FIELD_P,"WITNESS_SCHEMA_FIELD")?;
 need(text(at(&v,"mappingSha256")?)?==expected_map&&text(at(&v,"normalizedMatrixSha256")?)?==expected_matrix,"WITNESS_BINDING")?;
 need(num(at(&v,"nVars")?)?==n&&num(at(&v,"nInstances")?)?==67&&num(at(&v,"nWitnesses")?)?.checked_add(67)==Some(n),"WITNESS_COUNT")?;
 let values=list(at(&v,"values")?)?;need(values.len()==n,"WITNESS_LENGTH")?;let z=values.iter().map(fr).collect::<R<Vec<_>>>()?;need(z.first()==Some(&Fr::ONE),"ONE_NOT_ONE")?;Ok(z)
}
