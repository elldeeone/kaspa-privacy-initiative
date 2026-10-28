//! SOURCE-ONLY closed stdin/stdout synthetic harness; no PK/setup/proof or paths.
use kpi_nativeauthspend_seam::{self as seam,AuthSpendCircuit,AuthSpendStatement,AuthSpendWitness,ReferenceOutputCircuit,Note,H,CV,DOMAIN};
use ark_bn254::Fr;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use serde_json::{Value,json};
use std::io::{self,Read};
fn need(b:bool,c:&'static str)->Result<(),&'static str>{if b{Ok(())}else{Err(c)}}
fn only(v:&Value,keys:&[&str])->Result<(),&'static str>{let o=v.as_object().ok_or("OBJECT")?;need(o.len()==keys.len()&&keys.iter().all(|k|o.contains_key(*k)),"OBJECT_KEYS")}
fn val<'a>(v:&'a Value,k:&str)->Result<&'a Value,&'static str>{v.get(k).ok_or("KEY")}
fn txt(v:&Value)->Result<&str,&'static str>{v.as_str().ok_or("STRING")}
fn bytes<const N:usize>(v:&Value)->Result<[u8;N],&'static str>{let s=txt(v)?;need(s.len()==N*2&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"HEX")?;hex::decode(s).map_err(|_|"HEX")?.try_into().map_err(|_|"WIDTH")}
fn buffer(v:&Value)->Result<Vec<u8>,&'static str>{let s=txt(v)?;need(s.len()%2==0&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"HEX")?;hex::decode(s).map_err(|_|"HEX")}
fn blind(n:u64)->H{let mut b=[0;32];b[..8].copy_from_slice(&n.to_le_bytes());b}
fn note(pk:&[u8;64],incoming:u8,value:u64,rho:u8,k:u8,native_pk:u8)->Note{Note{owner:seam::owner_key_commitment(&DOMAIN,pk,&[incoming;32]),incoming:[incoming;32],value,rho:[rho;32],key_commitment:native::key_commitment(&DOMAIN,&[k;32]),native_pk:[native_pk;32]}}
fn row(n:&Note,k:u8,r:u64)->Result<Value,&'static str>{Ok(json!({"noteHex":hex::encode(n.bytes()),"kHex":hex::encode([k;32]),"blindHex":hex::encode(blind(r)),"cmHex":hex::encode(n.commitment(&DOMAIN)),"cvHex":hex::encode(native::value_commitment(n.value,&blind(r)).map_err(|_|"CV")?)}))}
fn derive(v:&Value)->Result<Value,&'static str>{
 only(v,&["mode","ownerKeys"])?;
 let keys=val(v,"ownerKeys")?.as_array().ok_or("KEY_ARRAY")?;need(keys.len()==3,"KEY_COUNT")?;let a=bytes::<64>(&keys[0])?;let b=bytes::<64>(&keys[1])?;let c=bytes::<64>(&keys[2])?;let keys=[a,b,c];
 let mut prior=Vec::new();for i in 0..3{let n=note(&keys[i],0x10+i as u8,60_000_000+i as u64*10_000_000,0x20+i as u8,0x60+i as u8,0x30+i as u8);prior.push(row(&n,0x60+i as u8,2+i as u64)?)}
 let ni=note(&a,0x22,2_000_000_000,0x44,0x71,0x55);let no=note(&b,0x23,300_000_000,0x45,0x72,0x56);let change=note(&a,0x24,1_680_000_000,0x46,0x73,0x57);let attack=note(&c,0x25,300_000_000,0x47,0x74,0x58);
 let delta=ark_ed_on_bn254::Fr::from(7u64)-ark_ed_on_bn254::Fr::from(11u64)-ark_ed_on_bn254::Fr::from(13u64);let mut db=[0;32];delta.serialize_compressed(db.as_mut_slice()).map_err(|_|"SCALAR")?;
 let cv=native::value_commitment(ni.value,&blind(7)).map_err(|_|"CV")?;let co=native::value_commitment(no.value,&blind(11)).map_err(|_|"CV")?;let cc=native::value_commitment(change.value,&blind(13)).map_err(|_|"CV")?;
 need(native::check_balance(&[cv],&[co,cc],20_000_000,&db).map_err(|_|"BALANCE_ENCODING")?,"BALANCE_REFERENCE")?;
 Ok(json!({"schema":"kpi-nativeauth-derived-public-fixture/v1","ownerKeys":keys.iter().map(hex::encode).collect::<Vec<_>>(),"prior":prior,"input":row(&ni,0x71,7)?,"outputs":[row(&no,0x72,11)?,row(&change,0x73,13)?],"coordinatorOutput":row(&attack,0x74,11)?,"nfHex":hex::encode(native::nullifier(&DOMAIN,&[0x71;32],&ni.commitment(&DOMAIN),3)),"deltaHex":hex::encode(db),"scope":"PUBLIC_SYNTHETIC_UNFUNDED_NO_PROOF_NO_DELIVERY"}))
}
fn statement(packet:&[u8])->Result<AuthSpendStatement,&'static str>{
 need(packet.len()==4077,"PACKET_LENGTH")?;let(p,b)=packet.split_at(193);
 need(&p[..8]==b"KPBPFX01"&&&b[..8]==b"KPBPBD01"&&b[16..48]==DOMAIN,"RESEARCH_FRAME")?;
 need(&b[148..156]==b"KPBPST01"&&b[156..188]==DOMAIN,"OLD_STATE")?;
 // Mandatory public path/alias/current-head checks are performed by the closed
 // Python driver before this stdin job; no boolean result is a circuit input.
 Ok(AuthSpendStatement{domain:DOMAIN,anchor:b[188..220].try_into().map_err(|_|"WIDTH")?,nf:b[436..468].try_into().map_err(|_|"WIDTH")?,cv:b[468..532].try_into().map_err(|_|"WIDTH")?,effects_digest:native::hash(&[b"KPBPEF01",p,&b[..3756]])})
}
fn counts(cs:&seam::join::R1cs,z:&[Fr])->Result<(usize,Option<usize>),&'static str>{let j=seam::join::Joined{cs:cs.clone(),native_rows:cs.constraints(),signature_rows:0,native_private:cs.witnesses,signature_private:0};let e=seam::join::evaluate(&j,z).map_err(|_|"MATRIX_BOUNDARY")?;Ok((e.native_failures,e.first_failure))}
fn check(v:&Value)->Result<Value,&'static str>{
 only(v,&["mode","case","packetHex","nativeInput","signatureMatrixHex","signatureWitnessHex","pins","referenceOutputs","outerLowPlusOne"])?;
 let packet=buffer(val(v,"packetHex")?)?;let stmt=statement(&packet)?;let pi=stmt.public_inputs();let input=val(v,"nativeInput")?;
 only(input,&["noteHex","kHex","position","pathHex","blindHex","ownerKeyHex"])?;
 let n=Note::parse(&bytes::<168>(val(input,"noteHex")?)?).map_err(|_|"NOTE")?;let pos=u32::try_from(val(input,"position")?.as_u64().ok_or("POSITION")?).map_err(|_|"POSITION")?;
 let pp=val(input,"pathHex")?.as_array().ok_or("PATH")?;need(pp.len()==16,"PATH_LENGTH")?;let mut path=[[0;32];16];for i in 0..16{path[i]=bytes::<32>(&pp[i])?}
 let key=bytes::<64>(val(input,"ownerKeyHex")?)?;let circuit=AuthSpendCircuit{statement:stmt,witness:AuthSpendWitness{note:n,nullifier_secret:bytes::<32>(val(input,"kHex")?)?,position:pos,path,blinding:bytes::<32>(val(input,"blindHex")?)?},owner_key_bytes:key};
 let (nc,nz)=seam::collect::collect(circuit,67).map_err(|_|"NATIVE_COLLECT")?;
 let matrix=buffer(val(v,"signatureMatrixHex")?)?;let witness=buffer(val(v,"signatureWitnessHex")?)?;let pins=val(v,"pins")?;
 let mh=txt(val(pins,"matrixSha256")?)?;let wh=txt(val(pins,"witnessSha256")?)?;let map=txt(val(pins,"mappingSha256")?)?;
 let sc=seam::interchange::signature_matrix(&matrix,mh,map)?;let sz=seam::interchange::signature_witness(&witness,wh,mh,map,sc.variables().map_err(|_|"SIGNATURE_SHAPE")?)?;
 let native_component=counts(&nc,&nz)?;let signature_component=counts(&sc,&sz)?;
 let joined=seam::join::join(&nc,&sc).map_err(|_|"JOIN_BOUNDARY")?;
 let outer=if val(v,"outerLowPlusOne")?==&Value::Bool(true){[pi[0]+Fr::ONE,pi[1]]}else{need(val(v,"outerLowPlusOne")?==&Value::Bool(false),"CONTROL_FLAG")?;pi};
 let z=seam::join::assignment(&joined,&nz,&sz,outer).map_err(|_|"ASSIGNMENT_BOUNDARY")?;let e=seam::join::evaluate(&joined,&z).map_err(|_|"ASSIGNMENT_BOUNDARY")?;
 // Reference-output checks are actual matrices, separately labelled. No proof
 // bytes or ciphertext correctness is asserted by these checks.
 let refs=val(v,"referenceOutputs")?.as_array().ok_or("OUTPUTS")?;need(refs.len()==2,"OUTPUT_COUNT")?;
 let body=&packet[193..];let mut output_checks=Vec::new();for i in 0..2{let x=&refs[i];let at=532+520*i;let note=Note::parse(&bytes::<168>(val(x,"noteHex")?)?).map_err(|_|"NOTE")?;let(rc,rz)=seam::collect::collect(ReferenceOutputCircuit{domain:DOMAIN,note,cm:body[at..at+32].try_into().map_err(|_|"WIDTH")?,cv:body[at+32..at+96].try_into().map_err(|_|"WIDTH")?,cf_hash:body[at+360..at+392].try_into().map_err(|_|"WIDTH")?,blinding:bytes::<32>(val(x,"blindHex")?)?},3).map_err(|_|"OUTPUT_COLLECT")?;output_checks.push(counts(&rc,&rz)?.0)}
 Ok(json!({"schema":"kpi-nativeauth-matrix-case/v1","case":txt(val(v,"case")?)?,"verdict":if e.native_failures+e.signature_failures+e.link_failures==0{"SAT"}else{"UNSAT_RESIDUAL"},"checked":e.checked,"nativeFailures":e.native_failures,"signatureFailures":e.signature_failures,"linkFailures":e.link_failures,"firstFailure":e.first_failure,"componentNativeFailures":native_component.0,"componentSignatureFailures":signature_component.0,"referenceOutputFailures":output_checks,"nativeMatrixHash":seam::join::fingerprint(&nc).map_err(|_|"FINGERPRINT")?,"nativeRows":joined.native_rows,"signatureRows":joined.signature_rows,"jointRows":joined.cs.constraints(),"jointInstances":3,"jointWitnesses":joined.cs.witnesses,"signingSeedOrNonceInWitness":false,"scope":"ONE_NEW_RESEARCH_AUTHORITY_SEAM_NOT_NATIVE_ACCEPTANCE_MPC_PRIVACY_OR_FEES"}))
}
fn boundary()->Result<Value,&'static str>{
 use seam::join::{R1cs,Joined,Boundary};
 let cs=R1cs{instances:3,witnesses:0,matrices:[vec![vec![(Fr::ONE,0)]],vec![vec![(Fr::ONE,0)]],vec![vec![(Fr::ONE,0)]]]};let j=Joined{cs,native_rows:1,signature_rows:0,native_private:0,signature_private:0};
 let cases=[("ONE_ZERO",vec![Fr::ZERO;3],Boundary::One),("ONE_TWO",vec![Fr::from(2u64),Fr::ZERO,Fr::ZERO],Boundary::One),("SHORT",vec![Fr::ONE;2],Boundary::Length),("LONG",vec![Fr::ONE;4],Boundary::Length)];let mut results=Vec::new();
 for(name,z,want)in cases{let got=seam::join::evaluate(&j,&z);need(matches!(&got,Err(e)if *e==want),"UNEXPECTED_BOUNDARY")?;results.push(json!({"case":name,"verdict":"ASSIGNMENT_REFUSAL","reason":format!("{want:?}"),"checked":0,"tinyMetadataOnly":true}))}
 Ok(json!({"schema":"kpi-nativeauth-boundary-controls/v1","cases":results}))
}
fn main(){let mut raw=String::new();if io::stdin().read_to_string(&mut raw).is_err(){eprintln!("STDIN");std::process::exit(2)}let result=(||{let v:Value=serde_json::from_str(&raw).map_err(|_|"JSON")?;match txt(val(&v,"mode")?)?{"derive"=>derive(&v),"check"=>check(&v),"boundary"=>boundary(),_=>Err("MODE")}})();match result{Ok(v)=>println!("{v}"),Err(c)=>{eprintln!("{c}");std::process::exit(2)}}}
