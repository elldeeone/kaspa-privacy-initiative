//! Explicit PUBLIC fixtures only; never reads a wallet or owner record.
#![forbid(unsafe_code)]
#[path = "../src/bin/owner_file_fr32/mod.rs"] mod owner_file_fr32;
use ark_bn254::Fr;
use std::{fs, io::{BufWriter, Write}, path::Path};
#[cfg(unix)] use std::os::unix::fs::OpenOptionsExt;
fn fresh(path:&Path)->std::io::Result<fs::File>{ fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) }
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<String>=std::env::args().collect(); if args.len()!=2{return Err("public fixture output directory required".into());}
 let root=Path::new(&args[1]);fs::create_dir(root)?;
 let a=[Fr::from(0u64),Fr::from(1u64),-Fr::from(1u64)]; let b=[-Fr::from(1u64);3];
 for (name,values) in [("A",a),("B",b)]{
  let mut binary=BufWriter::new(fresh(&root.join(format!("PUBLIC-{name}.bin")))?);
  owner_file_fr32::write_owner_file(&mut binary,0,3,&values)?;binary.flush()?;
  let mut text=BufWriter::new(fresh(&root.join(format!("PUBLIC-{name}.txt")))?);
  writeln!(text,"KPB_OWNER_INPUT_V1\nOWNER owner0\nCOUNT 3\nVALUES")?;
  for value in values{writeln!(text,"{value}")?;}writeln!(text,"END")?;text.flush()?;
 }
 for owner in 0..3u64{
  let value=match owner {0=>Fr::from(0u64),1=>Fr::from(1u64),_=>-Fr::from(1u64)};
  let mut file=BufWriter::new(fresh(&root.join(format!("PUBLIC-LARGE-{owner}.bin")))?);
  owner_file_fr32::write_owner_file(&mut file,owner,2_635_409,std::iter::repeat_n(&value,2_635_409))?;file.flush()?;
 }
 for (owner,value) in [(0u64,Fr::from(3u64)),(1u64,Fr::from(5u64))]{
  let mut file=BufWriter::new(fresh(&root.join(format!("PUBLIC-TOY-{owner}.bin")))?);
  owner_file_fr32::write_owner_file(&mut file,owner,1,std::iter::once(&value))?;file.flush()?;
 }
 println!("{{\"schema\":\"kpi-public-owner-fr32-producer-fixtures/v1\",\"small_count\":3,\"large_count\":2635409,\"large_file_bytes_each\":84333120,\"roles\":3,\"private_records_read_or_hashed\":false}}");Ok(())
}
