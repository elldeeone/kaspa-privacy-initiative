//! Finite public encoding differential; no setup/proving or private inputs.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    id: String,
    kind: String,
    hex: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    id: String,
    vk_hex: String,
    proof_hex: String,
    inputs_hex: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema: String,
    vectors: Vec<Vector>,
    statements: Vec<Statement>,
}

fn bytes(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if value.len() > 2 * maximum {
        return Err("predecode byte-size bound".into());
    }
    let bytes = hex::decode(value).map_err(|_| "hex".to_string())?;
    if hex::encode(&bytes) != value {
        return Err("canonical hex".into());
    }
    Ok(bytes)
}
fn bounded_vk(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 512 {
        return Err("VK byte-size bound".into());
    }
    if bytes.len() >= 232 && u64::from_le_bytes(bytes[224..232].try_into().unwrap()) > 8 {
        return Err("VK vector count bound before decode/allocation".into());
    }
    Ok(())
}

macro_rules! backend {
    ($name:ident,$bn:ident,$ec:ident,$ff:ident,$groth:ident,$ser:ident) => {
        mod $name {
            use super::*;
            use $bn::{Bn254,Fq,Fq2,Fr,G1Affine,G2Affine};
            use $ec::AffineRepr;
            use $ff::{BigInteger,PrimeField};
            use $groth::{Groth16,Proof,VerifyingKey,prepare_verifying_key};
            use $ser::{CanonicalDeserialize,CanonicalSerialize};

            fn encode<T:CanonicalSerialize>(value:&T)->Vec<u8>{
                let mut bytes=Vec::new();value.serialize_compressed(&mut bytes).unwrap();bytes
            }
            fn decode<T:CanonicalDeserialize+CanonicalSerialize>(raw:&[u8])->Result<(T,Value),String>{
                let mut rest=raw;
                let value=T::deserialize_compressed(&mut rest).map_err(|e|format!("{e:?}"))?;
                let encoded=encode(&value);
                let mut uncompressed=Vec::new();value.serialize_uncompressed(&mut uncompressed).unwrap();
                let profile=json!({"status":"accepted","remaining_bytes":rest.len(),
                    "roundtrip_equal":encoded==raw,"strict_canonical":rest.is_empty()&&encoded==raw,
                    "canonical_hex":hex::encode(encoded),"uncompressed_hex":hex::encode(uncompressed)});
                Ok((value,profile))
            }
            pub fn fixtures()->Value{
                let mut fq=Fq::MODULUS.to_bytes_le();fq.resize(32,0);
                let mut fr=Fr::MODULUS.to_bytes_le();fr.resize(32,0);
                // A bounded, deterministic public curve-encoding test point,
                // not a new proof or setup. Never clear its cofactor.
                let mut non_subgroup=None;
                for n in 0..64u64 {
                    let x=Fq2::new(Fq::from(n),Fq::from(1u64));
                    if let Some(p)=G2Affine::get_point_from_x_unchecked(x,false) {
                        if p.is_on_curve()&&!p.is_in_correct_subgroup_assuming_on_curve(){
                            non_subgroup=Some(json!({"x0":n,"x1":1,"hex":hex::encode(encode(&p)),
                                "on_curve":true,"in_prime_subgroup":false}));break;
                        }
                    }
                }
                json!({"fq_modulus_le":hex::encode(fq),"fr_modulus_le":hex::encode(fr),
                    "g1_identity":hex::encode(encode(&G1Affine::identity())),
                    "g2_identity":hex::encode(encode(&G2Affine::identity())),
                    "g1_generator":hex::encode(encode(&G1Affine::generator())),
                    "g2_generator":hex::encode(encode(&G2Affine::generator())),
                    "bounded_non_subgroup_g2":non_subgroup})
            }
            pub fn vector(v:&Vector)->Value{
                let maximum=match v.kind.as_str(){"vk"=>512,"proof"=>160,"g1"=>40,"g2"=>72,"fq"|"fr"=>40,_=>0};
                let raw=match bytes(&v.hex,maximum){Ok(x)=>x,Err(e)=>return json!({"status":"guard_rejected","error":e})};
                if v.kind=="vk" {if let Err(e)=bounded_vk(&raw){return json!({"status":"guard_rejected","error":e});}}
                let result:Result<Value,String>=(||{
                    Ok(match v.kind.as_str(){
                        "vk"=>{let(k,mut p)=decode::<VerifyingKey<Bn254>>(&raw)?;
                            p["ic_count"]=json!(k.gamma_abc_g1.len());
                            p["identity"]=json!(k.alpha_g1.is_zero()||k.beta_g2.is_zero()||k.gamma_g2.is_zero()||k.delta_g2.is_zero()||k.gamma_abc_g1.iter().any(|x|x.is_zero()));p},
                        "proof"=>{let(x,mut p)=decode::<Proof<Bn254>>(&raw)?;p["identity"]=json!(x.a.is_zero()||x.b.is_zero()||x.c.is_zero());p},
                        "g1"=>{let(x,mut p)=decode::<G1Affine>(&raw)?;p["identity"]=json!(x.is_zero());p},
                        "g2"=>{let(x,mut p)=decode::<G2Affine>(&raw)?;p["identity"]=json!(x.is_zero());p},
                        "fq"=>decode::<Fq>(&raw)?.1,"fr"=>decode::<Fr>(&raw)?.1,
                        _=>return Err("unknown kind".into()),
                    })
                })();
                result.unwrap_or_else(|e|json!({"status":"decode_rejected","error":e}))
            }
            pub fn statement(s:&Statement)->Value{
                let result:Result<Value,String>=(||{
                    let vk_bytes=bytes(&s.vk_hex,512)?;bounded_vk(&vk_bytes)?;
                    let proof_bytes=bytes(&s.proof_hex,160)?;
                    if s.inputs_hex.len()>3 {return Err("public input vector bound".into());}
                    let(k,kp)=decode::<VerifyingKey<Bn254>>(&vk_bytes).map_err(|e|format!("VK:{e}"))?;
                    let(p,pp)=decode::<Proof<Bn254>>(&proof_bytes).map_err(|e|format!("proof:{e}"))?;
                    let mut inputs=Vec::new();let mut input_profiles=Vec::new();
                    for raw in &s.inputs_hex {let(x,profile)=decode::<Fr>(&bytes(raw,40)?).map_err(|e|format!("input:{e}"))?;inputs.push(x);input_profiles.push(profile);}
                    let identity=k.alpha_g1.is_zero()||k.beta_g2.is_zero()||k.gamma_g2.is_zero()||k.delta_g2.is_zero()
                        ||k.gamma_abc_g1.iter().any(|x|x.is_zero())||p.a.is_zero()||p.b.is_zero()||p.c.is_zero();
                    let strict=kp["strict_canonical"]==true&&pp["strict_canonical"]==true
                        &&input_profiles.iter().all(|x|x["strict_canonical"]==true)&&!identity
                        &&k.gamma_abc_g1.len()==3&&inputs.len()==2&&vk_bytes.len()==328&&proof_bytes.len()==128;
                    let pvk=prepare_verifying_key(&k);
                    // Raw 0.6 verifier has no input-arity guard. Record a bounded
                    // library panic rather than losing all other finite cases.
                    let verdict=std::panic::catch_unwind(||Groth16::<Bn254>::verify_proof(&pvk,&p,&inputs));
                    Ok(json!({"status":"decoded","raw_verifier":match verdict{Ok(Ok(v))=>json!({"returned":v}),Ok(Err(e))=>json!({"error":format!("{e:?}")}),Err(e)=>json!({"panic":e.downcast_ref::<String>().cloned().or_else(||e.downcast_ref::<&str>().map(|x|x.to_string())).unwrap_or_else(||"non-string panic".into())})},
                        "strict_profile_accepted":strict,"identity_present":identity,
                        "vk":kp,"proof":pp,"inputs":input_profiles}))
                })();
                result.unwrap_or_else(|e|json!({"status":"rejected_before_verifier","error":e}))
            }
        }
    };
}
backend!(
    v05,
    ark_bn254_05,
    ark_ec_05,
    ark_ff_05,
    ark_groth16_05,
    ark_serialize_05
);
backend!(
    v06,
    ark_bn254_06,
    ark_ec_06,
    ark_ff_06,
    ark_groth16_06,
    ark_serialize_06
);

fn run() -> Result<Value, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--fixtures"] {
        return Ok(json!({"ark05":v05::fixtures(),"ark06":v06::fixtures()}));
    }
    if args.len() != 1 {
        return Err("INPUT_JSON | --fixtures".into());
    }
    let path = Path::new(&args[0]);
    if fs::metadata(path).map_err(|e| e.to_string())?.len() > 1_048_576 {
        return Err("input file size bound".into());
    }
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let input: Input = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if input.schema != "kpi-arkworks-public-differential-input-v1"
        || input.vectors.len() > 200
        || input.statements.len() > 50
    {
        return Err("input scope/count bounds".into());
    }
    Ok(
        json!({"schema":"kpi-arkworks-public-differential-v1","input_sha256":hex::encode(Sha256::digest(&raw)),
        "vectors":input.vectors.iter().map(|v|json!({"id":v.id,"kind":v.kind,"ark05":v05::vector(v),"ark06":v06::vector(v)})).collect::<Vec<_>>(),
        "statements":input.statements.iter().map(|s|json!({"id":s.id,"ark05":v05::statement(s),"ark06":v06::statement(s)})).collect::<Vec<_>>(),
        "limits":"finite bounded public vectors; no setup, new proof, private input, or general equivalence claim"}),
    )
}
fn main() {
    // Every raw verifier unwind is retained as a per-case JSON panic outcome.
    std::panic::set_hook(Box::new(|_| {}));
    match run() {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(e) => {
            eprintln!("arkworks differential: {e}");
            std::process::exit(1);
        }
    }
}
