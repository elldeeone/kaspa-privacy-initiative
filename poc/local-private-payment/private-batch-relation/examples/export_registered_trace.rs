//! ADR-0079 PUBLIC compiler entry. The C++ registered factory executes the
//! selected ELF directly with a fixed hashed specification and accepted head's
//! owned PUBLIC history. This program alone never mints accepted-head authority.
#[allow(dead_code)]
#[path = "export_financial_trace.rs"]
mod exporter;
#[allow(dead_code)]
#[path = "qualify_joint_core.rs"]
mod qualifier;

use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode};
use kpi_private_batch_relation::{joined_source::JoinedSourceCircuit, row_transport};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::{Path, PathBuf}};
type E = Box<dyn std::error::Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Specification {
    schema: String,
    signature_matrix: PathBuf,
    signature_matrix_sha256: String,
    signature_mapping_sha256: String,
    model_sha256: String,
    source_sha256: String,
    gzip_sha256: String,
    layout_sha256: String,
    prefix_recipe_sha256: String,
}
fn hash(s: &str) -> Result<(), E> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("noncanonical selected identity".into());
    }
    Ok(())
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, E> {
    Ok(value[key].as_str().ok_or("compiler output string absent")?)
}
fn number(value: &Value, key: &str) -> Result<u64, E> {
    Ok(value[key].as_u64().ok_or("compiler output integer absent")?)
}
fn actual_rows(input: &Path, specification: &Specification) -> Result<(), E> {
    let value: Value = serde_json::from_slice(&fs::read(input)?)?;
    let context = qualifier::context(hex::decode(string(&value, "context_hex")?)?.try_into()
        .map_err(|_| "context276 required")?);
    exporter::history(&value)?.validate(&context)?;
    let signature = auth::interchange::signature_matrix(&fs::read(&specification.signature_matrix)?,
        &specification.signature_matrix_sha256, &specification.signature_mapping_sha256)?;
    let source = JoinedSourceCircuit::from_public_context(context, core::array::from_fn(|_| signature.clone()))?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    let shape = source.generate_with_shape(cs.clone())?;
    cs.finalize();
    let mut axes = cs.to_matrices()?;
    if axes.len() != 1 || !axes.contains_key(R1CS_PREDICATE_LABEL) {
        return Err("unsupported source predicate".into());
    }
    let matrices = auth::join::R1cs {
        instances: cs.num_instance_variables(), witnesses: cs.num_witness_variables(),
        matrices: axes.remove(R1CS_PREDICATE_LABEL).ok_or("source R1CS absent")?
            .try_into().map_err(|_| "source axis count")?,
    };
    // Every finalized row, term, coefficient and physical column participates.
    // This boundary is deliberately fixed to the actual stock setup02 relation;
    // a changed relation requires a separately reviewed key selection.
    if matrices.instances != 3 || matrices.witnesses != 12949818 || matrices.constraints() != 13093029 ||
        shape.final_variables != 12949821 || shape.signature_variables != [10049; 3] ||
        matrices.variables().map_err(|_| "source geometry")? != shape.final_variables ||
        auth::join::fingerprint(&matrices).map_err(|_| "source fingerprint")? !=
            "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab" {
        return Err("actual finalized rows or variable mapping incompatible with selected key".into());
    }
    drop(matrices); drop(cs);
    Ok(())
}
fn main() -> Result<(), E> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 || args[0] != "--specification" || args[2] != "--input" || args[4] != "--output" {
        return Err("usage: export_registered_trace --specification FIXED-SPEC --input ACCEPTED-PUBLIC-HISTORY --output FRESH-DIR".into());
    }
    let specification_bytes = fs::read(&args[1])?;
    let specification: Specification = serde_json::from_slice(&specification_bytes)?;
    if specification.schema != "kpb-registered-financial-export-selection/v1" || !specification.signature_matrix.is_absolute() {
        return Err("selected compiler specification refused".into());
    }
    for pin in [&specification.signature_matrix_sha256, &specification.signature_mapping_sha256,
        &specification.model_sha256, &specification.source_sha256, &specification.gzip_sha256,
        &specification.layout_sha256, &specification.prefix_recipe_sha256] { hash(pin)?; }
    if row_transport::gzip_binary_sha256()? != specification.gzip_sha256 { return Err("gzip selection changed".into()); }
    let input = Path::new(&args[3]);
    let input_before = fs::read(input)?;
    let input_sha = hex::encode(Sha256::digest(&input_before));
    actual_rows(input, &specification)?;
    exporter::run_with_args(vec![args[3].clone(), specification.signature_matrix.to_string_lossy().into_owned(),
        specification.signature_matrix_sha256.clone(), specification.signature_mapping_sha256.clone(),
        specification.model_sha256.clone(), specification.source_sha256.clone(), args[5].clone()])?;
    if fs::read(input)? != input_before || fs::read(&args[1])? != specification_bytes ||
        row_transport::gzip_binary_sha256()? != specification.gzip_sha256 {
        return Err("public compiler input/tool changed".into());
    }
    let root = Path::new(&args[5]);
    let manifest: Value = serde_json::from_slice(&fs::read(root.join("PUBLIC-TRACE-MANIFEST.json"))?)?;
    if string(&manifest["layout"], "sha256")? != specification.layout_sha256 ||
        string(&manifest["prefix_recipe"], "sha256")? != specification.prefix_recipe_sha256 ||
        number(&manifest, "model_variables")? != 12949821 || number(&manifest, "model_instances")? != 3 ||
        manifest["owner_input_counts"] != serde_json::json!([2635409,2635409,2635409]) {
        return Err("physical input mapping/layout/recipe needs new explicit selection".into());
    }
    let mut descriptor = fs::OpenOptions::new().write(true).create_new(true).open(root.join("REGISTERED-EXPORT.txt"))?;
    writeln!(descriptor, "KPB_REGISTERED_EXPORT_V1\nMODEL {}\nSOURCE {}\nMATRIX c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab\nVARIABLES 12949821\nINSTANCES 3\nROWS 13093029\nDOMAIN 16777216\nHISTORY {}",
        specification.model_sha256, specification.source_sha256, input_sha)?;
    for (label, key) in [("TRACE", "trace"), ("LAYOUT", "layout")] {
        let part = &manifest[key];
        writeln!(descriptor, "{} {} {} {} {}", label, string(part,"sha256")?, number(part,"uncompressed_bytes")?,
            string(part,"container_sha256")?, number(part,"container_bytes")?)?;
    }
    writeln!(descriptor,"RECIPE {} {}\nEND", specification.prefix_recipe_sha256,number(&manifest["prefix_recipe"],"bytes")?)?;
    descriptor.sync_all()?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}
