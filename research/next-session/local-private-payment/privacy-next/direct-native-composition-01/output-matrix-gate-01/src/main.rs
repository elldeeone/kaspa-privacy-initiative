//! Synthetic Output-only matrix seam. No prover, setup, PK read or network API.
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL,
};
use ark_serialize::CanonicalSerialize;
use kpi_local_private_payment_relation as native;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

type Row = Vec<(Fr, usize)>;
type Matrix = Vec<Row>;
type Result<T> = core::result::Result<T, &'static str>;
const C: usize = 217_807;
const W: usize = 214_998;
const ORIGINAL_HASH: &str = "21e21c057dc22d0100d2dd46a6867acba2f89ef1481b8046b4b8c29d8521c116";
const PARAMETER_HASH: &str = "401abafb0b375aa71159c6f4fff4002985f02a29acf0dfe03d89991734d3eeef";
const FIELD_MODULUS: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

struct System { inputs: usize, witnesses: usize, constraints: usize, m: [Matrix; 3] }
impl System {
    fn columns(&self) -> usize { self.inputs + self.witnesses }
    fn validate(&self) -> Result<()> {
        let columns = self.inputs.checked_add(self.witnesses).ok_or("COLUMN_OVERFLOW")?;
        if self.inputs == 0 { return Err("MISSING_ONE_COLUMN"); }
        for matrix in &self.m {
            if matrix.len() != self.constraints { return Err("ROW_COUNT"); }
            for row in matrix {
                if row.iter().any(|(_, index)| *index >= columns) { return Err("COLUMN_INDEX"); }
            }
        }
        Ok(())
    }
}

fn extract(mut groups: BTreeMap<String, Vec<Matrix>>, inputs: usize, witnesses: usize,
           constraints: usize) -> Result<System> {
    // Even an empty unexpected predicate is refused. No predicate is dropped.
    if groups.len() != 1 || !groups.contains_key(R1CS_PREDICATE_LABEL) {
        return Err("PREDICATE_SET");
    }
    let m: [Matrix; 3] = groups.remove(R1CS_PREDICATE_LABEL).ok_or("PREDICATE_SET")?
        .try_into().map_err(|_| "MATRIX_ARITY")?;
    let system = System { inputs, witnesses, constraints, m };
    system.validate()?;
    Ok(system)
}

fn collect(output: native::OutputCircuit) -> Result<(System, Vec<Fr>)> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    output.generate_constraints(cs.clone()).map_err(|_| "NATIVE_SYNTHESIS")?;
    cs.finalize();
    if !cs.is_satisfied().map_err(|_| "NATIVE_CHECK")? { return Err("NATIVE_FIXTURE_UNSAT"); }
    if cs.num_constraints() != C || cs.num_instance_variables() != 3 || cs.num_witness_variables() != W {
        return Err("NATIVE_DIMENSIONS");
    }
    if native::circuit::matrix_fingerprint(&cs).map_err(|_| "NATIVE_FINGERPRINT")? != ORIGINAL_HASH {
        return Err("NATIVE_MATRIX_IDENTITY");
    }
    let mut z = cs.instance_assignment().map_err(|_| "NATIVE_ASSIGNMENT")?;
    z.extend(cs.witness_assignment().map_err(|_| "NATIVE_ASSIGNMENT")?);
    let system = extract(cs.to_matrices().map_err(|_| "NATIVE_MATRICES")?, 3, W, C)?;
    Ok((system, z))
}

fn map_index(index: usize) -> usize {
    match index { 0 => 0, 1 => 3, 2 => 4, _ => index + 2 }
}
fn inverse_index(index: usize) -> Result<usize> {
    match index { 0 => Ok(0), 3 => Ok(1), 4 => Ok(2), 5.. => Ok(index - 2), _ => Err("EXTERNAL_IN_NATIVE_PREFIX") }
}
fn lift(old: &System) -> Result<System> {
    old.validate()?;
    if old.inputs != 3 || old.witnesses != W || old.constraints != C { return Err("LIFT_SOURCE_SHAPE"); }
    old.columns().checked_add(2).ok_or("COLUMN_OVERFLOW")?;
    let mut m: [Matrix; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for k in 0..3 {
        for row in &old.m[k] {
            m[k].push(row.iter().map(|(v, i)| (*v, map_index(*i))).collect());
        }
    }
    for j in 0..2 {
        // (internal_digest[j] - external_digest[j]) * ONE = 0.
        m[0].push(vec![(Fr::ONE, 3 + j), (-Fr::ONE, 1 + j)]);
        m[1].push(vec![(Fr::ONE, 0)]);
        m[2].push(vec![]);
    }
    let lifted = System { inputs: 3, witnesses: W + 2, constraints: C + 2, m };
    lifted.validate()?;
    for k in 0..3 {
        for (before, after) in old.m[k].iter().zip(&lifted.m[k][..C]) {
            if before.len() != after.len() { return Err("ROUNDTRIP_ROW_LENGTH"); }
            for ((v, i), (v2, i2)) in before.iter().zip(after) {
                if v != v2 || *i != inverse_index(*i2)? { return Err("ROUNDTRIP_NATIVE_MATRIX"); }
            }
        }
    }
    Ok(lifted)
}
fn assignment(old: &[Fr], external: [Fr; 2]) -> Result<Vec<Fr>> {
    if old.len() != W + 3 || old[0] != Fr::ONE { return Err("NATIVE_ASSIGNMENT_SHAPE"); }
    let mut z = vec![old[0], external[0], external[1], old[1], old[2]];
    z.extend_from_slice(&old[3..]);
    Ok(z)
}
fn dot(row: &Row, z: &[Fr]) -> Fr {
    row.iter().fold(Fr::from(0u64), |sum, (coefficient, index)| sum + *coefficient * z[*index])
}
fn scalar_hex(value: &Fr) -> String {
    let mut raw = [0u8; 32];
    value.serialize_compressed(raw.as_mut_slice()).expect("fixed Fr encoding");
    hex::encode(raw)
}
struct Evaluation { first: Option<usize>, native_failures: usize, link_failures: usize, links: [Fr; 2] }
fn evaluate(system: &System, z: &[Fr]) -> Result<Evaluation> {
    if z.len() != system.columns() { return Err("ASSIGNMENT_LENGTH"); }
    // ONE is a reserved constant, not a free witness. An all-zero vector is refused.
    if z[0] != Fr::ONE { return Err("ONE_NOT_ONE"); }
    let mut result = Evaluation { first: None, native_failures: 0, link_failures: 0,
                                  links: [Fr::from(0u64); 2] };
    for i in 0..system.constraints {
        let residual = dot(&system.m[0][i], z) * dot(&system.m[1][i], z) - dot(&system.m[2][i], z);
        if i >= C { result.links[i - C] = residual; }
        if residual != Fr::from(0u64) {
            result.first.get_or_insert(i);
            if i < C { result.native_failures += 1; } else { result.link_failures += 1; }
        }
    }
    Ok(result)
}
fn emit(value: Value) { println!("{value}"); }
fn semantic(name: &str, system: &System, z: &[Fr], unsat: bool,
            native_pass: bool, link_pass: bool, required_first: Option<usize>, mutation: Value) -> Result<()> {
    let e = evaluate(system, z)?;
    let matches = e.first.is_some() == unsat && (e.native_failures == 0) == native_pass
        && (e.link_failures == 0) == link_pass && required_first.is_none_or(|i| e.first == Some(i));
    emit(json!({"event":"CONTROL", "name":name, "class":if e.first.is_some(){"UNSAT_RESIDUAL"}else{"SAT"},
        "matches_expected":matches, "checked_constraints":system.constraints,
        "first_failure_row":e.first, "native_failures":e.native_failures, "link_failures":e.link_failures,
        "link_residual_hex_le32":[scalar_hex(&e.links[0]),scalar_hex(&e.links[1])], "mutation":mutation}));
    if !matches { return Err("FIRST_UNEXPECTED_CONTROL_OUTCOME"); }
    Ok(())
}
fn boundary(name: &str, system: &System, z: &[Fr], expected: &str, mutation: Value) -> Result<()> {
    let actual = evaluate(system, z).err();
    let matches = actual == Some(expected);
    emit(json!({"event":"CONTROL", "name":name, "class":"ASSIGNMENT_BOUNDARY_REFUSAL",
        "actual_refusal":actual, "expected_refusal":expected, "matches_expected":matches,
        "checked_constraints":0, "counted_as_unsatisfied_constraints":false, "mutation":mutation}));
    if !matches { return Err("FIRST_UNEXPECTED_CONTROL_OUTCOME"); }
    Ok(())
}
fn source_boundary(name: &str, groups: BTreeMap<String, Vec<Matrix>>, expected: &str) -> Result<()> {
    let actual = extract(groups, 1, 0, 1).err();
    let matches = actual == Some(expected);
    emit(json!({"event":"CONTROL", "name":name, "class":"SOURCE_MATRIX_BOUNDARY_REFUSAL",
        "actual_refusal":actual, "expected_refusal":expected, "matches_expected":matches,
        "synthetic_metadata_only":true, "counted_as_unsatisfied_constraints":false}));
    if !matches { return Err("FIRST_UNEXPECTED_CONTROL_OUTCOME"); }
    Ok(())
}

struct HashWriter { file: fs::File, hash: Sha256, bytes: u64 }
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(bytes)?; self.hash.update(&bytes[..n]); self.bytes += n as u64; Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.file.flush() }
}
fn artifact(output: &Path, name: &str, write: impl FnOnce(&mut HashWriter) -> Result<()>) -> Result<Value> {
    let path = output.join(name);
    let file = fs::OpenOptions::new().write(true).create_new(true).mode(0o400).open(&path)
        .map_err(|_| "FRESH_ARTIFACT_REQUIRED")?;
    let mut writer = HashWriter { file, hash: Sha256::new(), bytes: 0 };
    write(&mut writer)?;
    writer.file.sync_all().map_err(|_| "ARTIFACT_FSYNC")?;
    Ok(json!({"path":name,"bytes":writer.bytes,"sha256":hex::encode(writer.hash.finalize())}))
}
fn number(writer: &mut HashWriter, n: usize) -> Result<()> {
    writer.write_all(&(n as u64).to_le_bytes()).map_err(|_| "ARTIFACT_WRITE")
}
fn field(writer: &mut HashWriter, value: &Fr) -> Result<()> {
    let mut bytes = [0u8; 32];
    value.serialize_compressed(bytes.as_mut_slice()).map_err(|_| "FIELD_SERIALIZATION")?;
    writer.write_all(&bytes).map_err(|_| "ARTIFACT_WRITE")
}
fn write_system(output: &Path, name: &str, system: &System) -> Result<Value> {
    artifact(output, name, |w| {
        w.write_all(b"KPIOMAT1").map_err(|_| "ARTIFACT_WRITE")?;
        for n in [system.inputs, system.witnesses, system.constraints] { number(w, n)?; }
        for matrix in &system.m {
            number(w, matrix.len())?;
            for row in matrix { number(w, row.len())?; for (v, i) in row { field(w, v)?; number(w, *i)?; } }
        }
        Ok(())
    })
}
fn write_assignment(output: &Path, name: &str, z: &[Fr]) -> Result<Value> {
    artifact(output, name, |w| {
        w.write_all(b"KPIOASN1").map_err(|_| "ARTIFACT_WRITE")?;
        number(w, z.len())?;
        for v in z { field(w, v)?; }
        Ok(())
    })
}

fn run(output: &Path) -> Result<()> {
    if Fr::MODULUS.to_string() != FIELD_MODULUS { return Err("FIELD_IDENTITY"); }
    if hex::encode(native::parameter_powers_digest()) != PARAMETER_HASH { return Err("PUBLIC_CV_PARAMETER_IDENTITY"); }
    let original_output = native::circuit::fixture().1; // Unchanged, explicitly public synthetic fixture.
    let (original, old_z) = collect(original_output.clone())?;
    let original_eval = evaluate(&original, &old_z)?;
    if original_eval.first.is_some() { return Err("NATIVE_MATRIX_EVALUATION"); }
    let mut alternative = original_output;
    alternative.witness.note.value += 1; // Second frozen valid public fixture, no seed retuning.
    alternative.statement.cm = alternative.witness.note.commitment(&native::DOMAIN);
    alternative.statement.cv = native::value_commitment(alternative.witness.note.value,
                                                       &alternative.witness.blinding).map_err(|_| "ALT_PUBLIC_CV")?;
    let (alt_matrix, alt_old_z) = collect(alternative)?;
    if original.m != alt_matrix.m { return Err("ASSIGNMENT_DEPENDENT_MATRIX"); }
    drop(alt_matrix);
    if old_z[1..3] == alt_old_z[1..3] { return Err("DEGENERATE_ALTERNATE_PUBLIC_DIGEST"); }
    let lifted = lift(&original)?;
    let base = assignment(&old_z, [old_z[1], old_z[2]])?;
    let alternate = assignment(&alt_old_z, [alt_old_z[1], alt_old_z[2]])?;
    let artifacts = vec![write_system(output,"ORIGINAL-MATRICES.bin",&original)?,
        write_system(output,"LIFTED-MATRICES.bin",&lifted)?,
        write_assignment(output,"PUBLIC-BASE-ASSIGNMENT.bin",&base)?,
        write_assignment(output,"PUBLIC-ALT-ASSIGNMENT.bin",&alternate)?];
    emit(json!({"event":"BASELINE", "native_matrix_sha256":ORIGINAL_HASH,
        "field_modulus_decimal":Fr::MODULUS.to_string(),
        "original":{"constraints":C,"instances":3,"witnesses":W},
        "lifted":{"constraints":C+2,"instances":3,"witnesses":W+2},
        "all_native_rows_roundtrip_exact":true,"public_CV_parameters_reconstructed":true,"artifacts":artifacts}));
    semantic("P01_original_fixture_linked",&lifted,&base,false,true,true,None,json!({"kind":"base"}))?;
    semantic("P02_alternate_fixture_linked",&lifted,&alternate,false,true,true,None,json!({"kind":"alternate"}))?;
    for j in 0..2 {
        let mut z = base.clone(); z[1+j] += Fr::ONE;
        semantic(if j==0{"N01_external_lo_changed"}else{"N02_external_hi_changed"},&lifted,&z,true,true,false,Some(C+j),
                 json!({"kind":"base_delta","index":1+j,"add":"1"}))?;
    }
    let z = assignment(&alt_old_z,[old_z[1],old_z[2]])?;
    semantic("N03_valid_alternate_native_with_old_external",&lifted,&z,true,true,false,None,
             json!({"kind":"alternate_external_from_base"}))?;
    let mut z = base.clone(); z[5] += Fr::ONE;
    semantic("N04_native_first_private_wire_changed",&lifted,&z,true,false,true,None,
             json!({"kind":"base_delta","index":5,"add":"1"}))?;
    for j in 0..2 {
        let mut z = base.clone(); z[1+j] += Fr::ONE; z[3+j] += Fr::ONE;
        semantic(if j==0{"N05_both_lo_changed_fixed_native_witness"}else{"N06_both_hi_changed_fixed_native_witness"},
                 &lifted,&z,true,false,true,None,json!({"kind":"base_deltas","indices":[1+j,3+j],"add":"1"}))?;
    }
    boundary("B01_all_zero_vector",&lifted,&vec![Fr::from(0u64);base.len()],"ONE_NOT_ONE",json!({"kind":"all_zero"}))?;
    let mut z=base.clone(); z[0]=Fr::from(2u64);
    boundary("B02_constant_two",&lifted,&z,"ONE_NOT_ONE",json!({"kind":"base_set","index":0,"value":"2"}))?;
    boundary("B03_missing_final_field",&lifted,&base[..base.len()-1],"ASSIGNMENT_LENGTH",json!({"kind":"base_remove_last"}))?;
    let mut z=base.clone(); z.push(Fr::from(0u64));
    boundary("B04_extra_field",&lifted,&z,"ASSIGNMENT_LENGTH",json!({"kind":"base_append_zero"}))?;
    let tiny = || vec![vec![vec![(Fr::ONE,0)]],vec![vec![(Fr::ONE,0)]],vec![vec![(Fr::ONE,0)]]];
    let mut groups=BTreeMap::from([(R1CS_PREDICATE_LABEL.to_owned(),tiny())]);
    groups.insert("unexpected-even-if-empty".to_owned(),vec![]);
    source_boundary("G01_extra_predicate",groups,"PREDICATE_SET")?;
    let mut missing=tiny(); missing.pop();
    source_boundary("G02_missing_C_matrix",BTreeMap::from([(R1CS_PREDICATE_LABEL.to_owned(),missing)]),"MATRIX_ARITY")?;
    let mut bad=tiny(); bad[0][0][0].1=1;
    source_boundary("G03_out_of_range_column",BTreeMap::from([(R1CS_PREDICATE_LABEL.to_owned(),bad)]),"COLUMN_INDEX")?;
    emit(json!({"schema":"kpxa-native-output-matrix-binding-gate/v1","status":"PASS_FROZEN_SYNTHETIC_MATRIX_CONTROLS",
        "cases":15,"sat":2,"actual_residual_unsat":6,"assignment_boundary_refusals":4,"source_matrix_boundary_refusals":3,
        "new_groth16_setup":false,"proof_generated":false,"PK_body_read":false,"spend_synthesized":false,
        "actual_Original_access":false,"network_or_financial_execution":false,"native_batch_or_privacy_qualified":false}));
    Ok(())
}
fn main() {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    if args.len()!=2 || args[0]!="--output" || args[1]!="/out" { emit(json!({"status":"REFUSED","reason":"EXACT_CLOSED_OUTPUT_REQUIRED"}));std::process::exit(2); }
    if let Err(reason)=run(Path::new("/out")) {
        emit(json!({"status":"FAIL_RETAIN_FIRST_OUTCOME","reason":reason}));std::process::exit(2);
    }
}
