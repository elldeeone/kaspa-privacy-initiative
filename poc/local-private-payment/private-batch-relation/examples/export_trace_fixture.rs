//! Export an explicitly PUBLIC, UNFUNDED SHA witness-extension fixture.
//! The model identity hashes actual R1CS rows, not Groth16 setup/PK queries.
//! This fixture is not a clear-witness input path for any financial experiment.
use ark_bn254::Fr;
use ark_r1cs_std::{GR1CSVar, convert::ToBitsGadget, uint8::UInt8};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL};
use kpi_private_batch_relation::{
    trace::{Bindings, TraceBuilder},
    trace_sha256::{digest_with_ark_trace, retained_digest_for_model},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn write(path: PathBuf, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = OpenOptions::new().create_new(true).write(true).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::args().nth(1).ok_or("output directory required")?);
    fs::create_dir(&root)?;
    let message = b"abc"; // Public standard fixture, never an owner secret.
    // First count the exact actual graph using the ordinary retained gadget.
    let count = ConstraintSystem::<Fr>::new_ref();
    count.set_optimization_goal(OptimizationGoal::Constraints);
    let bytes = UInt8::new_witness_vec(count.clone(), message)?;
    let _ = retained_digest_for_model(&bytes)?;
    let variables = count.num_variables();
    drop(count);

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let bytes = UInt8::new_witness_vec(cs.clone(), message)?;
    let mut trace = TraceBuilder::new(variables, 1)?;
    let mut inputs = BTreeMap::new();
    for byte in &bytes {
        for bit in byte.to_bits_le()? {
            let variable = bit.variable();
            if !variable.is_witness() {
                return Err("not a witness bit".into());
            }
            let column = 1 + variable.index().ok_or("missing witness index")?;
            trace.input(column)?;
            inputs.insert(column, Fr::from(bit.value()?));
        }
    }
    let digest = digest_with_ark_trace(&bytes, &mut trace)?;
    if cs.num_variables() != variables {
        return Err("changed actual SHA geometry".into());
    }
    trace.require_complete_model()?;
    let evaluated = trace.evaluate_public_fixture(&inputs)?;
    cs.finalize();
    if !cs.is_satisfied()? {
        return Err("public fixture is unsatisfied".into());
    }
    let mut groups = cs.to_matrices()?;
    if groups.len() != 1 || !groups.contains_key(R1CS_PREDICATE_LABEL) {
        return Err("unsupported predicate".into());
    }
    let model = auth::join::R1cs {
        instances: 1,
        witnesses: cs.num_witness_variables(),
        matrices: groups
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or("R1CS absent")?
            .try_into()
            .map_err(|_| "matrix axis count")?,
    };
    let model_sha = auth::join::fingerprint(&model).map_err(|_| "R1CS identity")?;
    let mut z = cs.instance_assignment()?;
    z.extend(cs.witness_assignment()?);
    if z != evaluated {
        return Err("trace differs from actual public SHA witness".into());
    }

    let half = message.len() * 8 / 2;
    let mut layout = format!(
        "KPB_TRACE_LAYOUT_V1\nMODEL_VARIABLES {variables}\nINSTANCES 1\nOWNERS 2\nOWNER owner0 {half}"
    );
    for i in 1..=half {
        layout.push_str(&format!(" {i}"));
    }
    layout.push_str(&format!("\nOWNER owner1 {}", message.len() * 8 - half));
    for i in half + 1..=message.len() * 8 {
        layout.push_str(&format!(" {i}"));
    }
    layout.push_str("\nEND\n");
    let layout_sha = hex(&Sha256::digest(layout.as_bytes()));
    let sources = [
        ("trace.rs", include_bytes!("../src/trace.rs").as_slice()),
        (
            "trace_sha256.rs",
            include_bytes!("../src/trace_sha256.rs").as_slice(),
        ),
        (
            "export_trace_fixture.rs",
            include_bytes!("export_trace_fixture.rs").as_slice(),
        ),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ];
    let mut source_hash = Sha256::new();
    source_hash.update(b"KPB_TRACE_PUBLIC_SOURCE_V1\0");
    for (name, body) in &sources {
        source_hash.update((name.len() as u64).to_le_bytes());
        source_hash.update(name.as_bytes());
        source_hash.update((body.len() as u64).to_le_bytes());
        source_hash.update(body);
    }
    let source_sha = hex(&source_hash.finalize());
    let mut trace_bytes = Vec::new();
    trace.write_text(
        &mut trace_bytes,
        &Bindings {
            source_sha256: source_sha.clone(),
            model_sha256: model_sha.clone(),
            layout_sha256: layout_sha.clone(),
        },
    )?;
    let trace_sha = hex(&Sha256::digest(&trace_bytes));
    let mut input_text = format!("PUBLIC_FIXTURE_INPUTS_V1 {}\n", inputs.len());
    for (i, value) in &inputs {
        input_text.push_str(&format!("{i} {value}\n"));
    }
    let mut expected_text = format!("PUBLIC_FIXTURE_EXPECTED_V1 {}\n", evaluated.len());
    for (i, value) in evaluated.iter().enumerate() {
        expected_text.push_str(&format!("{i} {value}\n"));
    }
    let digest_hex = hex(&digest.value()?);
    let mut columns = String::from("[");
    for (byte_index, byte) in digest.iter().enumerate() {
        if byte_index > 0 {
            columns.push(',');
        }
        columns.push('[');
        for (bit_index, bit) in byte.to_bits_le()?.iter().enumerate() {
            if bit_index > 0 {
                columns.push(',');
            }
            columns.push_str(
                &bit.variable()
                    .get_variable_index(1)
                    .ok_or("nonphysical digest bit")?
                    .to_string(),
            );
        }
        columns.push(']');
    }
    columns.push(']');
    write(root.join("trace.txt"), &trace_bytes)?;
    write(root.join("layout.txt"), layout.as_bytes())?;
    write(root.join("public-inputs.txt"), input_text.as_bytes())?;
    write(
        root.join("PUBLIC-expected-aux.txt"),
        expected_text.as_bytes(),
    )?;
    let manifest = format!(
        "{{\n  \"schema\":\"kpb-public-sha-trace-fixture/v1\",\n  \"scope\":\"PUBLIC_UNFUNDED_R1CS_WITNESS_EXTENSION_ONLY_NOT_GROTH16_MODEL\",\n  \"source_sha256\":\"{source_sha}\",\n  \"model_sha256\":\"{model_sha}\",\n  \"layout_sha256\":\"{layout_sha}\",\n  \"trace_sha256\":\"{trace_sha}\",\n  \"model_variables\":{variables},\n  \"variables\":{},\n  \"instances\":1,\n  \"r1cs_rows\":{},\n  \"message_hex\":\"{}\",\n  \"expected_sha256\":\"{digest_hex}\",\n  \"digest_columns_le_bits\":{columns},\n  \"private_owner_material\":false\n}}\n",
        trace.variables(),
        model.constraints(),
        hex(message)
    );
    write(root.join("manifest.json"), manifest.as_bytes())?;
    println!(
        "exported PUBLIC fixture: model_variables={variables}, rows={}, digest={digest_hex}, trace_sha256={trace_sha}",
        model.constraints()
    );
    Ok(())
}
