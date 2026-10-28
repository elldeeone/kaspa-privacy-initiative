//! PUBLIC unfunded two-owner SHA fixture with actual digest public inputs.
//! This exports real R1CS rows and a witness recipe, not Groth16 setup keys.
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    GR1CSVar, alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget,
    eq::EqGadget, fields::fp::FpVar, uint8::UInt8,
};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, R1CS_PREDICATE_LABEL,
};
use kpi_private_batch_relation::{
    trace::{Bindings, Lc, TraceBuilder},
    trace_sha256::{ark_bit, digest_with_ark_trace, retained_digest_for_model},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{self, OpenOptions}, io::Write, path::PathBuf};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|x| format!("{x:02x}")).collect() }
fn write(path: PathBuf, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(body)?;
    Ok(())
}

fn public_digest(cs: ConstraintSystemRef<Fr>, expected: &[u8])
    -> Result<[FpVar<Fr>; 2], Box<dyn std::error::Error>> {
    Ok([
        FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&expected[..16])))?,
        FpVar::new_input(cs, || Ok(Fr::from_le_bytes_mod_order(&expected[16..])))?,
    ])
}

fn bind_digest(digest: &[UInt8<Fr>], public: &[FpVar<Fr>; 2])
    -> Result<(), Box<dyn std::error::Error>> {
    for part in 0..2 {
        let mut bits = Vec::new();
        for byte in &digest[part * 16..part * 16 + 16] { bits.extend(byte.to_bits_le()?); }
        Boolean::le_bits_to_fp(&bits)?.enforce_equal(&public[part])?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::args().nth(1).ok_or("new output directory required")?);
    fs::create_dir(&root)?;
    let message = b"abc"; // Public standard fixture, never wallet material.
    let expected = Sha256::digest(message);
    let count = ConstraintSystem::<Fr>::new_ref();
    count.set_optimization_goal(OptimizationGoal::Constraints);
    let public = public_digest(count.clone(), &expected)?;
    let bytes = UInt8::new_witness_vec(count.clone(), message)?;
    let hash = retained_digest_for_model(&bytes)?;
    bind_digest(&hash, &public)?;
    let variables = count.num_variables();
    drop(count);

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let public = public_digest(cs.clone(), &expected)?;
    let bytes = UInt8::new_witness_vec(cs.clone(), message)?;
    let mut trace = TraceBuilder::new(variables, 3)?;
    let mut inputs = BTreeMap::new();
    for byte in &bytes {
        for bit in byte.to_bits_le()? {
            let variable = bit.variable();
            if !variable.is_witness() { return Err("input is not a witness bit".into()); }
            let column = variable.get_variable_index(3).ok_or("input variable kind")?;
            trace.input(column)?;
            inputs.insert(column, Fr::from(bit.value()?));
        }
    }
    let digest = digest_with_ark_trace(&bytes, &mut trace)?;
    bind_digest(&digest, &public)?;
    for part in 0..2 {
        let mut value = Lc::zero();
        let mut weight = Fr::ONE;
        for byte in &digest[16 * part..16 * part + 16] {
            for bit in byte.to_bits_le()? {
                value = value.plus(&ark_bit(&bit)?.scaled(weight));
                weight *= Fr::from(2u64);
            }
        }
        trace.assign_linear(1 + part, value)?;
    }
    if cs.num_variables() != variables || cs.num_instance_variables() != 3 {
        return Err("actual geometry changed".into());
    }
    trace.require_complete_model()?;
    let evaluated = trace.evaluate_public_fixture(&inputs)?;
    cs.finalize();
    if !cs.is_satisfied()? { return Err("public fixture is not satisfied".into()); }
    let mut groups = cs.to_matrices()?;
    if groups.len() != 1 || !groups.contains_key(R1CS_PREDICATE_LABEL) {
        return Err("unsupported predicate".into());
    }
    let model = auth::join::R1cs {
        instances: 3,
        witnesses: cs.num_witness_variables(),
        matrices: groups.remove(R1CS_PREDICATE_LABEL).ok_or("R1CS absent")?
            .try_into().map_err(|_| "matrix axes")?,
    };
    let r1cs_sha = auth::join::fingerprint(&model).map_err(|_| "R1CS fingerprint")?;
    let mut assignment = cs.instance_assignment()?;
    assignment.extend(cs.witness_assignment()?);
    if assignment != evaluated { return Err("trace/actual complete assignment mismatch".into()); }

    let mut layout = format!("KPB_TRACE_LAYOUT_V1\nMODEL_VARIABLES {variables}\nINSTANCES 3\nOWNERS 2\n");
    let columns = inputs.keys().copied().collect::<Vec<_>>();
    for owner in 0..2 {
        let selected = &columns[owner * 12..owner * 12 + 12];
        layout.push_str(&format!("OWNER owner{owner} {}", selected.len()));
        for column in selected { layout.push_str(&format!(" {column}")); }
        layout.push('\n');
    }
    layout.push_str("END\n");
    let layout_sha = hex(&Sha256::digest(layout.as_bytes()));
    let sources = [
        ("trace.rs", include_bytes!("../src/trace.rs").as_slice()),
        ("trace_sha256.rs", include_bytes!("../src/trace_sha256.rs").as_slice()),
        ("export_trace_public_digest.rs", include_bytes!("export_trace_public_digest.rs").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ];
    let mut source_hash = Sha256::new();
    source_hash.update(b"KPB_TRACE_PUBLIC_SOURCE_V1\0");
    for (name, body) in &sources {
        source_hash.update((name.len() as u64).to_le_bytes()); source_hash.update(name.as_bytes());
        source_hash.update((body.len() as u64).to_le_bytes()); source_hash.update(body);
    }
    let source_sha = hex(&source_hash.finalize());
    let mut trace_bytes = Vec::new();
    trace.write_text(&mut trace_bytes, &Bindings {
        source_sha256: source_sha.clone(), model_sha256: r1cs_sha.clone(), layout_sha256: layout_sha.clone(),
    })?;

    // Exact matrix terms, including their original order and zero/duplicate
    // entries, are retained for independent assignment-free setup import.
    let mut matrix_text = format!(
        "KPI_PUBLIC_R1CS_V1\nfield {}\nnum_instance 3\nnum_private {}\nnum_constraints {}\npublic_inputs 3 1 {} {}\n",
        Fr::MODULUS, model.witnesses, model.constraints(), assignment[1], assignment[2]);
    for (name, matrix) in ["A", "B", "C"].iter().zip(&model.matrices) {
        matrix_text.push_str(&format!("{name} {}\n", matrix.len()));
        for row in matrix {
            matrix_text.push_str(&format!("row {}", row.len()));
            for (coefficient, column) in row { matrix_text.push_str(&format!(" {column} {coefficient}")); }
            matrix_text.push('\n');
        }
    }
    matrix_text.push_str("END\n");
    let matrix_sha = hex(&Sha256::digest(matrix_text.as_bytes()));
    let mut inputs_text = format!("PUBLIC_FIXTURE_INPUTS_V1 {}\n", inputs.len());
    for (column, value) in &inputs { inputs_text.push_str(&format!("{column} {value}\n")); }
    let mut expected_text = format!("PUBLIC_FIXTURE_EXPECTED_V1 {}\n", assignment.len());
    for (column, value) in assignment.iter().enumerate() { expected_text.push_str(&format!("{column} {value}\n")); }
    let mut manifest = format!(
        "{{\n\"schema\":\"kpb-public-sha-digest-trace-fixture/v1\",\n\"scope\":\"PUBLIC_UNFUNDED_REAL_R1CS_NO_SETUP_KEYS_YET\",\n\"source_sha256\":\"{source_sha}\",\n\"model_sha256\":\"{r1cs_sha}\",\n\"r1cs_file_sha256\":\"{matrix_sha}\",\n\"layout_sha256\":\"{layout_sha}\",\n\"trace_sha256\":\"{}\",\n\"model_variables\":{variables},\n\"variables\":{},\n\"instances\":3,\n\"r1cs_rows\":{},\n\"message_hex\":\"616263\",\n\"expected_sha256\":\"{}\",\n\"public_inputs_decimal\":[\"1\",\"{}\",\"{}\"],\n\"private_owner_material\":false\n}}\n",
        hex(&Sha256::digest(&trace_bytes)), trace.variables(), model.constraints(),
        hex(&expected), assignment[1], assignment[2]);
    // Emit output bit IDs without serializing any financial owner input.
    let mut digest_columns = String::from("[");
    for (i, byte) in digest.iter().enumerate() {
        if i != 0 { digest_columns.push(','); }
        digest_columns.push('[');
        for (j, bit) in byte.to_bits_le()?.iter().enumerate() {
            if j != 0 { digest_columns.push(','); }
            digest_columns.push_str(&bit.variable().get_variable_index(3).ok_or("digest bit ID")?.to_string());
        }
        digest_columns.push(']');
    }
    digest_columns.push(']');
    manifest = manifest.replace("\"private_owner_material\":false", &format!("\"digest_columns_le_bits\":{digest_columns},\n\"private_owner_material\":false"));
    write(root.join("trace.txt"), &trace_bytes)?;
    write(root.join("layout.txt"), layout.as_bytes())?;
    write(root.join("R1CS-MATRICES.txt"), matrix_text.as_bytes())?;
    write(root.join("public-inputs.txt"), inputs_text.as_bytes())?;
    write(root.join("PUBLIC-expected-aux.txt"), expected_text.as_bytes())?;
    write(root.join("manifest.json"), manifest.as_bytes())?;
    let source_root = root.join("source"); fs::create_dir(&source_root)?;
    for (name, body) in sources { write(source_root.join(name), body)?; }
    println!("PUBLIC SHA public2 fixture: vars={variables}, rows={}, source={source_sha}, matrices={matrix_sha}", model.constraints());
    Ok(())
}
