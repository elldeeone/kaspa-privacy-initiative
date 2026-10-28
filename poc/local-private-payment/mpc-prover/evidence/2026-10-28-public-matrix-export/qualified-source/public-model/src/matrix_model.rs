//! Import only pinned public R1CS matrices. No assignment or owner input is read.
//! Re-synthesis must retain every row, coefficient, column and variable count
//! before the actual Groth16 query model is generated.
use super::*;
use ark_relations::gr1cs::LinearCombination;
use std::str::SplitWhitespace;

#[derive(Clone)]
struct MatrixCircuit {
    instances: usize,
    witnesses: usize,
    rows: usize,
    matrices: [Matrix<Fr>; 3],
}

impl ConstraintSynthesizer<Fr> for MatrixCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> std::result::Result<(), SynthesisError> {
        let mut variables = vec![Variable::One];
        for _ in 1..self.instances {
            variables.push(cs.new_input_variable(|| Err(SynthesisError::AssignmentMissing))?);
        }
        for _ in 0..self.witnesses {
            variables.push(cs.new_witness_variable(|| Err(SynthesisError::AssignmentMissing))?);
        }
        let lc = |axis: usize, row: usize| -> LinearCombination<Fr> {
            self.matrices[axis][row].iter().fold(lc!(), |sum, (c, i)| sum + (*c, variables[*i]))
        };
        for row in 0..self.rows {
            cs.enforce_r1cs_constraint(|| lc(0, row), || lc(1, row), || lc(2, row))?;
        }
        Ok(())
    }
}

struct Reader<'a>(SplitWhitespace<'a>);
impl<'a> Reader<'a> {
    fn token(&mut self) -> Result<&'a str> { self.0.next().ok_or_else(|| "truncated-public-R1CS".into()) }
    fn tag(&mut self, expected: &str) -> Result<()> {
        if self.token()? != expected { return Err("public-R1CS-field-order".into()); }
        Ok(())
    }
    fn count(&mut self) -> Result<usize> {
        let text = self.token()?;
        let value: usize = text.parse()?;
        if value.to_string() != text { return Err("noncanonical-R1CS-count".into()); }
        Ok(value)
    }
    fn scalar(&mut self) -> Result<Fr> { canonical_scalar(self.token()?) }
    fn matrix(&mut self, name: &str, rows: usize, variables: usize) -> Result<Matrix<Fr>> {
        self.tag(name)?;
        if self.count()? != rows { return Err("R1CS-row-arity".into()); }
        let mut matrix = Vec::with_capacity(rows);
        for _ in 0..rows {
            self.tag("row")?;
            let terms = self.count()?;
            let mut row = Vec::with_capacity(terms);
            for _ in 0..terms {
                let column = self.count()?;
                let coefficient = self.scalar()?;
                if column >= variables { return Err("R1CS-column-range".into()); }
                row.push((coefficient, column));
            }
            matrix.push(row);
        }
        Ok(matrix)
    }
}

fn require_digest(text: &str) -> Result<()> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("noncanonical-source-digest".into());
    }
    Ok(())
}

pub(super) fn export(input: &Path, expected_input: &str, trace_source: &str, destination: &Path) -> Result<()> {
    require_digest(expected_input)?;
    require_digest(trace_source)?;
    let body = fs::read(input)?;
    if hash(&body) != expected_input { return Err("public-R1CS-pin-mismatch".into()); }
    let text = std::str::from_utf8(&body)?;
    let mut reader = Reader(text.split_whitespace());
    reader.tag("KPI_PUBLIC_R1CS_V1")?;
    reader.tag("field")?;
    if reader.token()? != Fr::MODULUS.to_string() { return Err("public-R1CS-wrong-field".into()); }
    reader.tag("num_instance")?; let instances = reader.count()?;
    reader.tag("num_private")?; let witnesses = reader.count()?;
    reader.tag("num_constraints")?; let rows = reader.count()?;
    let variables = instances.checked_add(witnesses).ok_or("R1CS-variable-overflow")?;
    if instances < 2 || rows == 0 { return Err("public-R1CS-empty-statement".into()); }
    reader.tag("public_inputs")?;
    if reader.count()? != instances { return Err("R1CS-public-prefix-arity".into()); }
    let public = (0..instances).map(|_| reader.scalar()).collect::<Result<Vec<_>>>()?;
    if public[0] != Fr::ONE { return Err("R1CS-ONE-prefix".into()); }
    let matrices = [reader.matrix("A", rows, variables)?, reader.matrix("B", rows, variables)?, reader.matrix("C", rows, variables)?];
    reader.tag("END")?;
    if reader.0.next().is_some() { return Err("trailing-public-R1CS".into()); }
    let circuit = MatrixCircuit { instances, witnesses, rows, matrices };
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.clone().generate_constraints(cs.clone())?;
    cs.finalize();
    let actual = cs.to_matrices()?;
    if actual.len() != 1 || !actual.contains_key(R1CS_PREDICATE_LABEL) ||
        actual[R1CS_PREDICATE_LABEL] != circuit.matrices || cs.num_constraints() != rows ||
        cs.num_instance_variables() != instances || cs.num_witness_variables() != witnesses {
        return Err("public-R1CS-resynthesis-changed-exact-matrices".into());
    }
    let required = rows.checked_add(instances).ok_or("domain-overflow")?;
    let domain = Radix2EvaluationDomain::<Fr>::new(required).ok_or("domain-unavailable")?;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rand::rngs::OsRng)?;
    if pk.a_query.len() != variables || pk.b_g1_query.len() != variables || pk.b_g2_query.len() != variables ||
        pk.l_query.len() != witnesses || pk.h_query.len() != domain.size() - 1 || pk.vk.gamma_abc_g1.len() != instances {
        return Err("public-R1CS-Groth16-query-shape".into());
    }
    let pk_bytes = serialized(&pk)?;
    let vk_bytes = serialized(&pk.vk)?;
    let mut source = Sha256::new();
    source.update(b"KPI_PUBLIC_MATRIX_QUERY_SOURCE_V1\0");
    source.update(trace_source.as_bytes());
    source.update(expected_input.as_bytes());
    for data in [include_bytes!("main.rs").as_slice(), include_bytes!("matrix_model.rs").as_slice(), include_bytes!("../Cargo.toml").as_slice(), include_bytes!("../Cargo.lock").as_slice()] {
        source.update((data.len() as u64).to_le_bytes()); source.update(data);
    }
    let source_sha = hex::encode(source.finalize());
    let mut out = String::new();
    writeln!(out, "KPI_MASCOT_PUBLIC_MODEL_V1\nfield {}\ncurve BN254\nreduction LibSnark", Fr::MODULUS)?;
    writeln!(out, "source {source_sha}\npk_sha256 {}\nvk_sha256 {}", hash(&pk_bytes), hash(&vk_bytes))?;
    writeln!(out, "num_instance {instances}\nnum_private {witnesses}\nnum_constraints {rows}\ndomain {}", domain.size())?;
    writeln!(out, "omega {}\nomega_inverse {}\ninv_n {}\ncoset_shift {}", fr(domain.group_gen), fr(domain.group_gen_inv), fr(domain.size_inv), fr(Fr::GENERATOR))?;
    write!(out, "public_inputs {instances}")?;
    for value in &public { write!(out, " {}", fr(*value))?; }
    writeln!(out)?;
    for (label, values) in ["A", "B", "C"].iter().zip(&circuit.matrices) { matrix(&mut out, label, values)?; }
    writeln!(out, "alpha_g1 {}\nbeta_g1 {}\nbeta_g2 {}\ndelta_g1 {}\ndelta_g2 {}", point1(&pk.vk.alpha_g1), point1(&pk.beta_g1), point2(&pk.vk.beta_g2), point1(&pk.delta_g1), point2(&pk.vk.delta_g2))?;
    query1(&mut out, "a_query", &pk.a_query)?;
    query1(&mut out, "b_g1_query", &pk.b_g1_query)?;
    query2(&mut out, "b_g2_query", &pk.b_g2_query)?;
    query1(&mut out, "l_query", &pk.l_query)?;
    query1(&mut out, "h_query", &pk.h_query)?;
    writeln!(out, "vk_hex {}\nEND", hex::encode(&vk_bytes))?;
    // Allocate the new identity only after public validation and setup succeed.
    fs::create_dir(destination)?;
    fs::write(destination.join("public_model.txt"), out.as_bytes())?;
    fs::write(destination.join("pk.bin"), &pk_bytes)?;
    fs::write(destination.join("vk.bin"), &vk_bytes)?;
    let receipt = format!("{{\"schema\":\"kpi-public-matrix-query-export/v1\",\"matrix_sha256\":\"{expected_input}\",\"trace_source_sha256\":\"{trace_source}\",\"source_sha256\":\"{source_sha}\",\"model_sha256\":\"{}\",\"pk_sha256\":\"{}\",\"vk_sha256\":\"{}\",\"instances\":{instances},\"private_variables\":{witnesses},\"rows\":{rows},\"domain\":{},\"exact_matrices_resynthesized\":true,\"private_input_or_proof_read\":false}}\n", hash(out.as_bytes()), hash(&pk_bytes), hash(&vk_bytes), domain.size());
    fs::write(destination.join("EXPORT.json"), &receipt)?;
    print!("{receipt}");
    Ok(())
}
