use std::{env, fs, path::PathBuf};
fn span<'a>(s: &'a str, start: &str, end: &str) -> &'a str {
    let i = s.find(start).expect("source start marker");
    let j = s[i..].find(end).expect("source end marker") + i;
    &s[i..j]
}
fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../shared-pool/src");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    for p in ["protocol.rs", "two_input/circuit.rs", "two_input/mod.rs", "two_input/tree.rs", "compact/mod.rs"] {
        println!("cargo:rerun-if-changed={}", root.join(p).display());
    }
    let source = fs::read_to_string(root.join("two_input/mod.rs")).unwrap();
    let core = span(&source, "pub const NOTE_FLOOR", "#[derive(Clone, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct Bundle");
    let dummy = span(&source, "pub fn dummy_nf(", "pub fn reserve_spk(");
    let tree = fs::read_to_string(root.join("two_input/tree.rs")).unwrap();
    let tree = span(&tree, "pub const DEPTH", "#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]");
    let compact = fs::read_to_string(root.join("compact/mod.rs")).unwrap();
    let tag = span(&compact, "pub const NF_TAG", "pub const AUTH_LEN");
    let nf = span(&compact, "pub fn nullifier(", "#[derive(Clone, Debug)]");
    let circuit = fs::read_to_string(root.join("two_input/circuit.rs")).unwrap();
    // Strip only its leading inner documentation comment for include! syntax.
    let circuit_items = circuit.split_once('\n').unwrap().1;
    fs::write(out.join("circuit.rs"), circuit_items).unwrap();
    fs::write(out.join("types.rs"), format!("{core}\n{dummy}")).unwrap();
    fs::write(out.join("tree.rs"), tree).unwrap();
    fs::write(out.join("compact.rs"), format!("{tag}\n{nf}")).unwrap();
}
