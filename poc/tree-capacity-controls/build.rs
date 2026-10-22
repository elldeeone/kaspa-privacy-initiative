use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};
fn pinned(path: &std::path::Path, expected: &str) -> String {
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = fs::read(path).unwrap();
    let actual = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(actual, expected, "pinned production source changed");
    String::from_utf8(bytes).unwrap()
}
fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../shared-pool/src");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let tree = pinned(&root.join("two_input/tree.rs"), "9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed");
    let protocol = pinned(&root.join("protocol.rs"), "5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4");
    let start = tree.find("pub const DEPTH").unwrap();
    let end = tree.find("#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]").unwrap();
    fs::write(out.join("production-tree.rs"), &tree[start..end]).unwrap();
    let start = protocol.find("pub fn hash(").unwrap();
    let end = protocol.find("pub fn random(").unwrap();
    fs::write(out.join("production-hash.rs"), &protocol[start..end]).unwrap();
}
