use std::{env, process::Command};

fn required(name: &str) -> Result<String, &'static str> {
    env::var(name).map_err(|_| "build_metadata_missing")
}

fn line_value(value: &str) -> String {
    value.replace('\r', "\\r").replace('\n', "\\n")
}

fn metadata() -> Result<(), &'static str> {
    let compiler = required("RUSTC")?;
    let output = Command::new(compiler)
        .arg("-vV")
        .output()
        .map_err(|_| "build_compiler_identity_failed")?;
    if !output.status.success() {
        return Err("build_compiler_identity_failed");
    }
    let compiler =
        String::from_utf8(output.stdout).map_err(|_| "build_compiler_identity_invalid")?;
    if compiler.is_empty() {
        return Err("build_compiler_identity_invalid");
    }
    let mut features = Vec::new();
    for (name, _) in env::vars_os() {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("CARGO_FEATURE_"))
        {
            features.push(name.into_string().map_err(|_| "build_feature_invalid")?);
        }
    }
    features.sort();
    let flags = match env::var("CARGO_ENCODED_RUSTFLAGS") {
        Ok(flags) => flags,
        Err(env::VarError::NotPresent) => String::new(),
        Err(_) => return Err("build_flags_invalid"),
    };
    for name in ["RUSTC", "TARGET", "PROFILE", "CARGO_ENCODED_RUSTFLAGS"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for name in &features {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    for (name, value) in [
        ("KPI_RUSTC_VERBOSE", compiler),
        ("KPI_TARGET", required("TARGET")?),
        ("KPI_PROFILE", required("PROFILE")?),
        ("KPI_FEATURES", features.join(",")),
        ("KPI_RUSTFLAGS", flags),
    ] {
        // Cargo directives are line-oriented. Preserve compiler line breaks as
        // literal escapes; never let metadata introduce another directive.
        println!("cargo:rustc-env={name}={}", line_value(&value));
    }
    Ok(())
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("build_metadata_panic")));
    if let Err(code) = metadata() {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
