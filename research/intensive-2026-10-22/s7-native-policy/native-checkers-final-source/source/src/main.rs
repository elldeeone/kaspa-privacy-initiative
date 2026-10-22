mod app;
mod fixtures;
#[cfg(test)]
mod tests;
fn main() {
    if let Err(e) = app::run() {
        eprintln!("shared-pool trial: {e}");
        std::process::exit(1);
    }
}
