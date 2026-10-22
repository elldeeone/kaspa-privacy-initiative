fn main() {
    if let Err(e) = kpi_shared_pool::two_input::harness::run() {
        eprintln!("two-input: {e}");
        std::process::exit(1);
    }
}
