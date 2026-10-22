fn main() {
    if let Err(error) = kpi_shared_pool::two_input::lifecycle::run() {
        eprintln!("two-input offline lifecycle: {error}");
        std::process::exit(1);
    }
}
