fn main() {
    if let Err(error) = kpi_shared_pool::two_input::replay::run() {
        eprintln!("two-input public replay: {error}");
        std::process::exit(1);
    }
}
