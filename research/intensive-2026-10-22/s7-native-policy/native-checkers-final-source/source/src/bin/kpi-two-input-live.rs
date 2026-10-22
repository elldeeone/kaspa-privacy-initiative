fn main() {
    if let Err(e) = kpi_shared_pool::two_input::live::run() {
        eprintln!("two-input live adapter: {e}");
        std::process::exit(1);
    }
}
