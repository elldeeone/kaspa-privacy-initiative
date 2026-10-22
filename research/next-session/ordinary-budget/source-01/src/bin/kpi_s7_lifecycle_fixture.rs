fn main() {
    if let Err(error) = kpi_shared_pool::s7_lifecycle::fixture::run() {
        eprintln!("S7 initial public fixture: {error}");
        std::process::exit(1);
    }
}
