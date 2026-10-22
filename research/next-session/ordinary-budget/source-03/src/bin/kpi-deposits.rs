fn main() {
    if let Err(error) = kpi_shared_pool::compact::deposits::harness::run() {
        eprintln!("compact deposits: {error}");
        std::process::exit(1);
    }
}
