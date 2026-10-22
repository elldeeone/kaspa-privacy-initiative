fn main() {
    if let Err(error) = kpi_shared_pool::compact::recovery::run() {
        eprintln!("wallet recovery: {error}");
        std::process::exit(1);
    }
}
