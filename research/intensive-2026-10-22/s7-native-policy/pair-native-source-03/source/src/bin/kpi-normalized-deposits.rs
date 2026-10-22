fn main() {
    if let Err(error) = kpi_shared_pool::compact::normalization::run() {
        eprintln!("normalized deposits: {error}");
        std::process::exit(1);
    }
}
