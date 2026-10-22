fn main() {
    if let Err(error) = kpi_shared_pool::compact::study::run() {
        eprintln!("privacy study: {error}");
        std::process::exit(1);
    }
}
