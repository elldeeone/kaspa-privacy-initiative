fn main() {
    if let Err(error) = kpi_shared_pool::compact::fresh::run() {
        eprintln!("offline fresh-proof comparison: {error}");
        std::process::exit(1);
    }
}
