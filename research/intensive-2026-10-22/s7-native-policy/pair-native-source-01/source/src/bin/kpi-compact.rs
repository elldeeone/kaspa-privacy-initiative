fn main() {
    if let Err(error) = kpi_shared_pool::compact::experiment::run() {
        eprintln!("compact-state experiment: {error}");
        std::process::exit(1);
    }
}
