fn main() {
    if let Err(error) = kpi_shared_pool::anchored::experiment::run() {
        eprintln!("anchored authorization experiment: {error}");
        std::process::exit(1);
    }
}
