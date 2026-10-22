fn main() {
    if let Err(error) = kpi_shared_pool::two_input::wallet::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
