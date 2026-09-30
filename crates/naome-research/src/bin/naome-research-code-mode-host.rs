fn main() {
    if let Err(error) = naome_research::host_proxy::run_from_env() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
