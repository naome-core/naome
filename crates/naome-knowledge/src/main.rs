#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = naome_knowledge::runtime::execute().await {
        naome_knowledge::runtime::report_error(&error);
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("naome: supported platforms are Linux and macOS");
    std::process::exit(1);
}
