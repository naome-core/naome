#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().is_some_and(|arg| arg == "proof") {
        let result = arguments
            .map(|arg| {
                arg.into_string()
                    .map_err(|_| "proof arguments must be UTF-8")
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
            .and_then(|args| naome_proof_loop::cli::execute(&args));
        if let Err(error) = result {
            eprintln!("naome proof: {error}");
            std::process::exit(1);
        }
        return;
    }
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
