#[tokio::main]
async fn main() {
    grund_crypto::install_default();
    let args: Vec<String> = std::env::args().collect();
    let cli = match grund_cli::Standalone::parse_args(&args) {
        Ok(cli) => cli,
        Err(error) => match grund_cli::usage_error(&error, &args) {
            Some(status) => std::process::exit(status),
            None => error.exit(),
        },
    };
    let status = grund_cli::run(
        cli.command,
        grund_cli::Standalone::root(),
        env!("GRUND_BUILD_REVISION"),
    )
    .await;
    std::process::exit(status);
}
