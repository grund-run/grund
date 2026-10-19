#[tokio::main]
async fn main() {
    grund_crypto::install_default();
    let mut args: Vec<String> = std::env::args().collect();
    let original = args.len();
    let cli = loop {
        match grund_cli::Standalone::parse_args(&args) {
            Ok(cli) => break cli,
            Err(error) => {
                if args.len() < original + 3
                    && let Some(completed) = grund_cli::attended::complete(&args, &error).await
                {
                    args = completed;
                    continue;
                }
                match grund_cli::usage_error(&error, &args) {
                    Some(status) => std::process::exit(status),
                    None => error.exit(),
                }
            }
        }
    };
    if args.len() > original {
        grund_cli::attended::ran(&args);
    }
    let status = grund_cli::run(
        cli.command,
        grund_cli::Standalone::root(),
        env!("GRUND_BUILD_REVISION"),
    )
    .await;
    std::process::exit(status);
}
