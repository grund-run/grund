#[tokio::main]
async fn main() -> anyhow::Result<()> {
    grund::run_with_extensions(
        |config| {
            #[cfg(feature = "ee")]
            {
                grund_ee::extensions(config)
            }
            #[cfg(not(feature = "ee"))]
            {
                let _ = config;
                Ok(Vec::new())
            }
        },
        env!("GRUND_BUILD_REVISION"),
        env!("GRUND_BUILD_TIME"),
    )
    .await
}
