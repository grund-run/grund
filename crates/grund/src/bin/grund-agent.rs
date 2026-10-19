#[tokio::main]
async fn main() -> anyhow::Result<()> {
    grund::run_agent(env!("GRUND_BUILD_REVISION"), env!("GRUND_BUILD_TIME")).await
}
