fn main() {
    println!("cargo:rerun-if-env-changed=GRUND_REVISION");
    println!("cargo:rerun-if-env-changed=CI_COMMIT_SHA");
    let revision = std::env::var("GRUND_REVISION")
        .or_else(|_| std::env::var("CI_COMMIT_SHA"))
        .unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=GRUND_BUILD_REVISION={revision}");
}
