fn main() {
    println!("cargo:rerun-if-env-changed=GRUND_VERSION");
    println!("cargo:rerun-if-env-changed=GRUND_REVISION");
    println!("cargo:rerun-if-env-changed=CI_COMMIT_SHA");
    let version = std::env::var("GRUND_VERSION").unwrap_or_else(|_| {
        std::env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION")
    });
    println!("cargo:rustc-env=GRUND_VERSION={version}");
    let revision = std::env::var("GRUND_REVISION")
        .or_else(|_| std::env::var("CI_COMMIT_SHA"))
        .unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=GRUND_BUILD_REVISION={revision}");
}
