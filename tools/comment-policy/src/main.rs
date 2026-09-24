//! `cargo run -p comment-policy [workspace root]`: prints every comment the
//! policy refuses and exits 1 when there is any. The policy is in the
//! library's documentation.

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let violations = comment_policy::check_workspace(&root)?;
    for violation in &violations {
        println!("{violation}");
    }
    if violations.is_empty() {
        println!("comment policy: ok");
        Ok(())
    } else {
        eprintln!(
            "comment policy: {} comment(s) refused. In Rust, only doc comments on public items are allowed.",
            violations.len()
        );
        std::process::exit(1)
    }
}
