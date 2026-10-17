use std::{path::PathBuf, process::Command};

include!("src/files.rs");

fn main() {
    let root =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets the manifest dir"));
    let proto = root.join("../../proto");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-changed={}", proto.display());
    let protoc = std::env::var_os("PROTOC").unwrap_or_else(|| "protoc".into());
    let status = Command::new(protoc)
        .current_dir(&proto)
        .arg("--proto_path=.")
        .arg("--include_imports")
        .arg("--include_source_info")
        .arg(format!(
            "--descriptor_set_out={}",
            out.join("grund.desc").display()
        ))
        .args(FILES)
        .status()
        .expect("grund protocol generation needs protoc on PATH");
    assert!(status.success(), "protoc refused grund's protocol");
}
