use std::{path::PathBuf, process::Command};

const FILES: &[&str] = &[
    "grund/account/v1/account.proto",
    "grund/agent/v1/agent.proto",
    "grund/app/v1/app.proto",
    "grund/agent/v1/enrollment.proto",
    "grund/certificates/v1/certificates.proto",
    "grund/cli/v1/cli.proto",
    "grund/domain/v1/domain.proto",
    "grund/edge/v1/edge.proto",
    "grund/login/v1/login.proto",
    "grund/machine/v1/machine.proto",
    "grund/organisation/v1/organisation.proto",
    "grund/registry/v1/registry.proto",
    "grund/relay/v1/relay.proto",
    "grund/token/v1/token.proto",
];

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let descriptors = out.join("grund.desc");
    let protoc = std::env::var_os("PROTOC").unwrap_or_else(|| "protoc".into());
    let status = Command::new(protoc)
        .arg("--proto_path=../../proto")
        .arg("--include_imports")
        .arg("--include_source_info")
        .arg(format!("--descriptor_set_out={}", descriptors.display()))
        .args(FILES.iter().map(|f| format!("../../proto/{f}")))
        .status()
        .expect("grund protocol generation needs protoc on PATH");
    assert!(status.success(), "protoc refused grund's protocol");
    for file in FILES {
        println!("cargo:rerun-if-changed=../../proto/{file}");
    }
    connectrpc_build::Config::new()
        .descriptor_set(&descriptors)
        .files(FILES)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .compile()
        .expect("grund protocol generation must succeed");
}
