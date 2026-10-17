use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let descriptors = out.join("grund.desc");
    std::fs::write(&descriptors, grund_descriptors::FILE_DESCRIPTOR_SET)
        .expect("write grund's shared protocol descriptors");
    println!("cargo:rerun-if-env-changed=BUFFA_ELEMENT_MEMORY_LIMIT");
    connectrpc_build::Config::new()
        .descriptor_set(&descriptors)
        .emit_rerun_directives(false)
        .files(grund_descriptors::files::FILES)
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .compile()
        .expect("grund protocol generation must succeed");
}
