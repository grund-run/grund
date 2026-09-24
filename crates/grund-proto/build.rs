fn main() {
    connectrpc_build::Config::new()
        .files(&["../../proto/grund/account/v1/account.proto"])
        .includes(&["../../proto"])
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .compile()
        .expect("grund protocol generation must succeed; is protoc installed?");
}
