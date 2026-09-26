fn main() {
    connectrpc_build::Config::new()
        .files(&[
            "../../proto/grund/account/v1/account.proto",
            "../../proto/grund/agent/v1/agent.proto",
            "../../proto/grund/agent/v1/enrollment.proto",
            "../../proto/grund/machine/v1/machine.proto",
            "../../proto/grund/organisation/v1/organisation.proto",
        ])
        .includes(&["../../proto"])
        .include_file("_connectrpc.rs")
        .gate_client_feature(true)
        .compile()
        .expect("grund protocol generation must succeed; is protoc installed?");
}
