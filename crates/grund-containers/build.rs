fn main() {
    connectrpc_build::Config::new()
        .files(&[
            "proto/services/containers/v1/containers.proto",
            "proto/services/content/v1/content.proto",
            "proto/services/images/v1/images.proto",
            "proto/services/snapshots/v1/snapshots.proto",
            "proto/services/tasks/v1/tasks.proto",
            "proto/services/transfer/v1/transfer.proto",
            "proto/services/version/v1/version.proto",
            "proto/types/descriptor.proto",
            "proto/types/metrics.proto",
            "proto/types/mount.proto",
            "proto/types/platform.proto",
            "proto/types/runc/options/oci.proto",
            "proto/types/task/task.proto",
            "proto/types/transfer/imagestore.proto",
            "proto/types/transfer/registry.proto",
        ])
        .includes(&["proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("containerd protocol generation must succeed; is protoc installed?");
}
