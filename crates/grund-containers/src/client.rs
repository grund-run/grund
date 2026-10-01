//! containerd's gRPC API over its Unix socket, through connectrpc's gRPC
//! client: one HTTP/2 connection, shared by every call, and re-established
//! when containerd restarts. Every call carries `containerd-namespace:
//! grund`, so nothing here can reach another namespace.

use std::{path::Path, time::Duration};

use connectrpc::{
    ConnectError, ErrorCode, Protocol,
    client::{ClientConfig, Http2Connection, SharedHttp2Connection},
};

use crate::{
    NAMESPACE,
    api::containerd::services::{
        containers::v1::ContainersClient, content::v1::ContentClient, images::v1::ImagesClient,
        snapshots::v1::SnapshotsClient, tasks::v1::TasksClient, transfer::v1::TransferClient,
        version::v1::VersionClient,
    },
};

/// The transport every generated client is built on.
pub type Transport = SharedHttp2Connection;

/// A connection to one containerd, in namespace [`NAMESPACE`].
#[derive(Clone)]
pub struct Client {
    transport: Transport,
    config: ClientConfig,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the containerd listening on `socket`. Lazy: nothing
    /// connects until the first call. Must be called inside a tokio runtime.
    pub fn new(socket: &Path) -> Self {
        let authority = http::Uri::from_static("http://localhost");
        let transport = Http2Connection::builder()
            .establishment_timeout(Duration::from_secs(5))
            .lazy_unix(socket, authority.clone())
            .shared(1024);
        let config = ClientConfig::new(authority)
            .with_protocol(Protocol::Grpc)
            .with_default_header("containerd-namespace", NAMESPACE);
        Self { transport, config }
    }

    /// The containers service.
    pub fn containers(&self) -> ContainersClient<Transport> {
        ContainersClient::new(self.transport.clone(), self.config.clone())
    }

    /// The content store.
    pub fn content(&self) -> ContentClient<Transport> {
        ContentClient::new(self.transport.clone(), self.config.clone())
    }

    /// The image records.
    pub fn images(&self) -> ImagesClient<Transport> {
        ImagesClient::new(self.transport.clone(), self.config.clone())
    }

    /// The snapshotters.
    pub fn snapshots(&self) -> SnapshotsClient<Transport> {
        SnapshotsClient::new(self.transport.clone(), self.config.clone())
    }

    /// Tasks: a container's processes.
    pub fn tasks(&self) -> TasksClient<Transport> {
        TasksClient::new(self.transport.clone(), self.config.clone())
    }

    /// The transfer service, which pulls images.
    pub fn transfer(&self) -> TransferClient<Transport> {
        TransferClient::new(self.transport.clone(), self.config.clone())
    }

    /// containerd's version.
    pub fn version(&self) -> VersionClient<Transport> {
        VersionClient::new(self.transport.clone(), self.config.clone())
    }
}

/// Whether containerd said the thing does not exist.
pub fn not_found(error: &ConnectError) -> bool {
    error.code == ErrorCode::NotFound
}

/// Whether containerd said the thing exists already.
pub fn already_exists(error: &ConnectError) -> bool {
    error.code == ErrorCode::AlreadyExists
}

/// A containerd error as an [`anyhow::Error`] saying what was being done.
pub fn failed(what: &str, error: ConnectError) -> anyhow::Error {
    anyhow::anyhow!(
        "containerd {what}: {} ({})",
        error.message.as_deref().unwrap_or("no message"),
        error.code.as_str()
    )
}
