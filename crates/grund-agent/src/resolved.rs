//! Pointing the machine's own resolver at the stub (grund-docs
//! design/network.md §6.2): where systemd-resolved runs, `grund0` gets the
//! stub as its DNS server and `~grund.internal` as a routing-only domain,
//! so `ping db.machines.grund.internal` works with no step by hand, and
//! every other name keeps going where it went before.
//!
//! It uses resolved's per-link D-Bus API (`org.freedesktop.resolve1`
//! `SetLinkDNS`, `SetLinkDomains`, `SetLinkDefaultRoute`, and DNSSEC, LLMNR
//! and mDNS off for the link), not `resolvectl`, so the agent needs no
//! binary beside it and the calls can be tested against a fake bus. The
//! settings belong to the link: they go when `grund0` goes, and the agent
//! reverts them itself when it stops ([`revert`]).
//!
//! Where resolved is not running, nothing is changed: the agent logs once
//! what the operator must do, and says so in `network.json`
//! ([`HostResolver::Absent`]).

use std::net::Ipv6Addr;

use serde::Serialize;

/// The domain routed to the stub.
pub const DOMAIN: &str = "grund.internal";

const AF_INET6: i32 = 10;

#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Manager {
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDomains")]
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDefaultRoute")]
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;
    #[zbus(name = "SetLinkDNSSEC")]
    fn set_link_dnssec(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;
    #[zbus(name = "SetLinkLLMNR")]
    fn set_link_llmnr(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;
    #[zbus(name = "SetLinkMulticastDNS")]
    fn set_link_multicast_dns(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;
    #[zbus(name = "RevertLink")]
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
}

/// What the agent did to the machine's resolver, as `network.json` says it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostResolver {
    /// Not tried yet: `grund0` is not up.
    Pending,
    /// resolved sends `~grund.internal` on this link to the stub.
    Configured { ifindex: i32, stub: Ipv6Addr },
    /// No systemd-resolved: names under grund.internal resolve only for
    /// software asking the stub itself. `hint` says what to configure.
    Absent { hint: String },
    /// resolved is there but refused.
    Failed { error: String },
}

/// Configures `ifindex` (`grund0`) in resolved over `connection`: the stub
/// as its DNS server, `~grund.internal` routed to it, never the default
/// route for other names, and no DNSSEC, LLMNR or mDNS on it.
pub async fn configure(
    connection: &zbus::Connection,
    ifindex: i32,
    stub: Ipv6Addr,
) -> zbus::Result<()> {
    let manager = ManagerProxy::new(connection).await?;
    manager
        .set_link_dns(ifindex, vec![(AF_INET6, stub.octets().to_vec())])
        .await?;
    manager
        .set_link_domains(ifindex, vec![(DOMAIN.to_string(), true)])
        .await?;
    manager.set_link_default_route(ifindex, false).await?;
    manager.set_link_dnssec(ifindex, "no").await?;
    manager.set_link_llmnr(ifindex, "no").await?;
    manager.set_link_multicast_dns(ifindex, "no").await?;
    Ok(())
}

/// Drops everything [`configure`] set on `ifindex`.
pub async fn revert(connection: &zbus::Connection, ifindex: i32) -> zbus::Result<()> {
    ManagerProxy::new(connection)
        .await?
        .revert_link(ifindex)
        .await
}

/// The hint for a machine without resolved.
pub fn hint(stub: Ipv6Addr) -> String {
    format!(
        "no systemd-resolved on this machine: send queries for {DOMAIN} to [{stub}]:53 \
         (in dnsmasq: server=/{DOMAIN}/{stub}; in unbound: a forward-zone for {DOMAIN}); \
         names outside {DOMAIN} are unaffected"
    )
}

/// Whether an error means resolved is not on the bus at all, rather than
/// that it refused.
pub fn is_absent(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, _, _) => matches!(
            name.as_str(),
            "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.NameHasNoOwner"
                | "org.freedesktop.systemd1.NoSuchUnit"
        ),
        zbus::Error::InputOutput(_) | zbus::Error::Address(_) => true,
        _ => false,
    }
}

/// Configures resolved on the system bus, reporting what came of it.
pub async fn apply(ifindex: i32, stub: Ipv6Addr) -> (HostResolver, Option<zbus::Connection>) {
    let connection = match zbus::Connection::system().await {
        Ok(connection) => connection,
        Err(_) => {
            return (HostResolver::Absent { hint: hint(stub) }, None);
        }
    };
    match configure(&connection, ifindex, stub).await {
        Ok(()) => (HostResolver::Configured { ifindex, stub }, Some(connection)),
        Err(error) if is_absent(&error) => (HostResolver::Absent { hint: hint(stub) }, None),
        Err(error) => (
            HostResolver::Failed {
                error: error.to_string(),
            },
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct FakeResolved {
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
    impl FakeResolved {
        #[zbus(name = "SetLinkDNS")]
        fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) {
            let shown: Vec<String> = addresses
                .iter()
                .map(|(family, bytes)| {
                    let octets: [u8; 16] = bytes.clone().try_into().unwrap_or([0; 16]);
                    format!("{family}:{}", Ipv6Addr::from(octets))
                })
                .collect();
            self.calls
                .lock()
                .unwrap()
                .push(format!("dns {ifindex} {shown:?}"));
        }
        #[zbus(name = "SetLinkDomains")]
        fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("domains {ifindex} {domains:?}"));
        }
        #[zbus(name = "SetLinkDefaultRoute")]
        fn set_link_default_route(&self, ifindex: i32, enable: bool) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("default-route {ifindex} {enable}"));
        }
        #[zbus(name = "SetLinkDNSSEC")]
        fn set_link_dnssec(&self, ifindex: i32, mode: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("dnssec {ifindex} {mode}"));
        }
        #[zbus(name = "SetLinkLLMNR")]
        fn set_link_llmnr(&self, ifindex: i32, mode: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("llmnr {ifindex} {mode}"));
        }
        #[zbus(name = "SetLinkMulticastDNS")]
        fn set_link_multicast_dns(&self, ifindex: i32, mode: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("mdns {ifindex} {mode}"));
        }
        #[zbus(name = "RevertLink")]
        fn revert_link(&self, ifindex: i32) {
            self.calls.lock().unwrap().push(format!("revert {ifindex}"));
        }
    }

    async fn a_fake_bus() -> (zbus::Connection, FakeResolved, zbus::Connection) {
        let (ours, theirs) = tokio::net::UnixStream::pair().unwrap();
        let fake = FakeResolved::default();
        let guid = zbus::Guid::generate();
        let server = zbus::connection::Builder::unix_stream(theirs)
            .server(guid)
            .unwrap()
            .p2p()
            .serve_at("/org/freedesktop/resolve1", fake.clone())
            .unwrap()
            .build();
        let client = zbus::connection::Builder::unix_stream(ours).p2p().build();
        let (server, client) = tokio::join!(server, client);
        (client.unwrap(), fake, server.unwrap())
    }

    #[tokio::test]
    async fn the_stub_gets_grund_internal_on_grund0_and_nothing_else() {
        let (bus, fake, _server) = a_fake_bus().await;
        let stub: Ipv6Addr = "fd12:3456:789a:2::53".parse().unwrap();
        configure(&bus, 7, stub).await.unwrap();
        revert(&bus, 7).await.unwrap();
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![
                r#"dns 7 ["10:fd12:3456:789a:2::53"]"#.to_string(),
                r#"domains 7 [("grund.internal", true)]"#.to_string(),
                "default-route 7 false".to_string(),
                "dnssec 7 no".to_string(),
                "llmnr 7 no".to_string(),
                "mdns 7 no".to_string(),
                "revert 7".to_string(),
            ]
        );
    }

    #[test]
    fn a_missing_resolved_is_absent_and_a_refusal_is_not() {
        let unknown = zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from("org.freedesktop.DBus.Error.ServiceUnknown")
                .unwrap(),
            None,
            zbus::message::Message::method_call("/", "Ping")
                .unwrap()
                .build(&())
                .unwrap(),
        );
        assert!(is_absent(&unknown));
        let denied = zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from("org.freedesktop.DBus.Error.AccessDenied")
                .unwrap(),
            None,
            zbus::message::Message::method_call("/", "Ping")
                .unwrap()
                .build(&())
                .unwrap(),
        );
        assert!(!is_absent(&denied));
        assert!(hint("fd12::53".parse().unwrap()).contains("[fd12::53]:53"));
    }
}
