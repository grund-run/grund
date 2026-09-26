//! grund's own bridge, for a machine where grund agent runs as root: the
//! VMs' egress, and nothing else.
//!
//! ```text
//!   grundbr0      a Linux bridge holding the /24's first address, the VMs' gateway
//!   grundvm<n>    one tap per VM, on the bridge; the VM is .<n>
//!   inet grund    grund's nftables table, replaced whole on every start:
//!                   VMs reach the internet, masqueraded behind the host
//!                   VMs do not reach each other, the host, link-local addresses
//!                   (a cloud host's metadata service) or private and CGNAT
//!                   ranges (the LAN, a tailnet), except the nameservers they use
//!                   nothing reaches a VM unless the VM opened the connection
//!                   no IPv6 is forwarded from the bridge
//! ```
//!
//! The /24 is chosen once from 10.213.0.0/16, the first one no route on the
//! host overlaps, and kept in `<data dir>/network.json`, so a VM keeps its
//! address across agent restarts. The only other host setting touched is
//! IPv4 forwarding, which the host needs to route for its VMs.
//!
//! Another firewall can still drop what grund accepts: nftables runs every
//! base chain on a hook, and any one of them dropping a packet drops it.
//! Docker's FORWARD chain does, with policy drop. [`Bridge::egress_blocked`]
//! finds such a chain, and the runtime then reports no egress rather than
//! placing VMs that cannot register.

use std::{
    net::Ipv4Addr,
    path::Path,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

/// The bridge's name.
pub const BRIDGE: &str = "grundbr0";

/// The nftables table grund owns.
pub const TABLE: &str = "grund";

/// Destinations a VM never reaches, other than its nameservers.
pub const PRIVATE: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Where VM subnets are chosen from: 10.213.<n>.0/24.
pub const POOL: [u8; 2] = [10, 213];

/// grund's bridge on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bridge {
    /// The /24's network address.
    pub subnet: Ipv4Addr,
    /// What the VMs resolve names with.
    pub nameservers: Vec<Ipv4Addr>,
}

impl Bridge {
    /// The bridge recorded in `data_dir`, or a new one on a /24 no route
    /// overlaps; then the bridge, forwarding and the table, set up.
    pub fn prepare(data_dir: &Path) -> anyhow::Result<Self> {
        let record = data_dir.join("network.json");
        let nameservers = host_nameservers();
        let bridge = match std::fs::read(&record)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Bridge>(&raw).ok())
        {
            Some(kept) => Bridge {
                nameservers,
                ..kept
            },
            None => {
                let routes = run("ip", &["-4", "route", "show", "table", "all"])?;
                let links = run("ip", &["-4", "-o", "addr", "show"])?;
                let taken: Vec<(u32, u8)> = parse_routes(&routes)
                    .into_iter()
                    .chain(parse_addresses(&links))
                    .collect();
                let subnet = choose_subnet(&taken).ok_or_else(|| {
                    anyhow::anyhow!("every /24 in 10.213.0.0/16 overlaps a route on this machine")
                })?;
                Bridge {
                    subnet,
                    nameservers,
                }
            }
        };
        bridge.set_up()?;
        let tmp = record.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&bridge)?)?;
        std::fs::rename(tmp, record)?;
        Ok(bridge)
    }

    /// The VMs' gateway: the bridge's own address.
    pub fn gateway(&self) -> Ipv4Addr {
        host(self.subnet, 1)
    }

    fn set_up(&self) -> anyhow::Result<()> {
        if !Path::new("/sys/class/net").join(BRIDGE).exists() {
            run("ip", &["link", "add", BRIDGE, "type", "bridge"])?;
        }
        let address = format!("{}/24", self.gateway());
        let current = run("ip", &["-4", "-o", "addr", "show", "dev", BRIDGE])?;
        if !current.contains(&format!("inet {address} ")) {
            run("ip", &["addr", "flush", "dev", BRIDGE])?;
            run("ip", &["addr", "add", &address, "dev", BRIDGE])?;
        }
        run("ip", &["link", "set", BRIDGE, "up"])?;
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| anyhow::anyhow!("enable IPv4 forwarding: {e}"))?;
        nft(&self.ruleset())
    }

    /// grund's whole table, replacing whatever it held.
    pub fn ruleset(&self) -> String {
        let subnet = format!("{}/24", self.subnet);
        let private = PRIVATE.join(", ");
        let resolvers = if self.nameservers.is_empty() {
            String::new()
        } else {
            let list: Vec<String> = self.nameservers.iter().map(Ipv4Addr::to_string).collect();
            format!(
                "\t\tiifname \"{BRIDGE}\" ip daddr {{ {} }} udp dport 53 accept\n\
                 \t\tiifname \"{BRIDGE}\" ip daddr {{ {} }} tcp dport 53 accept\n",
                list.join(", "),
                list.join(", ")
            )
        };
        format!(
            "table inet {TABLE}\n\
             delete table inet {TABLE}\n\
             table inet {TABLE} {{\n\
             \tchain forward {{\n\
             \t\ttype filter hook forward priority filter; policy accept;\n\
             \t\tiifname \"{BRIDGE}\" oifname \"{BRIDGE}\" drop\n\
             \t\tiifname \"{BRIDGE}\" meta nfproto ipv6 drop\n\
             \t\toifname \"{BRIDGE}\" ct state established,related accept\n\
             \t\toifname \"{BRIDGE}\" drop\n\
             \t\tiifname \"{BRIDGE}\" ip saddr != {subnet} drop\n\
             {resolvers}\
             \t\tiifname \"{BRIDGE}\" ip daddr {{ {private} }} counter drop\n\
             \t\tiifname \"{BRIDGE}\" accept\n\
             \t}}\n\
             \tchain input {{\n\
             \t\ttype filter hook input priority filter; policy accept;\n\
             \t\tiifname \"{BRIDGE}\" ct state established,related accept\n\
             \t\tiifname \"{BRIDGE}\" counter drop\n\
             \t}}\n\
             \tchain postrouting {{\n\
             \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
             \t\tip saddr {subnet} ip daddr != {subnet} oifname != \"{BRIDGE}\" masquerade\n\
             \t}}\n\
             }}\n"
        )
    }

    /// Why a VM's traffic cannot leave this machine, when another firewall
    /// drops what grund forwards.
    pub fn egress_blocked(&self) -> Option<String> {
        let ruleset = run("nft", &["list", "ruleset"]).ok()?;
        foreign_forward_drop(&ruleset)
    }

    /// Adds the tap of the VM at `.octet` to the bridge, owned by `owner`
    /// so only that VM's Firecracker can open it, replacing a stale one.
    pub fn add_tap(&self, octet: u8, owner: u32) -> anyhow::Result<String> {
        let name = tap_name(octet);
        let owner = owner.to_string();
        let _ = run("ip", &["link", "del", &name]);
        run(
            "ip",
            &[
                "tuntap", "add", "dev", &name, "mode", "tap", "user", &owner, "group", &owner,
            ],
        )?;
        run("ip", &["link", "set", &name, "master", BRIDGE])?;
        run("ip", &["link", "set", &name, "up"])?;
        Ok(name)
    }

    /// Removes the VM's tap, if it is there.
    pub fn remove_tap(&self, octet: u8) {
        let name = tap_name(octet);
        if Path::new("/sys/class/net").join(&name).exists() {
            let _ = run("ip", &["link", "del", &name]);
        }
    }

    /// The kernel's `ip=` argument for the VM at `.octet`.
    pub fn kernel_ip(&self, octet: u8, hostname: &str) -> String {
        let dns: Vec<String> = self
            .nameservers
            .iter()
            .take(2)
            .map(Ipv4Addr::to_string)
            .collect();
        format!(
            "ip={}::{}:255.255.255.0:{hostname}:eth0:off:{}",
            host(self.subnet, octet),
            self.gateway(),
            dns.join(":")
        )
    }
}

/// The tap of the VM at `.octet`.
pub fn tap_name(octet: u8) -> String {
    format!("grundvm{octet}")
}

/// The VM's MAC: locally administered, unicast, from its address.
pub fn mac(subnet: Ipv4Addr, octet: u8) -> String {
    let [a, b, c, _] = subnet.octets();
    format!("06:00:{a:02x}:{b:02x}:{c:02x}:{octet:02x}")
}

/// The lowest address in .2 to .254 no VM holds.
pub fn free_octet(taken: &[u8]) -> Option<u8> {
    (2..=254).find(|octet| !taken.contains(octet))
}

fn host(subnet: Ipv4Addr, octet: u8) -> Ipv4Addr {
    let [a, b, c, _] = subnet.octets();
    Ipv4Addr::new(a, b, c, octet)
}

/// The first 10.213.<n>.0/24 that overlaps none of `taken` (network,
/// prefix length).
pub fn choose_subnet(taken: &[(u32, u8)]) -> Option<Ipv4Addr> {
    (0..=255u8)
        .map(|n| Ipv4Addr::new(POOL[0], POOL[1], n, 0))
        .find(|candidate| {
            let candidate = (u32::from(*candidate), 24u8);
            !taken.iter().any(|route| overlaps(candidate, *route))
        })
}

fn overlaps((a, a_len): (u32, u8), (b, b_len): (u32, u8)) -> bool {
    let len = a_len.min(b_len);
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    a & mask == b & mask
}

fn prefix(text: &str) -> Option<(u32, u8)> {
    let (address, len) = text.split_once('/').unwrap_or((text, "32"));
    Some((address.parse::<Ipv4Addr>().ok()?.into(), len.parse().ok()?))
}

/// Destinations of `ip -4 route show table all`, without the default route
/// or grund's own bridge, whose old subnet is free to take again.
pub fn parse_routes(text: &str) -> Vec<(u32, u8)> {
    const TYPES: &[&str] = &[
        "unicast",
        "local",
        "broadcast",
        "multicast",
        "anycast",
        "blackhole",
        "unreachable",
        "prohibit",
        "throw",
        "nat",
    ];
    text.lines()
        .filter(|line| !on_bridge(line))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let first = words.next()?;
            let destination = if TYPES.contains(&first) {
                words.next()?
            } else {
                first
            };
            prefix(destination)
        })
        .filter(|(_, len)| *len > 0)
        .collect()
}

/// Networks of `ip -4 -o addr show`, except grund's own bridge's.
pub fn parse_addresses(text: &str) -> Vec<(u32, u8)> {
    text.lines()
        .filter(|line| !on_bridge(line))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words.find(|word| *word == "inet")?;
            prefix(words.next()?)
        })
        .collect()
}

fn on_bridge(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words.windows(2).any(|pair| pair == ["dev", BRIDGE]) || words.get(1) == Some(&BRIDGE)
}

/// A base chain on the forward hook, outside grund's table, that drops by
/// default: then it drops what grund forwards too.
pub fn foreign_forward_drop(ruleset: &str) -> Option<String> {
    let mut table = String::new();
    let mut chain = String::new();
    for line in ruleset.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("table ") {
            table = rest.trim_end_matches('{').trim().to_string();
        } else if let Some(rest) = line.strip_prefix("chain ") {
            chain = rest.trim_end_matches('{').trim().to_string();
        } else if line.contains("hook forward")
            && line.contains("policy drop")
            && table != format!("inet {TABLE}")
        {
            return Some(format!(
                "the {table} table's {chain} chain drops forwarded traffic by default (docker does this); allow {BRIDGE} there, or run VMs where nothing else filters forwarding"
            ));
        }
    }
    None
}

/// The host's IPv4 nameservers that a VM can reach: not loopback (a local
/// stub such as systemd-resolved's), preferring the upstreams resolved
/// lists. None found, the VMs get none, and grund join reports it cannot
/// resolve.
pub fn host_nameservers() -> Vec<Ipv4Addr> {
    ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|text| parse_nameservers(&text))
        .find(|found| !found.is_empty())
        .unwrap_or_default()
}

/// The non-loopback IPv4 nameservers of a resolv.conf.
pub fn parse_nameservers(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse::<Ipv4Addr>().ok())
        .filter(|address| !address.is_loopback() && !address.is_unspecified())
        .collect()
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            missing(
                program,
                if program == "nft" {
                    "nftables"
                } else {
                    "iproute2"
                },
                e,
            )
        })?;
    anyhow::ensure!(
        output.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn missing(program: &str, package: &str, error: std::io::Error) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "{program} is required for bridged VMs: install {package}, or run with --vm-network isolated"
        )
    } else {
        anyhow::anyhow!("{program}: {error}")
    }
}

fn nft(ruleset: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| missing("nft", "nftables", e))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("nft: no stdin"))?
        .write_all(ruleset.as_bytes())?;
    let output = child.wait_with_output()?;
    anyhow::ensure!(
        output.status.success(),
        "nft: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subnet_is_the_first_no_route_or_address_overlaps() {
        let routes = parse_routes(
            "default via 192.168.1.1 dev eth0\n\
             10.213.0.0/24 dev docker0 proto kernel scope link\n\
             local 10.213.1.7 dev lo table local proto kernel scope host\n\
             broadcast 127.255.255.255 dev lo table local\n\
             192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.20\n",
        );
        assert_eq!(choose_subnet(&routes), Some(Ipv4Addr::new(10, 213, 2, 0)));
        assert_eq!(
            choose_subnet(&[(u32::from(Ipv4Addr::new(10, 0, 0, 0)), 8)]),
            None,
            "a /8 covers the whole pool"
        );
        let addresses =
            parse_addresses("2: eth0    inet 10.213.0.9/16 brd 10.213.255.255 scope global eth0\n");
        assert_eq!(
            addresses,
            vec![(u32::from(Ipv4Addr::new(10, 213, 0, 9)), 16)]
        );
        assert_eq!(choose_subnet(&addresses), None);
        assert_eq!(choose_subnet(&[]), Some(Ipv4Addr::new(10, 213, 0, 0)));
    }

    #[test]
    fn grunds_own_bridge_does_not_take_its_subnet() {
        let routes = parse_routes(
            "10.213.0.0/24 dev grundbr0 proto kernel scope link src 10.213.0.1 linkdown\n\
             local 10.213.0.1 dev grundbr0 table local proto kernel scope host src 10.213.0.1\n",
        );
        let addresses =
            parse_addresses("5: grundbr0    inet 10.213.0.1/24 scope global grundbr0\n");
        assert!(routes.is_empty() && addresses.is_empty());
        assert_eq!(choose_subnet(&routes), Some(Ipv4Addr::new(10, 213, 0, 0)));
    }

    #[test]
    fn a_default_route_takes_nothing() {
        assert!(parse_routes("default via 10.0.0.1 dev eth0\n").is_empty());
    }

    #[test]
    fn only_reachable_nameservers_are_given_to_vms() {
        assert_eq!(
            parse_nameservers("nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver ::1\n"),
            vec![Ipv4Addr::new(192, 168, 1, 1)]
        );
    }

    #[test]
    fn the_ruleset_isolates_vms_and_lets_only_their_own_connections_back_in() {
        let bridge = Bridge {
            subnet: Ipv4Addr::new(10, 213, 4, 0),
            nameservers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        };
        let rules = bridge.ruleset();
        assert!(rules.starts_with("table inet grund\ndelete table inet grund\n"));
        assert!(rules.contains("iifname \"grundbr0\" oifname \"grundbr0\" drop"));
        assert!(rules.contains("oifname \"grundbr0\" ct state established,related accept\n\t\toifname \"grundbr0\" drop"));
        assert!(rules.contains("ip saddr != 10.213.4.0/24 drop"));
        assert!(rules.contains("169.254.0.0/16"));
        let resolver = rules
            .find("ip daddr { 192.168.1.1 } udp dport 53 accept")
            .unwrap();
        let private = rules.find("ip daddr { 10.0.0.0/8").unwrap();
        assert!(
            resolver < private,
            "the nameserver is allowed before the LAN is refused"
        );
        assert!(rules.contains(
            "ip saddr 10.213.4.0/24 ip daddr != 10.213.4.0/24 oifname != \"grundbr0\" masquerade"
        ));
        assert_eq!(
            bridge.kernel_ip(7, "vm-1"),
            "ip=10.213.4.7::10.213.4.1:255.255.255.0:vm-1:eth0:off:192.168.1.1"
        );
        assert_eq!(mac(bridge.subnet, 7), "06:00:0a:d5:04:07");
        assert_eq!(tap_name(254), "grundvm254");
        assert!(tap_name(254).len() <= 15);
    }

    #[test]
    fn another_tables_dropping_forward_chain_is_found() {
        let docker = "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n\
                      table inet grund {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n}\n";
        let found = foreign_forward_drop(docker).unwrap();
        assert!(found.contains("ip filter table's FORWARD chain"), "{found}");
        let own = "table inet grund {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n";
        assert_eq!(foreign_forward_drop(own), None);
    }

    #[test]
    fn the_first_free_address_is_used() {
        assert_eq!(free_octet(&[]), Some(2));
        assert_eq!(free_octet(&[2, 3, 5]), Some(4));
        let all: Vec<u8> = (2..=254).collect();
        assert_eq!(free_octet(&all), None);
    }
}
