//! PROXY protocol (v1 and v2, haproxy's spec) in front of the edge: an L4
//! proxy that passes TLS through by SNI can say who the client is with a
//! header before the ClientHello. The edge reads it only from the sources
//! GRUND_EDGE_PROXY_PROTOCOL_FROM names, where it is then required, so no
//! client can choose its own address, and uses that address for its
//! per-address limits and the entry header (the gate's X-Forwarded-For).

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// The most a header may take: v1's 107 bytes, or v2's 16 plus what its
/// addresses and TLVs claim, capped here.
pub const MAX_V2_LENGTH: usize = 1024;

/// An address or a network that is trusted to send PROXY headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    pub network: IpAddr,
    pub prefix: u8,
}

impl std::str::FromStr for Source {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match input.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (input.trim(), None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| format!("{input:?} is not an address or a network like 10.0.9.0/24"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("{input:?} has a bad prefix length"))?,
            None => max,
        };
        Ok(Self { network, prefix })
    }
}

impl Source {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Reads one PROXY header and returns the client's address it names, or the
/// connection's own peer for a LOCAL (v2) or UNKNOWN (v1) header. Reads no
/// byte past the header.
pub async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    peer: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    let mut first = [0u8; 12];
    reader.read_exact(&mut first[..5]).await?;
    if &first[..5] == b"PROXY" {
        let mut line = b"PROXY".to_vec();
        loop {
            anyhow::ensure!(line.len() < 107, "a PROXY v1 line longer than 107 bytes");
            let byte = reader.read_u8().await?;
            line.push(byte);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        return v1(&line, peer);
    }
    reader.read_exact(&mut first[5..]).await?;
    anyhow::ensure!(
        &first == V2_SIGNATURE,
        "the connection does not start with a PROXY header"
    );
    let mut fixed = [0u8; 4];
    reader.read_exact(&mut fixed).await?;
    let length = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
    anyhow::ensure!(
        length <= MAX_V2_LENGTH,
        "a PROXY v2 header of {length} bytes"
    );
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    v2(fixed[0], fixed[1], &body, peer)
}

fn v1(line: &[u8], peer: SocketAddr) -> anyhow::Result<SocketAddr> {
    let line = std::str::from_utf8(line)?.trim_end();
    let parts: Vec<&str> = line.split(' ').collect();
    match parts.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(peer),
        ["PROXY", "TCP4" | "TCP6", source, _, port, _] => {
            Ok(SocketAddr::new(source.parse()?, port.parse()?))
        }
        _ => anyhow::bail!("a malformed PROXY v1 line"),
    }
}

fn v2(
    version_command: u8,
    family: u8,
    body: &[u8],
    peer: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    anyhow::ensure!(
        version_command >> 4 == 2,
        "a PROXY header of version {}",
        version_command >> 4
    );
    match version_command & 0x0f {
        0 => return Ok(peer),
        1 => {}
        other => anyhow::bail!("a PROXY v2 command {other}"),
    }
    match family >> 4 {
        1 => {
            anyhow::ensure!(body.len() >= 12, "a short PROXY v2 IPv4 address block");
            let ip = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            Ok(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([body[8], body[9]]),
            ))
        }
        2 => {
            anyhow::ensure!(body.len() >= 36, "a short PROXY v2 IPv6 address block");
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&body[..16])?);
            Ok(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([body[32], body[33]]),
            ))
        }
        _ => Ok(peer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "10.0.9.1:40000".parse().unwrap()
    }

    #[tokio::test]
    async fn both_versions_name_the_client_and_nothing_after_the_header_is_read() {
        let mut v1 = b"PROXY TCP4 203.0.113.7 10.0.9.1 51000 443\r\n\x16\x03\x01".to_vec();
        let mut reader = v1.as_slice();
        assert_eq!(
            read(&mut reader, peer()).await.unwrap(),
            "203.0.113.7:51000".parse().unwrap()
        );
        assert_eq!(reader, b"\x16\x03\x01");
        v1.clear();

        let mut v2 = V2_SIGNATURE.to_vec();
        v2.extend_from_slice(&[0x21, 0x11, 0, 12]);
        v2.extend_from_slice(&[198, 51, 100, 9, 10, 0, 9, 1]);
        v2.extend_from_slice(&51001u16.to_be_bytes());
        v2.extend_from_slice(&443u16.to_be_bytes());
        v2.extend_from_slice(b"\x16");
        let mut reader = v2.as_slice();
        assert_eq!(
            read(&mut reader, peer()).await.unwrap(),
            "198.51.100.9:51001".parse().unwrap()
        );
        assert_eq!(reader, b"\x16");

        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0, 0]);
        assert_eq!(read(&mut local.as_slice(), peer()).await.unwrap(), peer());
    }

    #[tokio::test]
    async fn a_connection_without_a_header_or_with_a_bad_one_is_refused() {
        assert!(
            read(
                &mut &b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x00"[..],
                peer()
            )
            .await
            .is_err()
        );
        assert!(
            read(&mut &b"PROXY TCP4 nonsense\r\n"[..], peer())
                .await
                .is_err()
        );
        let mut long = V2_SIGNATURE.to_vec();
        long.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        assert!(read(&mut long.as_slice(), peer()).await.is_err());
    }

    #[test]
    fn sources_match_by_network_and_mapped_addresses_count() {
        let net: Source = "10.0.9.0/24".parse().unwrap();
        assert!(net.contains("10.0.9.1".parse().unwrap()));
        assert!(net.contains("::ffff:10.0.9.200".parse().unwrap()));
        assert!(!net.contains("10.0.10.1".parse().unwrap()));
        let one: Source = "172.17.64.2".parse().unwrap();
        assert!(
            one.contains("172.17.64.2".parse().unwrap())
                && !one.contains("172.17.64.3".parse().unwrap())
        );
        assert!("10.0.9.0/33".parse::<Source>().is_err());
        assert!("gateway".parse::<Source>().is_err());
    }
}
