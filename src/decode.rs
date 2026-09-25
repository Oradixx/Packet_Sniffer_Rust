//! Turns raw captured bytes into a one-line summary (addresses, protocol, details).
//!
//! This module has no dependency on pcap or on the terminal, so it can be unit tested
//! with hand-built packets.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{
    ArpOperation, EtherType, Icmpv4Type, LinkHeader, NetHeaders, PacketHeaders, TransportHeader,
};

/// Link-layer header types (values of pcap's `DLT_*` / `LINKTYPE_*` constants).
pub mod linktype {
    /// BSD loopback: 4-byte address family, then the IP packet (macOS `lo0`).
    pub const NULL: i32 = 0;
    pub const ETHERNET: i32 = 1;
    pub const RAW: i32 = 101;
    /// OpenBSD loopback: same layout as NULL, family in network byte order.
    pub const LOOP: i32 = 108;
    /// Linux "cooked" capture (the `any` pseudo-interface): 16-byte header.
    pub const LINUX_SLL: i32 = 113;
    /// Linux "cooked" capture v2 (newer libpcap for `any`): 20-byte header.
    pub const LINUX_SLL2: i32 = 276;
    pub const IPV4: i32 = 228;
    pub const IPV6: i32 = 229;
}

/// Protocol family, used by the display to pick a color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Other,
}

/// One-line description of a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
    pub kind: Kind,
}

/// Decodes a captured frame. Returns `None` when the link type is not supported or the
/// packet cannot be parsed.
pub fn decode(link_type: i32, data: &[u8]) -> Option<Summary> {
    let headers = match link_type {
        linktype::ETHERNET => PacketHeaders::from_ethernet_slice(data).ok()?,
        linktype::NULL | linktype::LOOP => PacketHeaders::from_ip_slice(data.get(4..)?).ok()?,
        linktype::RAW | linktype::IPV4 | linktype::IPV6 => {
            PacketHeaders::from_ip_slice(data).ok()?
        }
        linktype::LINUX_SLL => {
            let protocol = u16::from_be_bytes([*data.get(14)?, *data.get(15)?]);
            PacketHeaders::from_ether_type(EtherType(protocol), data.get(16..)?).ok()?
        }
        linktype::LINUX_SLL2 => {
            let protocol = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            PacketHeaders::from_ether_type(EtherType(protocol), data.get(20..)?).ok()?
        }
        _ => return None,
    };
    Some(summarize(&headers))
}

fn summarize(headers: &PacketHeaders) -> Summary {
    let (mut source, mut destination) = match &headers.net {
        Some(NetHeaders::Ipv4(ip, _)) => (
            Ipv4Addr::from(ip.source).to_string(),
            Ipv4Addr::from(ip.destination).to_string(),
        ),
        Some(NetHeaders::Ipv6(ip, _)) => (
            Ipv6Addr::from(ip.source).to_string(),
            Ipv6Addr::from(ip.destination).to_string(),
        ),
        Some(NetHeaders::Arp(_)) | None => match &headers.link {
            Some(LinkHeader::Ethernet2(eth)) => (mac(&eth.source), mac(&eth.destination)),
            _ => ("?".to_string(), "?".to_string()),
        },
    };
    let is_ipv6 = matches!(headers.net, Some(NetHeaders::Ipv6(..)));
    let payload_len = headers.payload.slice().len();

    let (protocol, info, kind) = match &headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            source = with_port(&source, tcp.source_port, is_ipv6);
            destination = with_port(&destination, tcp.destination_port, is_ipv6);
            let mut flags = Vec::new();
            for (set, name) in [
                (tcp.syn, "SYN"),
                (tcp.fin, "FIN"),
                (tcp.rst, "RST"),
                (tcp.psh, "PSH"),
                (tcp.ack, "ACK"),
            ] {
                if set {
                    flags.push(name);
                }
            }
            let mut info = format!("[{}] len={payload_len}", flags.join(", "));
            if let Some(service) = service(tcp.source_port, tcp.destination_port) {
                info = format!("{service} {info}");
            }
            ("TCP".to_string(), info, Kind::Tcp)
        }
        Some(TransportHeader::Udp(udp)) => {
            source = with_port(&source, udp.source_port, is_ipv6);
            destination = with_port(&destination, udp.destination_port, is_ipv6);
            let mut info = format!("len={payload_len}");
            if let Some(service) = service(udp.source_port, udp.destination_port) {
                info = format!("{service} {info}");
            }
            ("UDP".to_string(), info, Kind::Udp)
        }
        Some(TransportHeader::Icmpv4(icmp)) => {
            let info = match &icmp.icmp_type {
                Icmpv4Type::EchoRequest(echo) => {
                    format!("echo request id={} seq={}", echo.id, echo.seq)
                }
                Icmpv4Type::EchoReply(echo) => {
                    format!("echo reply id={} seq={}", echo.id, echo.seq)
                }
                Icmpv4Type::DestinationUnreachable(_) => "destination unreachable".to_string(),
                Icmpv4Type::TimeExceeded(_) => "time exceeded".to_string(),
                _ => {
                    let bytes = icmp.to_bytes();
                    format!("type={} code={}", bytes[0], bytes[1])
                }
            };
            ("ICMP".to_string(), info, Kind::Icmp)
        }
        Some(TransportHeader::Icmpv6(icmp)) => {
            let info = match icmp.icmp_type.type_u8() {
                128 => "echo request".to_string(),
                129 => "echo reply".to_string(),
                133 => "router solicitation".to_string(),
                134 => "router advertisement".to_string(),
                135 => "neighbor solicitation".to_string(),
                136 => "neighbor advertisement".to_string(),
                t => format!("type={t} code={}", icmp.icmp_type.code_u8()),
            };
            ("ICMPv6".to_string(), info, Kind::Icmp)
        }
        None => match &headers.net {
            Some(NetHeaders::Arp(arp)) => {
                let info = match arp.try_eth_ipv4() {
                    Ok(p) if p.operation == ArpOperation::REQUEST => {
                        source = Ipv4Addr::from(p.sender_ipv4).to_string();
                        destination = Ipv4Addr::from(p.target_ipv4).to_string();
                        format!("who has {destination}? tell {source}")
                    }
                    Ok(p) if p.operation == ArpOperation::REPLY => {
                        source = Ipv4Addr::from(p.sender_ipv4).to_string();
                        destination = Ipv4Addr::from(p.target_ipv4).to_string();
                        format!("{source} is at {}", mac(&p.sender_mac))
                    }
                    _ => format!("operation {}", arp.operation.0),
                };
                ("ARP".to_string(), info, Kind::Arp)
            }
            Some(NetHeaders::Ipv4(ip, _)) => (
                "IPv4".to_string(),
                format!("protocol {}", ip.protocol.0),
                Kind::Other,
            ),
            Some(NetHeaders::Ipv6(ip, _)) => (
                "IPv6".to_string(),
                format!("next header {}", ip.next_header.0),
                Kind::Other,
            ),
            None => {
                let ether_type = match &headers.link {
                    Some(LinkHeader::Ethernet2(eth)) => format!("0x{:04x}", eth.ether_type.0),
                    _ => "?".to_string(),
                };
                (
                    format!("ETH {ether_type}"),
                    format!("len={payload_len}"),
                    Kind::Other,
                )
            }
        },
    };

    Summary {
        source,
        destination,
        protocol,
        info,
        kind,
    }
}

/// Name of a well-known service on either port, if any.
fn service(source_port: u16, destination_port: u16) -> Option<&'static str> {
    let name = |port| match port {
        22 => Some("SSH"),
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        80 => Some("HTTP"),
        123 => Some("NTP"),
        443 => Some("HTTPS"),
        1900 => Some("SSDP"),
        5353 => Some("mDNS"),
        _ => None,
    };
    name(destination_port).or_else(|| name(source_port))
}

fn with_port(address: &str, port: u16, is_ipv6: bool) -> String {
    if is_ipv6 {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Hex dump of the first `max_bytes` bytes: offset, 16 hex bytes, then the ASCII view.
pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    let shown = &data[..data.len().min(max_bytes)];
    for (i, chunk) in shown.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let _ = writeln!(
            out,
            "      {:04x}  {:<47}  {}",
            i * 16,
            hex.join(" "),
            ascii
        );
    }
    if data.len() > max_bytes {
        let _ = writeln!(out, "      ... ({} more bytes)", data.len() - max_bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{ArpHardwareId, ArpPacket, PacketBuilder};

    const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
    const IP_A: [u8; 4] = [192, 168, 1, 10];
    const IP_B: [u8; 4] = [93, 184, 216, 34];

    #[test]
    fn tcp_syn_over_ethernet() {
        let builder = PacketBuilder::ethernet2(MAC_A, MAC_B)
            .ipv4(IP_A, IP_B, 64)
            .tcp(51234, 443, 1000, 64240)
            .syn();
        let mut bytes = Vec::with_capacity(builder.size(0));
        builder.write(&mut bytes, &[]).unwrap();

        let s = decode(linktype::ETHERNET, &bytes).unwrap();
        assert_eq!(s.source, "192.168.1.10:51234");
        assert_eq!(s.destination, "93.184.216.34:443");
        assert_eq!(s.protocol, "TCP");
        assert_eq!(s.info, "HTTPS [SYN] len=0");
        assert_eq!(s.kind, Kind::Tcp);
    }

    #[test]
    fn udp_dns_with_payload() {
        let builder = PacketBuilder::ethernet2(MAC_A, MAC_B)
            .ipv4(IP_A, [1, 1, 1, 1], 64)
            .udp(40000, 53);
        let payload = [0u8; 29];
        let mut bytes = Vec::new();
        builder.write(&mut bytes, &payload).unwrap();

        let s = decode(linktype::ETHERNET, &bytes).unwrap();
        assert_eq!(s.destination, "1.1.1.1:53");
        assert_eq!(s.protocol, "UDP");
        assert_eq!(s.info, "DNS len=29");
    }

    #[test]
    fn icmp_echo_on_macos_loopback() {
        // macOS lo0 uses the NULL link type: 4-byte address family (AF_INET = 2), then IPv4
        let builder =
            PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64).icmpv4_echo_request(7, 3);
        let mut bytes = vec![2, 0, 0, 0];
        builder.write(&mut bytes, &[]).unwrap();

        let s = decode(linktype::NULL, &bytes).unwrap();
        assert_eq!(s.source, "127.0.0.1");
        assert_eq!(s.protocol, "ICMP");
        assert_eq!(s.info, "echo request id=7 seq=3");
        assert_eq!(s.kind, Kind::Icmp);
    }

    #[test]
    fn linux_cooked_captures() {
        let builder = PacketBuilder::ipv4(IP_A, IP_B, 64).udp(40000, 123);
        let mut ip = Vec::new();
        builder.write(&mut ip, &[]).unwrap();

        // SLL: 14 bytes of packet type / address fields, then the protocol (0x0800 = IPv4)
        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&[0x08, 0x00]);
        sll.extend_from_slice(&ip);
        // SLL2: protocol first, then 18 more bytes
        let mut sll2 = vec![0x08, 0x00];
        sll2.extend_from_slice(&[0u8; 18]);
        sll2.extend_from_slice(&ip);

        for (link_type, frame) in [(linktype::LINUX_SLL, sll), (linktype::LINUX_SLL2, sll2)] {
            let s = decode(link_type, &frame).unwrap();
            assert_eq!(s.destination, "93.184.216.34:123");
            assert_eq!(s.info, "NTP len=0");
        }
    }

    #[test]
    fn ipv6_udp_uses_brackets() {
        let builder = PacketBuilder::ipv6(
            Ipv6Addr::LOCALHOST.octets(),
            Ipv6Addr::LOCALHOST.octets(),
            64,
        )
        .udp(5353, 5353);
        let mut bytes = Vec::new();
        builder.write(&mut bytes, &[]).unwrap();

        let s = decode(linktype::RAW, &bytes).unwrap();
        assert_eq!(s.source, "[::1]:5353");
        assert_eq!(s.info, "mDNS len=0");
    }

    #[test]
    fn arp_request() {
        let arp = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REQUEST,
            &MAC_A,
            &IP_A,
            &[0; 6],
            &[192, 168, 1, 1],
        )
        .unwrap();
        let builder = PacketBuilder::ethernet2(MAC_A, [0xff; 6]).arp(arp);
        let mut bytes = Vec::new();
        builder.write(&mut bytes).unwrap();

        let s = decode(linktype::ETHERNET, &bytes).unwrap();
        assert_eq!(s.protocol, "ARP");
        assert_eq!(s.info, "who has 192.168.1.1? tell 192.168.1.10");
        assert_eq!(s.kind, Kind::Arp);
    }

    #[test]
    fn unknown_link_type_and_garbage_are_skipped() {
        assert_eq!(decode(9999, &[0; 64]), None);
        assert_eq!(decode(linktype::ETHERNET, &[0x01, 0x02]), None);
    }

    #[test]
    fn hex_dump_shows_ascii_and_truncates() {
        let data: Vec<u8> = b"GET / HTTP/1.1\r\nHost".to_vec();
        let dump = hex_dump(&data, 16);
        assert!(dump.contains("0000  47 45 54 20"));
        assert!(dump.contains("GET / HTTP/1.1.."));
        assert!(dump.contains("... (4 more bytes)"));
    }
}
