# Packet Sniffer (Rust)

A command-line network packet sniffer written in Rust: it captures live traffic on an interface with libpcap and prints one line per packet, with addresses, ports, protocol and details (TCP flags, well-known services, ICMP types, ARP requests).

Project from the Rust Bootcamp (December 2025), reworked in September 2026.

[![CI](https://github.com/Oradixx/Packet_Sniffer_Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Oradixx/Packet_Sniffer_Rust/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust&logoColor=white)

```
$ sudo ./target/release/packet-sniffer -i lo -c 6
Capturing on lo (Ctrl+C to stop)

     Time  Source                   Destination              Protocol Length  Info
----------------------------------------------------------------------------------------------------
    0.000  127.0.0.1:52852          127.0.0.1:8443           TCP          74  [SYN] len=0
    0.000  127.0.0.1:8443           127.0.0.1:52852          TCP          74  [SYN, ACK] len=0
    0.000  127.0.0.1:52852          127.0.0.1:8443           TCP          66  [ACK] len=0
    0.000  127.0.0.1:52852          127.0.0.1:8443           TCP          71  [PSH, ACK] len=5
    0.000  127.0.0.1:8443           127.0.0.1:52852          TCP          66  [ACK] len=0
    0.000  127.0.0.1:8443           127.0.0.1:52852          TCP          66  [FIN, ACK] len=0

6 packets captured
```

*A TCP connection on the loopback interface: handshake, 5 bytes of data, then the close.*

## Features

- **Live capture** on any interface, in promiscuous mode, with the list of available interfaces.
- **Decoding** of Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 and ARP (with [etherparse](https://crates.io/crates/etherparse)).
- **Details per protocol**:
  - TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`) and payload size;
  - well-known services (DNS, HTTP, HTTPS, SSH, NTP, DHCP, mDNS, SSDP);
  - ICMP echo request / reply with id and sequence number;
  - ARP requests and replies (`who has 192.168.1.1? tell 192.168.1.10`).
- **Several link types**: Ethernet, BSD loopback (macOS `lo0`), raw IP, and Linux "cooked" captures (`any` interface).
- **BPF filters** with the tcpdump syntax (`-f "tcp port 443"`), computed in the kernel by libpcap.
- **Hex dump** of the first 64 bytes of each packet, with an ASCII column (`-x`).
- **Colors** by protocol in a terminal, plain text when the output is redirected to a file.

## Installation

Requires [Rust](https://rustup.rs) and libpcap:

| OS | libpcap |
|---|---|
| macOS | already installed |
| Linux | `sudo apt install libpcap-dev` (Debian/Ubuntu) |
| Windows | [Npcap](https://npcap.com), with "WinPcap API-compatible Mode" checked. If the build fails on `wpcap.lib`, set the `LIB` environment variable to the Npcap SDK `Lib/x64` folder. |

```bash
git clone https://github.com/Oradixx/Packet_Sniffer_Rust.git
cd Packet_Sniffer_Rust
cargo build --release
```

## Usage

Capturing packets needs administrator rights (`sudo` on macOS and Linux).

```bash
./target/release/packet-sniffer --list
sudo ./target/release/packet-sniffer -i en0
sudo ./target/release/packet-sniffer -i en0 -f "udp port 53" -c 20
sudo ./target/release/packet-sniffer -i en0 -f "tcp port 443" -x
```

| Option | Effect |
|---|---|
| `-i, --interface <NAME>` | interface to capture on (without it, the interfaces are listed) |
| `-l, --list` | list the available interfaces |
| `-f, --filter <BPF>` | capture filter, tcpdump syntax |
| `-c, --count <N>` | stop after N packets |
| `-x, --hex` | hex dump of the first 64 bytes |

On Windows, interface names look like `\Device\NPF_{GUID}`: copy the exact name from `--list` and put it in quotes.

## Code structure

```
src/
├── main.rs     # command line (clap), capture loop (pcap), display
└── decode.rs   # bytes → summary: link types, addresses, protocol details, hex dump
```

`decode.rs` does not depend on pcap or the terminal. Its unit tests build packets with etherparse's `PacketBuilder` (TCP, UDP, ICMP, IPv6, ARP, loopback and Linux cooked captures), so they run without network access or admin rights:

```bash
cargo test
```

CI runs `cargo fmt --check`, `cargo clippy -D warnings`, the tests and a release build on every push.

## Legal notice

This tool is for learning and for analyzing **your own networks**. Capturing traffic on a network without the explicit permission of its owner is illegal in most countries.

## Authors

- **Clément Vurpillot** — [@Oradixx](https://github.com/Oradixx)
- **Noé Spychala**

Licensed under the [MIT License](LICENSE).
