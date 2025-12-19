Packet Sniffer Rust

Project - Rust Bootcamp

A network packet capture and analysis tool developed in Rust. This program allows you to intercept traffic (TCP, UDP, ICMP, ARP) in real-time and visualize the details in the terminal with a colored interface.

👥 Authors

Clément VURPILLOT @0radixx
Noé SPYCHALA


🚀 Features

Automatic detection of available network interfaces.

Real-time capture (Promiscuous Mode).

Multi-layer analysis: Ethernet -> IP (v4/v6) -> Transport.

Protocol support: TCP, UDP, ICMP, ARP.

Colored output for quick traffic distinction.

Hexdump mode (-x) for raw packet inspection.

🛠️ Installation & Requirements

Requirements

Rust & Cargo: Install Rust

Windows: Install Npcap.

⚠️ IMPORTANT: Check the "Install Npcap in WinPcap API-compatible Mode" option during installation.

If link error (wpcap.lib), set the environment variable to the Npcap SDK path.

Linux: Install libpcap-dev (sudo apt install libpcap-dev).

Compilation

cargo build --release

💻 Usage

1. List interfaces

Displays all available network adapters on the machine.

cargo run

2. Start capture

Copy the exact interface name (e.g., \Device\NPF_{...} on Windows or eth0 on Linux).
(Use quotes if the name contains spaces or braces)

cargo run -- --interface "\Device\NPF_{INTERFACE_GUID}"

3. Advanced options

-x or --hex: Displays raw packet content (payload) in hexadecimal.

cargo run -- --interface "..." -x

⚠️ Legal Warning

Please read carefully:
This tool is developed strictly for educational and defensive purposes. Intercepting network traffic on third-party systems without explicit authorization is illegal and punishable by law.
The author disclaims any responsibility for malicious use of this software. Use it only on your own networks.

Project completed for Rust Bootcamp - December 2025
