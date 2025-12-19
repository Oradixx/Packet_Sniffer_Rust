use clap::Parser;
use crossterm::style::{Color, SetForegroundColor, ResetColor};
use etherparse::{PacketHeaders, NetHeaders, TransportHeader};
use pcap::{Device, Capture};
use std::io::{self, Write};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    interface: Option<String>,

    #[arg(short = 'x', long)]
    hex: bool,
}

fn main() {
    let args = Cli::parse();

    if args.interface.is_none() {
        list_interfaces();
        return;
    }

    let interface_name = args.interface.unwrap();
    println!("Tentative de capture sur : {}", interface_name);

    let devices = Device::list().expect("Erreur lors du listage des interfaces");
    let device = devices.into_iter()
        .find(|d| d.name == interface_name)
        .expect("Interface introuvable ! Vérifiez le nom avec --list (ou lancez sans argument)");

    let mut cap = Capture::from_device(device).unwrap()
        .promisc(true)
        .snaplen(5000)
        .timeout(1000)
        .open().unwrap();

    println!("🚀 Sniffer démarré ! (Ctrl+C pour arrêter)\n");
    println!("{:<20} | {:<20} | {:<20} | {:<10} | Info", "Source", "Destination", "Protocol", "Size");
    println!("{}", "-".repeat(100));

    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet, args.hex);
    }
}

fn list_interfaces() {
    println!("Interfaces disponibles :");
    let devices = Device::list().expect("Impossible de lister les interfaces");
    
    for device in devices {
        print!(" -Name: {:<20}", device.name);
        if let Some(desc) = device.desc {
            print!(" (Desc: {})", desc);
        }
        println!();
    }
    println!("\nUsage: cargo run -- --interface <NOM_EXACT>");
}

fn process_packet(packet: &pcap::Packet, show_hex: bool) {
    match PacketHeaders::from_ethernet_slice(packet.data) {
        Err(_) => {
        },
        Ok(headers) => {
            let mut src_str = String::from("?");
            let mut dst_str = String::from("?");
            let mut proto_str = String::from("Unknown");
            
            let mut color = Color::White;

            if let Some(net) = headers.net {
                match net {
                    NetHeaders::Ipv4(ipv4, _) => {
                        src_str = format!("{:?}", ipv4.source);
                        dst_str = format!("{:?}", ipv4.destination);
                        color = Color::Green;
                    },
                    NetHeaders::Ipv6(ipv6, _) => {
                        src_str = format!("{:?}", ipv6.source);
                        dst_str = format!("{:?}", ipv6.destination);
                        color = Color::Blue;
                    },
                    NetHeaders::Arp(_) => {
                        src_str = "ARP".to_string();
                        dst_str = "ARP".to_string();
                        proto_str = "ARP".to_string();
                        color = Color::Magenta;
                    }
                }
            }

            if let Some(transport) = headers.transport {
                match transport {
                    TransportHeader::Tcp(tcp) => {
                        proto_str = format!("TCP :{}", tcp.destination_port);
                        color = Color::Cyan;
                    },
                    TransportHeader::Udp(udp) => {
                        proto_str = format!("UDP :{}", udp.destination_port);
                        color = Color::Yellow;
                    },
                    TransportHeader::Icmpv4(_) => {
                        proto_str = "ICMP".to_string();
                        color = Color::Red;
                    },
                    TransportHeader::Icmpv6(_) => {
                        proto_str = "ICMPv6".to_string();
                        color = Color::Magenta;
                    }
                }
            }

            print_colored(color, &format!("{:<20} | {:<20} | {:<20} | {:<10} bytes", 
                src_str, dst_str, proto_str, packet.header.len));

            if show_hex {
                print_hex_dump(packet.data);
            }
        }
    }
}

fn print_colored(color: Color, text: &str) {
    let mut stdout = io::stdout();
    let _ = crossterm::queue!(stdout, SetForegroundColor(color));
    let _ = writeln!(stdout, "{}", text);
    let _ = crossterm::queue!(stdout, ResetColor);
    let _ = stdout.flush();
}

fn print_hex_dump(data: &[u8]) {
    let mut i = 0;
    for chunk in data.chunks(16) {
        print!("      {:04x}  ", i);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        println!();
        i += 16;
        if i > 64 {
            println!("      ...");
            break;
        }
    }
}