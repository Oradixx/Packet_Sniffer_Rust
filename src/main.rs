mod decode;

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use pcap::{Capture, Device};

use decode::{Kind, Summary};

/// Capture network packets on an interface and print a one-line summary of each one.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Interface to capture on (see --list). Without it, the available interfaces are listed.
    #[arg(short, long)]
    interface: Option<String>,

    /// List the available interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// BPF filter, same syntax as tcpdump (e.g. "tcp port 443", "udp", "host 1.1.1.1")
    #[arg(short, long)]
    filter: Option<String>,

    /// Stop after this many packets
    #[arg(short, long)]
    count: Option<u64>,

    /// Show the first 64 bytes of each packet in hexadecimal
    #[arg(short = 'x', long)]
    hex: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match (&cli.interface, cli.list) {
        (Some(interface), false) => capture(interface, &cli),
        _ => list_interfaces(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("Error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn list_interfaces() -> Result<(), String> {
    let devices = Device::list().map_err(|e| format!("cannot list interfaces: {e}"))?;
    println!("Available interfaces:");
    for device in devices {
        match device.desc {
            Some(desc) => println!("  {:<24} {desc}", device.name),
            None => println!("  {}", device.name),
        }
    }
    println!("\nUsage: packet-sniffer --interface <NAME>");
    Ok(())
}

fn capture(interface: &str, cli: &Cli) -> Result<(), String> {
    let device = Device::list()
        .map_err(|e| format!("cannot list interfaces: {e}"))?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| format!("interface '{interface}' not found (run with --list)"))?;

    let mut cap = Capture::from_device(device)
        .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open())
        .map_err(|e| {
            format!("cannot open '{interface}': {e}\nCapturing usually needs admin rights: try with sudo.")
        })?;

    if let Some(filter) = &cli.filter {
        cap.filter(filter, true)
            .map_err(|e| format!("invalid filter '{filter}': {e}"))?;
    }

    let link_type = cap.get_datalink().0;
    let use_color = io::stdout().is_terminal();

    println!("Capturing on {interface} (Ctrl+C to stop)\n");
    println!(
        "{:>9}  {:<24} {:<24} {:<8} {:>6}  Info",
        "Time", "Source", "Destination", "Protocol", "Length"
    );
    println!("{}", "-".repeat(100));

    let mut start: Option<f64> = None;
    let mut seen = 0u64;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1e6;
                let elapsed = ts - *start.get_or_insert(ts);
                if let Some(summary) = decode::decode(link_type, packet.data) {
                    print_line(elapsed, &summary, packet.header.len, use_color);
                    if cli.hex {
                        print!("{}", decode::hex_dump(packet.data, 64));
                    }
                }
                seen += 1;
                if cli.count.is_some_and(|max| seen >= max) {
                    break;
                }
            }
            // The read timeout only means "no packet during the last second": keep waiting
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(format!("capture stopped: {e}")),
        }
    }
    println!("\n{seen} packets captured");
    Ok(())
}

fn print_line(elapsed: f64, s: &Summary, length: u32, use_color: bool) {
    let line = format!(
        "{elapsed:>9.3}  {:<24} {:<24} {:<8} {length:>6}  {}",
        s.source, s.destination, s.protocol, s.info
    );
    let mut stdout = io::stdout().lock();
    if use_color {
        let color = match s.kind {
            Kind::Tcp => Color::Cyan,
            Kind::Udp => Color::Yellow,
            Kind::Icmp => Color::Red,
            Kind::Arp => Color::Magenta,
            Kind::Other => Color::White,
        };
        let _ = crossterm::queue!(stdout, SetForegroundColor(color));
        let _ = writeln!(stdout, "{line}");
        let _ = crossterm::queue!(stdout, ResetColor);
    } else {
        let _ = writeln!(stdout, "{line}");
    }
    let _ = stdout.flush();
}
