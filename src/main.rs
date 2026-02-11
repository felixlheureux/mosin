mod cli;
mod constants;
mod module;

use std::net::IpAddr;
use std::path::Path;

use clap::Parser;
use cli::{Cli, Commands};
use dns_parser::Packet as DnsPacket;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use constants::{
    DNS_PORT, DOH_DOMAINS_URL, DOH_IPS_URL, HTTPS_PORT, PACKET_BUFFER_SIZE, TUN_DEVICE_NAME,
};
use module::blocklist::Blocklist;
use module::doh::{DohBlocker, extract_sni};
use module::sinkhole::{forge_nxdomain, forge_tcp_rst};

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Start {
            blocklist,
            ip_blocklist,
            block_doh,
            doh_ips,
            doh_domains,
            verbose,
            quiet,
        } => {
            run_start(
                blocklist,
                ip_blocklist,
                block_doh,
                doh_ips,
                doh_domains,
                verbose,
                quiet,
            )
            .await;
        }
        Commands::Status => {
            println!("Status: not yet implemented");
        }
        Commands::Stop => {
            println!("Stop: not yet implemented");
        }
    }
}

async fn run_start(
    blocklists: Vec<String>,
    ip_blocklists: Vec<String>,
    block_doh: bool,
    doh_ips_file: String,
    doh_domains_file: String,
    verbose: bool,
    quiet: bool,
) {
    // --- Load blocklists ---
    let mut bl = Blocklist::new();

    for path in &blocklists {
        match bl.load_domain_file(Path::new(path)) {
            Ok(count) => {
                if !quiet {
                    println!("[+] Loaded {} domains from {}", count, path);
                }
            }
            Err(e) => eprintln!("[!] Failed to load domain blocklist {}: {}", path, e),
        }
    }

    for path in &ip_blocklists {
        match bl.load_ip_file(Path::new(path)) {
            Ok(count) => {
                if !quiet {
                    println!("[+] Loaded {} IP/CIDRs from {}", count, path);
                }
            }
            Err(e) => eprintln!("[!] Failed to load IP blocklist {}: {}", path, e),
        }
    }

    if bl.domains.is_empty() && !blocklists.is_empty() {
        eprintln!("[!] Warning: loaded blocklists but no domains were added");
    }

    // --- Load DoH blocker ---
    let doh_blocker = if block_doh {
        match DohBlocker::from_files(Path::new(&doh_ips_file), Path::new(&doh_domains_file)) {
            Ok(blocker) => {
                if !quiet {
                    println!(
                        "[+] DoH blocking enabled: {} IPs, {} hostnames",
                        blocker.ip_count(),
                        blocker.hostname_count()
                    );
                }
                Some(blocker)
            }
            Err(e) => {
                eprintln!("[!] Failed to load DoH blocklists: {}", e);
                eprintln!("    mkdir -p lists");
                eprintln!("    curl -o {} {}", doh_ips_file, DOH_IPS_URL);
                eprintln!("    curl -o {} {}", doh_domains_file, DOH_DOMAINS_URL);
                None
            }
        }
    } else {
        None
    };

    if !quiet {
        println!("[*] Total blocked domains: {}", bl.domains.len());
        println!("[*] Starting mosin...");
    }

    // --- Start TUN device ---
    let mut device = match module::device::start_device().await {
        Ok(d) => {
            if !quiet {
                println!("[*] TUN device {} started", TUN_DEVICE_NAME);
            }
            d
        }
        Err(e) => {
            eprintln!("[!] Failed to start TUN device: {}", e);
            return;
        }
    };

    if !quiet {
        println!("[*] Shield active. Listening for packets...");
    }

    let mut buffer = [0u8; PACKET_BUFFER_SIZE];

    loop {
        let n = match device.read(&mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[!] Read error: {}", e);
                break;
            }
        };

        let raw_packet = &buffer[..n];

        // Parse IP headers
        let packet = match PacketHeaders::from_ip_slice(raw_packet) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Extract destination IP
        let dst_ip: Option<IpAddr> = match &packet.net {
            Some(NetHeaders::Ipv4(h, _)) => {
                Some(IpAddr::V4(std::net::Ipv4Addr::from(h.destination)))
            }
            _ => None,
        };

        match &packet.transport {
            // ===== UDP Port 53 — DNS Sinkhole =====
            Some(TransportHeader::Udp(udp))
                if udp.destination_port == DNS_PORT || udp.source_port == DNS_PORT =>
            {
                let payload = packet.payload.slice();
                if payload.is_empty() {
                    continue;
                }

                match DnsPacket::parse(payload) {
                    Ok(dns) => {
                        for question in &dns.questions {
                            let domain = question.qname.to_string();

                            if bl.is_domain_blocked(&domain) {
                                if verbose {
                                    println!("[DNS BLOCKED] {} -> NXDOMAIN", domain);
                                }

                                // Forge NXDOMAIN and send it back
                                if let Some(nxdomain) = forge_nxdomain(raw_packet)
                                    && let Err(e) = device.write_all(&nxdomain).await
                                {
                                    eprintln!("[!] Failed to write NXDOMAIN: {}", e);
                                }
                            } else if verbose {
                                println!("[DNS PASS] {}", domain);
                            }
                        }
                    }
                    Err(e) => {
                        if verbose {
                            eprintln!("[!] DNS parse error: {}", e);
                        }
                    }
                }
            }

            // ===== TCP — DoH Blocking + IP Blocking =====
            Some(TransportHeader::Tcp(tcp)) => {
                let dst = match dst_ip {
                    Some(ip) => ip,
                    None => continue,
                };

                // Check if destination port is 443 (HTTPS / DoH)
                if tcp.destination_port == HTTPS_PORT
                    && let Some(ref doh) = doh_blocker
                {
                    // --- DoH IP blocking ---
                    if doh.is_doh_ip(dst) {
                        if verbose {
                            println!("[DoH BLOCKED] IP {} -> RST", dst);
                        }
                        if let Some(rst) = forge_tcp_rst(raw_packet) {
                            let _ = device.write_all(&rst).await;
                        }
                        continue;
                    }

                    // --- DoH SNI blocking ---
                    let tcp_payload = packet.payload.slice();
                    if !tcp_payload.is_empty()
                        && let Some(sni) = extract_sni(tcp_payload)
                        && doh.is_doh_hostname(&sni)
                    {
                        if verbose {
                            println!("[DoH BLOCKED] SNI {} -> RST", sni);
                        }
                        if let Some(rst) = forge_tcp_rst(raw_packet) {
                            let _ = device.write_all(&rst).await;
                        }
                        continue;
                    }
                }

                // --- General IP blocking (TCP) ---
                if bl.is_ip_blocked(dst) {
                    if verbose {
                        println!("[IP BLOCKED] {} -> RST", dst);
                    }
                    if let Some(rst) = forge_tcp_rst(raw_packet) {
                        let _ = device.write_all(&rst).await;
                    }
                    continue;
                }
            }

            // ===== UDP (non-DNS) — IP Blocking =====
            Some(TransportHeader::Udp(_)) => {
                if let Some(dst) = dst_ip
                    && bl.is_ip_blocked(dst)
                {
                    if verbose {
                        println!("[IP BLOCKED] {} (UDP drop)", dst);
                    }
                    // UDP has no RST — silent drop is the only option
                    continue;
                }
            }

            _ => {}
        }
    }
}
