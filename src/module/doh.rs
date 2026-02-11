/// DoH Bypass Prevention — blocks known DNS-over-HTTPS providers.
///
/// Prevents applications from bypassing the DNS sinkhole by using DoH.
/// Two mechanisms:
/// 1. Block TCP port 443 to known DoH resolver IPs (loaded from file)
/// 2. Extract SNI from TLS ClientHello and block known DoH hostnames (loaded from file)
///
/// Uses external lists from dibdot/DoH-IP-blocklists (updated hourly).
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::Path;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use super::blocklist::DomainTrie;

/// DoH blocker backed by external blocklist files.
///
/// Uses `IpNetworkTable` (radix tree) for IP lookups and `DomainTrie` for
/// hostname matching — both are O(1) relative to list size.
pub struct DohBlocker {
    ips: IpNetworkTable<()>,
    hostnames: DomainTrie,
    ip_count: usize,
    hostname_count: usize,
}

impl DohBlocker {
    /// Create a new DohBlocker by loading IP and domain lists from files.
    ///
    /// Files are read line-by-line via `BufRead` to avoid loading the entire
    /// file into memory at once.
    pub fn from_files(
        ip_file: &Path,
        domain_file: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ips = IpNetworkTable::new();
        let mut ip_count = 0;

        let ip_reader = io::BufReader::new(std::fs::File::open(ip_file)?);
        for line in ip_reader.lines() {
            let line = line?;
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Format: "1.0.0.1             # comment" — extract just the IP
            let ip_str = line.split_whitespace().next().unwrap_or("");
            let ip_str = ip_str.split('#').next().unwrap_or("").trim();
            if ip_str.is_empty() {
                continue;
            }
            if let Ok(network) = ip_str.parse::<IpNetwork>() {
                ips.insert(network, ());
                ip_count += 1;
            } else if let Ok(ip) = ip_str.parse::<IpAddr>() {
                ips.insert(IpNetwork::from(ip), ());
                ip_count += 1;
            }
        }

        let mut hostnames = DomainTrie::new();
        let mut hostname_count = 0;

        let domain_reader = io::BufReader::new(std::fs::File::open(domain_file)?);
        for line in domain_reader.lines() {
            let line = line?;
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            hostnames.insert(&line);
            hostname_count += 1;
        }

        Ok(Self {
            ips,
            hostnames,
            ip_count,
            hostname_count,
        })
    }

    pub fn ip_count(&self) -> usize {
        self.ip_count
    }

    pub fn hostname_count(&self) -> usize {
        self.hostname_count
    }

    /// Check if a destination IP is a known DoH resolver.
    pub fn is_doh_ip(&self, ip: IpAddr) -> bool {
        self.ips.longest_match(ip).is_some()
    }

    /// Check if an SNI hostname matches a known DoH provider.
    ///
    /// Uses `DomainTrie` for O(label_count) lookup with automatic subdomain
    /// matching — no linear scan over the entire hostname list.
    pub fn is_doh_hostname(&self, sni: &str) -> bool {
        self.hostnames.is_blocked(sni)
    }
}

/// Extract the SNI (Server Name Indication) from a TLS ClientHello in a TCP payload.
///
/// Returns `None` if the payload is not a valid TLS ClientHello or has no SNI extension.
pub fn extract_sni(tcp_payload: &[u8]) -> Option<String> {
    use tls_parser::{TlsMessage, TlsMessageHandshake, parse_tls_plaintext};

    if tcp_payload.is_empty() || tcp_payload[0] != 0x16 {
        return None;
    }

    let (_, tls_record) = parse_tls_plaintext(tcp_payload).ok()?;

    for msg in &tls_record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg
            && let Some(ext_data) = ch.ext
        {
            return parse_sni_from_extensions(ext_data);
        }
    }

    None
}

/// Parse SNI from raw TLS extension bytes. SNI extension type = 0x0000.
fn parse_sni_from_extensions(ext_data: &[u8]) -> Option<String> {
    let mut pos = 0;

    while pos + 4 <= ext_data.len() {
        let ext_type = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]);
        let ext_len = u16::from_be_bytes([ext_data[pos + 2], ext_data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_data.len() {
            break;
        }

        if ext_type == 0x0000 && ext_len >= 5 {
            let name_type = ext_data[pos + 2];
            let name_len = u16::from_be_bytes([ext_data[pos + 3], ext_data[pos + 4]]) as usize;

            if name_type == 0 && pos + 5 + name_len <= ext_data.len() {
                let name = &ext_data[pos + 5..pos + 5 + name_len];
                return String::from_utf8(name.to_vec()).ok();
            }
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_load_doh_ips_from_file() {
        let ip_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doh_ips.txt");
        let domain_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doh_domains.txt");

        if !ip_path.exists() || !domain_path.exists() {
            eprintln!("Skipping test: DoH list files not found. Download them first.");
            return;
        }

        let blocker = DohBlocker::from_files(&ip_path, &domain_path).unwrap();

        assert!(blocker.ip_count() > 100, "Should load many DoH IPs");
        assert!(
            blocker.hostname_count() > 100,
            "Should load many DoH hostnames"
        );

        assert!(blocker.is_doh_ip("8.8.8.8".parse().unwrap()));
        assert!(blocker.is_doh_ip("1.1.1.1".parse().unwrap()));
        assert!(!blocker.is_doh_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_doh_hostname_matching() {
        let ip_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doh_ips.txt");
        let domain_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doh_domains.txt");

        if !ip_path.exists() || !domain_path.exists() {
            return;
        }

        let blocker = DohBlocker::from_files(&ip_path, &domain_path).unwrap();

        assert!(blocker.is_doh_hostname("1dot1dot1dot1.cloudflare-dns.com"));
        assert!(!blocker.is_doh_hostname("example.com"));
    }

    #[test]
    fn test_sni_extraction_from_real_client_hello() {
        let sni_name = b"dns.google";
        let sni_name_len = sni_name.len() as u16;
        let sni_list_len = sni_name_len + 3;
        let sni_ext_len = sni_list_len + 2;

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
        extensions.extend_from_slice(&sni_list_len.to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&sni_name_len.to_be_bytes());
        extensions.extend_from_slice(sni_name);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(&[0u8; 32]);
        ch_body.push(0);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
        ch_body.extend_from_slice(&[0x01, 0x00]);
        ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let ch_len = ch_body.len() as u32;
        handshake.push((ch_len >> 16) as u8);
        handshake.push((ch_len >> 8) as u8);
        handshake.push(ch_len as u8);
        handshake.extend_from_slice(&ch_body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(extract_sni(&record), Some("dns.google".to_string()));
    }

    #[test]
    fn test_sni_extraction_non_tls() {
        assert!(extract_sni(b"GET / HTTP/1.1\r\n").is_none());
        assert!(extract_sni(&[]).is_none());
    }
}
