/// Integration tests for the mosin ad blocker.
///
/// Tests the public API of each module and cross-module interactions.
use std::path::PathBuf;

/// Helper: path to test fixtures relative to CARGO_MANIFEST_DIR.
fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

mod blocklist_integration {
    use super::*;

    #[test]
    fn test_load_steven_black_hosts_file() {
        let path = fixture_path("blocklist.txt");
        if !path.exists() {
            eprintln!("Skipping: blocklist.txt not found (download Steven Black first)");
            return;
        }

        let mut bl = mosin::module::blocklist::Blocklist::new();
        let count = bl.load_domain_file(&path).unwrap();

        // Steven Black has ~79k domains
        assert!(count > 50_000, "Expected 50k+ domains, got {}", count);

        // Well-known ad domains should be blocked
        assert!(bl.is_domain_blocked("adservice.google.com"));
        assert!(bl.is_domain_blocked("pagead2.googlesyndication.com"));

        // Normal domains should NOT be blocked
        assert!(!bl.is_domain_blocked("google.com"));
        assert!(!bl.is_domain_blocked("github.com"));
        assert!(!bl.is_domain_blocked("rust-lang.org"));
    }

    #[test]
    fn test_load_small_test_blocklist() {
        let path = fixture_path("test_blocklist_small.txt");
        let mut bl = mosin::module::blocklist::Blocklist::new();
        let count = bl.load_domain_file(&path).unwrap();

        assert_eq!(count, 10, "Small test list should have 10 domains");

        // Exact matches
        assert!(bl.is_domain_blocked("ads.example.com"));
        assert!(bl.is_domain_blocked("doubleclick.net"));
        assert!(bl.is_domain_blocked("analytics.google.com"));

        // Subdomain of blocked domain should also be blocked
        assert!(bl.is_domain_blocked("sub.doubleclick.net"));
        assert!(bl.is_domain_blocked("deep.sub.ads.example.com"));

        // Unrelated should pass
        assert!(!bl.is_domain_blocked("example.com"));
        assert!(!bl.is_domain_blocked("google.com"));
    }

    #[test]
    fn test_multiple_blocklist_files() {
        let small = fixture_path("test_blocklist_small.txt");
        let mut bl = mosin::module::blocklist::Blocklist::new();

        let count1 = bl.load_domain_file(&small).unwrap();
        assert_eq!(count1, 10);

        // Loading same file again should add (deduplicated by trie structure)
        let count2 = bl.load_domain_file(&small).unwrap();
        assert_eq!(count2, 10);

        // Both loads should work
        assert!(bl.is_domain_blocked("ads.example.com"));
    }
}

mod sinkhole_integration {
    #[test]
    fn test_nxdomain_round_trip() {
        // Build a DNS query, forge NXDOMAIN, verify the response is parseable
        let domain = "ads.example.com";

        // Build DNS query packet (IP/UDP/DNS)
        let query = build_dns_query(domain, [10, 0, 0, 1], [8, 8, 8, 8], 1234, 53);
        let response =
            mosin::module::sinkhole::forge_nxdomain(&query).expect("Should forge NXDOMAIN");

        // Verify IP layer: addresses swapped
        assert_eq!(&response[12..16], &[8, 8, 8, 8]); // src = original dst
        assert_eq!(&response[16..20], &[10, 0, 0, 1]); // dst = original src

        // Verify UDP layer: ports swapped
        let src_port = u16::from_be_bytes([response[20], response[21]]);
        let dst_port = u16::from_be_bytes([response[22], response[23]]);
        assert_eq!(src_port, 53);
        assert_eq!(dst_port, 1234);

        // Verify DNS layer: RCODE = NXDOMAIN (3)
        let dns_start = 28;
        let rcode = response[dns_start + 3] & 0x0F;
        assert_eq!(rcode, 3, "RCODE should be NXDOMAIN (3)");

        // QR bit should be 1 (response)
        assert_eq!(response[dns_start + 2] & 0x80, 0x80, "QR should be 1");
    }

    #[test]
    fn test_tcp_rst_round_trip() {
        // Build a TCP SYN packet, forge RST, verify response
        let syn = build_tcp_syn([10, 0, 0, 1], [1, 2, 3, 4], 54321, 443, 1000);
        let rst = mosin::module::sinkhole::forge_tcp_rst(&syn).expect("Should forge RST");

        // IP: addresses swapped
        assert_eq!(&rst[12..16], &[1, 2, 3, 4]); // src = original dst
        assert_eq!(&rst[16..20], &[10, 0, 0, 1]); // dst = original src

        // TCP: ports swapped
        let src_port = u16::from_be_bytes([rst[20], rst[21]]);
        let dst_port = u16::from_be_bytes([rst[22], rst[23]]);
        assert_eq!(src_port, 443);
        assert_eq!(dst_port, 54321);

        // RST flag (bit 2) should be set
        let flags = rst[33]; // TCP flags byte
        assert_eq!(flags & 0x04, 0x04, "RST flag should be set");

        // ACK flag should also be set (RST+ACK)
        assert_eq!(flags & 0x10, 0x10, "ACK flag should be set");

        // ACK number should be SYN seq + 1
        let ack_num = u32::from_be_bytes([rst[28], rst[29], rst[30], rst[31]]);
        assert_eq!(ack_num, 1001, "ACK should be SYN seq + 1");
    }

    /// Build a minimal DNS query packet for testing.
    fn build_dns_query(
        domain: &str,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&[0xAB, 0xCD]); // ID
        dns.extend_from_slice(&[0x01, 0x00]); // Flags
        dns.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        dns.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR
        for label in domain.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0x00);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

        let udp_len = (8 + dns.len()) as u16;
        let total_len = (20 + 8 + dns.len()) as u16;

        let mut pkt = Vec::new();
        // IP header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0; 2]); // ID
        pkt.extend_from_slice(&[0x40, 0x00]); // Flags
        pkt.push(64); // TTL
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0, 0]); // Checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // IP checksum
        let cksum = ip_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xff) as u8;
        // UDP header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // Checksum
        pkt.extend_from_slice(&dns);
        pkt
    }

    /// Build a minimal TCP SYN packet for testing.
    fn build_tcp_syn(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        let total_len: u16 = 40; // 20 IP + 20 TCP
        let mut pkt = Vec::new();
        // IP header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[0x40, 0x00]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        let cksum = ip_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xff) as u8;
        // TCP header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes()); // Seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // Ack
        pkt.push(0x50); // Data offset = 5
        pkt.push(0x02); // SYN flag
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // Window
        pkt.extend_from_slice(&[0, 0]); // Checksum
        pkt.extend_from_slice(&[0, 0]); // Urgent
        pkt
    }

    fn ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i < header.len() - 1 {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

mod doh_integration {
    use super::*;

    #[test]
    fn test_doh_blocker_full_pipeline() {
        let ip_path = fixture_path("doh_ips.txt");
        let domain_path = fixture_path("doh_domains.txt");

        if !ip_path.exists() || !domain_path.exists() {
            eprintln!("Skipping: DoH list files not found");
            return;
        }

        let blocker = mosin::module::doh::DohBlocker::from_files(&ip_path, &domain_path).unwrap();

        // Should have loaded substantial lists
        assert!(blocker.ip_count() > 2000);
        assert!(blocker.hostname_count() > 1000);

        // Major DoH providers must be blocked
        assert!(blocker.is_doh_ip("8.8.8.8".parse().unwrap()));
        assert!(blocker.is_doh_ip("1.1.1.1".parse().unwrap()));
        assert!(blocker.is_doh_ip("9.9.9.9".parse().unwrap()));

        // Private IPs should not be blocked
        assert!(!blocker.is_doh_ip("192.168.1.1".parse().unwrap()));
        assert!(!blocker.is_doh_ip("10.0.0.1".parse().unwrap()));
    }
}
