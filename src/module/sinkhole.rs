/// DNS Sinkhole — forges NXDOMAIN responses for blocked domains.
///
/// Given a raw IP packet containing a DNS query, this module constructs
/// a response packet with RCODE=NXDOMAIN and writes it back to the TUN device.
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};

use super::packet;

/// Extract IPv4 src/dst/ttl from a parsed packet. Returns None for non-IPv4.
fn extract_ipv4_info(parsed: &PacketHeaders) -> Option<([u8; 4], [u8; 4], u8)> {
    match &parsed.net {
        Some(NetHeaders::Ipv4(h, _)) => Some((h.source, h.destination, h.time_to_live)),
        _ => None,
    }
}

/// Forge an NXDOMAIN response from a raw IP packet containing a DNS query.
///
/// The returned `Vec<u8>` is a complete IP packet ready to write to the TUN device.
/// Returns `None` if the packet cannot be parsed or is not a valid DNS query.
pub fn forge_nxdomain(original_packet: &[u8]) -> Option<Vec<u8>> {
    let parsed = PacketHeaders::from_ip_slice(original_packet).ok()?;

    let (src_ip, dst_ip, ttl) = extract_ipv4_info(&parsed)?;

    let (src_port, dst_port) = match &parsed.transport {
        Some(TransportHeader::Udp(udp)) => (udp.source_port, udp.destination_port),
        _ => return None,
    };

    let dns_payload = parsed.payload.slice();
    if dns_payload.len() < 12 {
        return None;
    }

    let query_id = &dns_payload[0..2];
    let qdcount = &dns_payload[4..6];

    // Find end of question section (after the 12-byte header)
    let mut pos = 12;
    let qd = u16::from_be_bytes([qdcount[0], qdcount[1]]);
    for _ in 0..qd {
        while pos < dns_payload.len() && dns_payload[pos] != 0 {
            let label_len = dns_payload[pos] as usize;
            pos += 1 + label_len;
        }
        pos += 1; // terminating 0x00
        pos += 4; // QTYPE (2) + QCLASS (2)
    }

    if pos > dns_payload.len() {
        return None;
    }

    // Construct DNS response payload
    let mut dns_response = Vec::with_capacity(pos);
    dns_response.extend_from_slice(query_id);
    dns_response.push(0x85); // QR=1, OPCODE=0, AA=1, TC=0, RD=1
    dns_response.push(0x83); // RA=1, Z=0, RCODE=3 (NXDOMAIN)
    dns_response.extend_from_slice(qdcount);
    dns_response.extend_from_slice(&[0, 0]); // ANCOUNT
    dns_response.extend_from_slice(&[0, 0]); // NSCOUNT
    dns_response.extend_from_slice(&[0, 0]); // ARCOUNT
    dns_response.extend_from_slice(&dns_payload[12..pos]);

    // Build UDP header (swapped ports)
    let udp_len = (8 + dns_response.len()) as u16;
    let mut udp_header = [0u8; 8];
    udp_header[0..2].copy_from_slice(&dst_port.to_be_bytes());
    udp_header[2..4].copy_from_slice(&src_port.to_be_bytes());
    udp_header[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // udp_header[6..8] = checksum (0 = disabled for IPv4)

    let total_len = 20 + udp_len as usize + dns_response.len();
    let ip_header = packet::build_ipv4_response_header(
        &src_ip,
        &dst_ip,
        ttl,
        17, // UDP
        20 + udp_len,
    );

    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&ip_header);
    pkt.extend_from_slice(&udp_header);
    pkt.extend_from_slice(&dns_response);

    Some(pkt)
}

/// Forge a TCP RST packet to immediately reject a blocked TCP connection.
///
/// Instead of silently dropping packets (which causes client timeouts),
/// this sends a RST that makes the connection fail instantly.
pub fn forge_tcp_rst(original_packet: &[u8]) -> Option<Vec<u8>> {
    let parsed = PacketHeaders::from_ip_slice(original_packet).ok()?;

    let (src_ip, dst_ip, ttl) = extract_ipv4_info(&parsed)?;

    let (src_port, dst_port, seq_num, ack_num, syn_flag) = match &parsed.transport {
        Some(TransportHeader::Tcp(tcp)) => (
            tcp.source_port,
            tcp.destination_port,
            tcp.sequence_number,
            tcp.acknowledgment_number,
            tcp.syn,
        ),
        _ => return None,
    };

    // If SYN: ACK the SYN (seq+1). Otherwise: ACK existing data.
    let (rst_seq, rst_ack) = if syn_flag {
        (0u32, seq_num.wrapping_add(1))
    } else {
        (
            ack_num,
            seq_num.wrapping_add(parsed.payload.slice().len() as u32),
        )
    };

    // TCP header (20 bytes)
    let mut tcp_header = [0u8; 20];
    tcp_header[0..2].copy_from_slice(&dst_port.to_be_bytes());
    tcp_header[2..4].copy_from_slice(&src_port.to_be_bytes());
    tcp_header[4..8].copy_from_slice(&rst_seq.to_be_bytes());
    tcp_header[8..12].copy_from_slice(&rst_ack.to_be_bytes());
    tcp_header[12] = 0x50; // Data offset = 5 (20 bytes)
    tcp_header[13] = 0x14; // RST + ACK
    // Window, checksum, urgent = 0

    let tcp_cksum = packet::tcp_checksum(&dst_ip, &src_ip, &tcp_header, &[]);
    tcp_header[16] = (tcp_cksum >> 8) as u8;
    tcp_header[17] = (tcp_cksum & 0xff) as u8;

    let ip_header = packet::build_ipv4_response_header(&src_ip, &dst_ip, ttl, 6, 40);

    let mut pkt = Vec::with_capacity(40);
    pkt.extend_from_slice(&ip_header);
    pkt.extend_from_slice(&tcp_header);

    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::packet;
    use super::*;

    fn build_test_dns_query(domain: &str) -> Vec<u8> {
        let src_ip: [u8; 4] = [10, 0, 0, 1];
        let dst_ip: [u8; 4] = [8, 8, 8, 8];

        let mut dns = Vec::new();
        dns.extend_from_slice(&[0xAB, 0xCD]);
        dns.extend_from_slice(&[0x01, 0x00]);
        dns.extend_from_slice(&[0x00, 0x01]);
        dns.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        for label in domain.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0x00);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let udp_len = (8 + dns.len()) as u16;
        let total_len = (20 + 8 + dns.len()) as u16;

        let ip_header = packet::build_ipv4_response_header(&dst_ip, &src_ip, 64, 17, total_len);

        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());

        let mut pkt = Vec::with_capacity(total_len as usize);
        pkt.extend_from_slice(&ip_header);
        pkt.extend_from_slice(&udp);
        pkt.extend_from_slice(&dns);
        pkt
    }

    #[test]
    fn test_forge_nxdomain_returns_valid_packet() {
        let query = build_test_dns_query("ads.example.com");
        let response = forge_nxdomain(&query).expect("Should forge a response");

        assert!(response.len() >= 20 + 8 + 12);
        assert_eq!(&response[12..16], &[8, 8, 8, 8]);
        assert_eq!(&response[16..20], &[10, 0, 0, 1]);

        let udp_src = u16::from_be_bytes([response[20], response[21]]);
        let udp_dst = u16::from_be_bytes([response[22], response[23]]);
        assert_eq!(udp_src, 53);
        assert_eq!(udp_dst, 1234);

        let dns_offset = 28;
        assert_eq!(&response[dns_offset..dns_offset + 2], &[0xAB, 0xCD]);
        assert_eq!(response[dns_offset + 2] & 0x80, 0x80);
        assert_eq!(response[dns_offset + 3] & 0x0F, 0x03);
    }

    #[test]
    fn test_forge_nxdomain_with_short_packet() {
        assert!(forge_nxdomain(&[0u8; 10]).is_none());
    }
}
