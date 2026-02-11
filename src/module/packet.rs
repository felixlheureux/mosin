//! Shared packet-building utilities for IP/UDP/TCP headers and checksums.
//!
//! Used by both `sinkhole.rs` (NXDOMAIN, TCP RST) and test helpers.

/// Compute the IPv4 header checksum (RFC 1071).
pub fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        i += 2;
    }
    if !header.len().is_multiple_of(2) {
        sum += u32::from(header[header.len() - 1]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute TCP checksum with pseudo-header (RFC 793).
pub fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_header: &[u8], payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u32::from(u16::from_be_bytes([src_ip[0], src_ip[1]]));
    sum += u32::from(u16::from_be_bytes([src_ip[2], src_ip[3]]));
    sum += u32::from(u16::from_be_bytes([dst_ip[0], dst_ip[1]]));
    sum += u32::from(u16::from_be_bytes([dst_ip[2], dst_ip[3]]));
    sum += 6u32; // Protocol: TCP
    sum += (tcp_header.len() + payload.len()) as u32;

    // TCP header + payload
    let mut i = 0;
    while i + 1 < tcp_header.len() {
        sum += u32::from(u16::from_be_bytes([tcp_header[i], tcp_header[i + 1]]));
        i += 2;
    }
    // Handle odd tcp_header length
    let tcp_odd = !tcp_header.len().is_multiple_of(2);
    if tcp_odd && !payload.is_empty() {
        sum += u32::from(u16::from_be_bytes([
            tcp_header[tcp_header.len() - 1],
            payload[0],
        ]));
        i = 1;
    } else if tcp_odd {
        sum += u32::from(tcp_header[tcp_header.len() - 1]) << 8;
        i = 0;
    } else {
        i = 0;
    }
    while i + 1 < payload.len() {
        sum += u32::from(u16::from_be_bytes([payload[i], payload[i + 1]]));
        i += 2;
    }
    if i < payload.len() {
        sum += u32::from(payload[payload.len() - 1]) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a raw IPv4 header (20 bytes) with swapped src/dst from original.
/// Returns the header with a valid checksum.
pub fn build_ipv4_response_header(
    original_src: &[u8; 4],
    original_dst: &[u8; 4],
    ttl: u8,
    protocol: u8,
    total_len: u16,
) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // Version=4, IHL=5
    // h[1] = 0x00; DSCP+ECN (already zero)
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    // h[4..6] = identification (zero)
    h[6] = 0x40; // Don't Fragment
    // h[7] = 0x00; Fragment offset
    h[8] = ttl;
    h[9] = protocol;
    // h[10..12] = checksum placeholder (zero)
    h[12..16].copy_from_slice(original_dst); // src ← original dst
    h[16..20].copy_from_slice(original_src); // dst ← original src

    let cksum = ip_checksum(&h);
    h[10] = (cksum >> 8) as u8;
    h[11] = (cksum & 0xff) as u8;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_checksum_known_value() {
        // Known good IPv4 header from RFC 1071 example
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[8] = 64; // TTL
        header[9] = 17; // UDP
        header[2..4].copy_from_slice(&40u16.to_be_bytes());
        header[12..16].copy_from_slice(&[10, 0, 0, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let cksum = ip_checksum(&header);

        // Verify: checksum of header with valid checksum should be 0
        header[10] = (cksum >> 8) as u8;
        header[11] = (cksum & 0xff) as u8;
        assert_eq!(ip_checksum(&header), 0);
    }
}
