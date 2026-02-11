//! Application-wide constants.

// --- TUN Device ---
pub const TUN_DEVICE_NAME: &str = "mosin0";
pub const TUN_ADDRESS: &str = "10.0.0.1";
pub const TUN_NETMASK: (u8, u8, u8, u8) = (255, 255, 255, 0);
pub const TUN_DESTINATION: &str = "10.0.0.2";
pub const PACKET_BUFFER_SIZE: usize = 4096;

// --- Ports ---
pub const DNS_PORT: u16 = 53;
pub const HTTPS_PORT: u16 = 443;

// --- DoH Blocklist URLs ---
pub const DOH_IPS_URL: &str =
    "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt";
pub const DOH_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt";

// --- Default File Paths ---
pub const DEFAULT_DOH_IPS_FILE: &str = "lists/doh_ips.txt";
pub const DEFAULT_DOH_DOMAINS_FILE: &str = "lists/doh_domains.txt";

// --- Recommended Blocklist URLs (for reference / future auto-download) ---
#[allow(dead_code)]
pub const BLOCKLIST_STEVEN_BLACK: &str =
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
#[allow(dead_code)]
pub const BLOCKLIST_OISD_BIG: &str = "https://big.oisd.nl/";
#[allow(dead_code)]
pub const BLOCKLIST_HAGEZI_PRO: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt";
