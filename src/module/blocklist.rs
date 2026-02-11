use std::collections::HashMap;
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::Path;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// Reverse-label trie for efficient domain matching with wildcard subdomain support.
///
/// Domains are stored by reversing their labels: `ads.google.com` → `com.google.ads`.
/// Blocking `google.com` automatically blocks all subdomains (e.g. `ads.google.com`).
#[derive(Debug)]
pub struct DomainTrie {
    children: HashMap<String, DomainTrie>,
    is_blocked: bool,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_blocked: false,
        }
    }

    /// Insert a domain into the trie as blocked.
    /// Labels are reversed so `ads.google.com` becomes the path `com` → `google` → `ads`.
    pub fn insert(&mut self, domain: &str) {
        let labels: Vec<&str> = domain.rsplit('.').collect();
        let mut node = self;

        for label in labels {
            node = node.children.entry(label.to_lowercase()).or_default();
        }
        node.is_blocked = true;
    }

    /// Check if a domain (or any of its parent domains) is blocked.
    /// For example, if `google.com` is blocked, then `ads.google.com` returns true.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let labels: Vec<&str> = domain.rsplit('.').collect();
        let mut node = self;

        for label in labels {
            if node.is_blocked {
                return true;
            }
            match node.children.get(&label.to_lowercase()) {
                Some(child) => node = child,
                None => return false,
            }
        }
        node.is_blocked
    }

    /// Returns the total number of blocked entries in the trie.
    pub fn len(&self) -> usize {
        let mut count = if self.is_blocked { 1 } else { 0 };
        for child in self.children.values() {
            count += child.len();
        }
        count
    }

    /// Returns true if the trie contains no blocked entries.
    pub fn is_empty(&self) -> bool {
        !self.is_blocked && self.children.values().all(|c| c.is_empty())
    }
}

impl Default for DomainTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined blocklist holding both domain and IP blocklists.
pub struct Blocklist {
    pub domains: DomainTrie,
    pub ips: IpNetworkTable<()>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            domains: DomainTrie::new(),
            ips: IpNetworkTable::new(),
        }
    }

    /// Load a domain blocklist file. Auto-detects format:
    /// - Hosts-file format: `0.0.0.0 ads.example.com` or `127.0.0.1 ads.example.com`
    /// - Domains-only format: `ads.example.com` (one per line)
    ///
    /// Skips comments (`#`, `!`), blank lines, and localhost entries.
    /// Uses BufRead to stream lines instead of loading the entire file into memory.
    pub fn load_domain_file(&mut self, path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let reader = io::BufReader::new(std::fs::File::open(path)?);
        let mut count = 0;

        for line in reader.lines() {
            let raw = line?;
            let line = raw.trim();

            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            let domain = if let Some(rest) = line.strip_prefix("0.0.0.0 ") {
                rest.trim()
            } else if let Some(rest) = line.strip_prefix("127.0.0.1 ") {
                rest.trim()
            } else if line.contains(' ') || line.contains('\t') {
                continue;
            } else {
                line
            };

            // Strip inline comments
            let domain = domain.split('#').next().unwrap_or("").trim();

            // Skip empty, localhost, and broadcast entries
            if domain.is_empty()
                || domain == "localhost"
                || domain == "localhost.localdomain"
                || domain == "local"
                || domain == "broadcasthost"
                || domain == "0.0.0.0"
                || domain.starts_with("ip6-")
            {
                continue;
            }

            self.domains.insert(domain);
            count += 1;
        }

        Ok(count)
    }

    /// Load an IP/CIDR blocklist file. One entry per line.
    /// Supports both individual IPs (`1.2.3.4`) and CIDR ranges (`1.2.3.0/24`).
    /// Uses BufRead to stream lines.
    pub fn load_ip_file(&mut self, path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
        let reader = io::BufReader::new(std::fs::File::open(path)?);
        let mut count = 0;

        for line in reader.lines() {
            let raw = line?;
            let line = raw.trim();

            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            // Try CIDR first (e.g. "1.2.3.0/24"), then bare IP (e.g. "1.2.3.4")
            let network = if let Ok(n) = line.parse::<IpNetwork>() {
                n
            } else if let Ok(ip) = line.parse::<IpAddr>() {
                IpNetwork::from(ip)
            } else {
                continue;
            };
            self.ips.insert(network, ());
            count += 1;
        }

        Ok(count)
    }

    /// Check if a domain is blocked.
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        self.domains.is_blocked(domain)
    }

    /// Check if an IP address is blocked (longest-prefix match in radix tree).
    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        self.ips.longest_match(ip).is_some()
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_domain_trie_exact_match() {
        let mut trie = DomainTrie::new();
        trie.insert("doubleclick.net");

        assert!(trie.is_blocked("doubleclick.net"));
        assert!(!trie.is_blocked("example.com"));
    }

    #[test]
    fn test_domain_trie_wildcard_subdomain() {
        let mut trie = DomainTrie::new();
        trie.insert("doubleclick.net");

        assert!(trie.is_blocked("ad.doubleclick.net"));
        assert!(trie.is_blocked("deep.sub.doubleclick.net"));
    }

    #[test]
    fn test_domain_trie_no_false_positive() {
        let mut trie = DomainTrie::new();
        trie.insert("ads.example.com");

        assert!(!trie.is_blocked("example.com"));
        assert!(!trie.is_blocked("google.com"));
    }

    #[test]
    fn test_domain_trie_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("ADS.Example.COM");

        assert!(trie.is_blocked("ads.example.com"));
        assert!(trie.is_blocked("ADS.EXAMPLE.COM"));
    }

    #[test]
    fn test_load_hosts_file() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/test_blocklist_small.txt");
        let mut blocklist = Blocklist::new();
        let count = blocklist.load_domain_file(&path).unwrap();

        assert!(count > 0);
        assert!(blocklist.is_domain_blocked("ads.example.com"));
        assert!(blocklist.is_domain_blocked("doubleclick.net"));
        assert!(blocklist.is_domain_blocked("ad.doubleclick.net"));
        assert!(!blocklist.is_domain_blocked("google.com"));
    }

    #[test]
    fn test_ip_blocking() {
        let mut blocklist = Blocklist::new();
        let network: IpNetwork = "1.2.3.0/24".parse().unwrap();
        blocklist.ips.insert(network, ());

        assert!(blocklist.is_ip_blocked("1.2.3.4".parse().unwrap()));
        assert!(blocklist.is_ip_blocked("1.2.3.255".parse().unwrap()));
        assert!(!blocklist.is_ip_blocked("1.2.4.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_blocking_single_ip() {
        let mut blocklist = Blocklist::new();
        let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let network = IpNetwork::from(ip);
        blocklist.ips.insert(network, ());

        assert!(blocklist.is_ip_blocked("8.8.8.8".parse().unwrap()));
        assert!(!blocklist.is_ip_blocked("8.8.8.9".parse().unwrap()));
    }
}
