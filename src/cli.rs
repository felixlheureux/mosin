use crate::constants;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mosin", about = "mosin — system-wide ad blocker")]
#[command(version = "0.2.0", author = "Felix Lheureux <felix.lheureux@pm.me>")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the ad blocker
    Start {
        /// Domain blocklist file (hosts-file or domains-only format), repeatable
        #[arg(long, short = 'b', action = clap::ArgAction::Append)]
        blocklist: Vec<String>,

        /// IP/CIDR blocklist file (one entry per line), repeatable
        #[arg(long, short = 'I', action = clap::ArgAction::Append)]
        ip_blocklist: Vec<String>,

        /// Block known DoH providers to prevent DNS bypass
        #[arg(long)]
        block_doh: bool,

        /// DoH resolver IP blocklist file (one IP per line)
        #[arg(long, default_value = constants::DEFAULT_DOH_IPS_FILE)]
        doh_ips: String,

        /// DoH hostname blocklist file (one domain per line)
        #[arg(long, default_value = constants::DEFAULT_DOH_DOMAINS_FILE)]
        doh_domains: String,

        /// Enable verbose logging
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Suppress all output except errors
        #[arg(long, short = 'q')]
        quiet: bool,
    },

    /// Show status (placeholder for future use)
    Status,

    /// Stop the ad blocker (placeholder for future use)
    Stop,
}
