//! Flash Drive UnCorruptor — CLI entry point.
//!
//! Usage:
//!   fdu list [--json]
//!   fdu scan <DEVICE> [--deep] [--json]
//!   fdu diagnose <DEVICE> [--bad-sectors] [--json]
//!   fdu recover <DEVICE> <OUTPUT> [--strategy both] [--file-types jpg,pdf]
//!   fdu repair <DEVICE> --unsafe [--fix-fat] [--backup-first]
//!   fdu web [--port 3000]

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fdu",
    version,
    about = "Flash Drive UnCorruptor — First aid toolkit for flash drives",
    long_about = "Diagnose, recover, and repair corrupted USB flash drives.\n\n\
                  Supports FAT32, exFAT, NTFS, ext4, and HFS+ filesystems.\n\
                  Run 'fdu list' to see connected drives, then use scan/diagnose/recover."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging (use -vv for debug, -vvv for trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// List all connected removable drives
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Include non-removable drives
        #[arg(long)]
        include_internal: bool,
    },

    /// Scan a device for filesystem integrity issues
    Scan {
        /// Device path (e.g., /dev/sdb1) or disk image file
        device: String,

        /// Perform a deep cluster-level scan (slower but more thorough)
        #[arg(long)]
        deep: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run diagnostics on a device (bad sectors, read speed, health)
    Diagnose {
        /// Device path or disk image file
        device: String,

        /// Test all sectors for readability (can be slow on large drives)
        #[arg(long)]
        bad_sectors: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Attempt to recover deleted files from a device
    Recover {
        /// Device path or disk image file
        device: String,

        /// Directory to save recovered files
        output: String,

        /// Recovery strategy
        #[arg(long, default_value = "both")]
        strategy: String,

        /// Only recover specific file types (comma-separated, e.g., "jpg,pdf,zip")
        #[arg(long)]
        file_types: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Repair filesystem issues (DESTRUCTIVE — requires --unsafe)
    Repair {
        /// Device path
        device: String,

        /// Required flag to enable destructive write operations
        #[arg(long, name = "unsafe")]
        unsafe_mode: bool,

        /// Rebuild the FAT allocation table
        #[arg(long)]
        fix_fat: bool,

        /// Remove bad cluster chains
        #[arg(long)]
        remove_bad_chains: bool,

        /// Create a backup before making changes (default: true)
        #[arg(long, default_value = "true")]
        backup_first: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup logging based on verbosity
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .init();

    match cli.command {
        Commands::List {
            json,
            include_internal,
        } => commands::list::run(json, include_internal),

        Commands::Scan { device, deep, json } => commands::scan::run(&device, deep, json),

        Commands::Diagnose {
            device,
            bad_sectors,
            json,
        } => commands::diagnose::run(&device, bad_sectors, json),

        Commands::Recover {
            device,
            output,
            strategy,
            file_types,
            json,
        } => commands::recover::run(&device, &output, &strategy, file_types, json),

        Commands::Repair {
            device,
            unsafe_mode,
            fix_fat,
            remove_bad_chains,
            backup_first,
        } => commands::repair::run(
            &device,
            unsafe_mode,
            fix_fat,
            remove_bad_chains,
            backup_first,
        ),
    }
}
