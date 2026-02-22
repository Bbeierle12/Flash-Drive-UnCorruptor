//! `fdu extract <device> <output>` — quarantine-based file extraction.

use anyhow::{Context, Result};
use colored::Colorize;
use fdu_models::ExtractionPolicy;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;

pub fn run(device: &str, output: &str, policy_str: &str, json: bool) -> Result<()> {
    let dev = crate::commands::scan::open_device(device)?;

    let policy = ExtractionPolicy::from_str_loose(policy_str)
        .context(format!(
            "Unknown policy: '{}'. Use: verified-only, include-suspicious, forensic-full",
            policy_str
        ))?;

    let output_dir = Path::new(output);

    if !json {
        println!(
            "{} {} {} → {}",
            "Quarantine Extraction".bold().green(),
            "→".dimmed(),
            device.bold(),
            output.bold()
        );
        println!("  Policy: {}", policy);
        println!();
    }

    let pb = if !json {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        Some(pb)
    } else {
        None
    };

    let progress_cb: Option<Box<dyn Fn(fdu_models::ExtractionProgress) + Send>> =
        if let Some(ref pb) = pb {
            let pb = pb.clone();
            Some(Box::new(move |prog| {
                pb.set_message(format!(
                    "Extracting {}/{}: {}",
                    prog.files_processed, prog.files_total, prog.current_file
                ));
            }))
        } else {
            None
        };

    let manifest = fdu_extract::extract(&*dev, policy, output_dir, progress_cb)
        .context("Extraction failed")?;

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        println!(
            "  {} {} file(s) extracted ({} total)",
            "✓".green(),
            manifest.files.len(),
            fdu_core::models::format_bytes(manifest.total_bytes()),
        );

        if manifest.flagged_count() > 0 {
            println!(
                "  {} {} file(s) had security findings",
                "⚠".yellow(),
                manifest.flagged_count(),
            );
        }

        println!("  Manifest: {}", output_dir.join("extraction_manifest.json").display());
    }

    Ok(())
}
