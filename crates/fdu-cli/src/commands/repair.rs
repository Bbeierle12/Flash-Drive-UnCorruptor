//! `fdu repair` — repair filesystem issues (destructive, requires --unsafe).

pub fn run(
    device_path: &str,
    unsafe_mode: bool,
    _fix_fat: bool,
    _remove_bad_chains: bool,
    _backup_first: bool,
) -> anyhow::Result<()> {
    // Regardless of --unsafe, repair is not yet implemented
    anyhow::bail!(
        "The 'repair' command is not yet implemented (planned for Phase 4).\n\n\
         To assess drive health, use:\n\
         \x20 fdu scan {}\n\
         \x20 fdu diagnose {}\n\n\
         --unsafe flag was {}: {}",
        device_path,
        device_path,
        if unsafe_mode { "provided" } else { "not provided" },
        if unsafe_mode {
            "acknowledged, but no repair operations are available yet."
        } else {
            "will be required once repair is implemented."
        },
    );
}
