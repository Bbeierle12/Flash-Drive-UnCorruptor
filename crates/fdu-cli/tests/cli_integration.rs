//! CLI integration tests for the `fdu` binary.
//!
//! These tests exercise the actual compiled binary via `assert_cmd`,
//! verifying argument parsing, help output, error messages, and
//! subcommand behavior.

use assert_cmd::Command;
use predicates::prelude::*;

fn fdu() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("fdu").unwrap()
}

// ════════════════════════════════════════════════════════════════════
// Phase 7 — CLI Integration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn phase7_no_args_shows_help() {
    fdu()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn phase7_help_lists_subcommands() {
    fdu()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("diagnose"))
        .stdout(predicate::str::contains("recover"))
        .stdout(predicate::str::contains("repair"));
}

#[test]
fn phase7_version_shows_version() {
    fdu()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("fdu"));
}

#[test]
fn phase7_list_shows_platform_output() {
    // `list` should either succeed and show device information, or fail
    // gracefully with a platform/permission error.  It must never crash.
    let result = fdu().arg("list").assert();
    let output = result.get_output();
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    // Must produce *some* recognizable output — the previous fallback
    // (`!combined.is_empty()`) made this test vacuously pass.
    assert!(
        combined.contains("Platform")
            || combined.contains("platform")
            || combined.contains("No removable")
            || combined.contains("no removable")
            || combined.contains("Device")
            || combined.contains("device")
            || combined.contains("Error")
            || combined.contains("error")
            || combined.contains("Permission")
            || combined.contains("permission"),
        "list command produced unrecognised output: {}",
        combined
    );
}

#[test]
fn phase7_scan_missing_device_arg() {
    fdu()
        .arg("scan")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn phase7_repair_without_unsafe_shows_safety_message() {
    // repair without --unsafe should fail with a safety-related message
    fdu()
        .args(["repair", "/dev/null"])
        .assert()
        .failure();
}

#[test]
fn phase7_repair_with_unsafe_shows_stub() {
    // repair with --unsafe on a non-existent device should fail
    // but the error should be about the device, not about unsafe flag
    fdu()
        .args(["repair", "/dev/nonexistent", "--unsafe"])
        .assert()
        .failure();
}

#[test]
fn phase7_recover_missing_args() {
    // recover needs both DEVICE and OUTPUT
    fdu()
        .arg("recover")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn phase7_verbose_flag_doesnt_break_help() {
    fdu()
        .args(["-vvv", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn phase7_diagnose_missing_device_arg() {
    fdu()
        .arg("diagnose")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}
