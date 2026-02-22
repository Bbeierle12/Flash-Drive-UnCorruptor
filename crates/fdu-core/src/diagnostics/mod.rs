//! Drive diagnostics — health checks, bad sector detection, performance testing.

pub mod bad_sectors;

pub use bad_sectors::scan_bad_sectors;
