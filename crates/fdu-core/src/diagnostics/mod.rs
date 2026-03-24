//! Drive diagnostics — health checks, bad sector detection, entropy analysis,
//! fake flash detection, and performance testing.

pub mod bad_sectors;
pub mod entropy;
pub mod fake_flash;

pub use bad_sectors::scan_bad_sectors;
pub use entropy::scan_entropy;
pub use fake_flash::detect_fake_flash;
