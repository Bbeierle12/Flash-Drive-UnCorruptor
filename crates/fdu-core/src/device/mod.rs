//! Device abstraction layer.
//!
//! Provides a platform-independent interface for reading raw bytes from
//! block devices (USB drives, SD cards, etc.) and a mock implementation
//! for testing.

pub mod mock;
pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux;

pub use mock::MockDevice;
pub use traits::Device;
