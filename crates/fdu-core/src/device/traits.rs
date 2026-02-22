//! Device trait — the core abstraction for reading/writing raw block devices.

use crate::errors::Result;
use crate::models::FsType;

/// A raw block device that can be read from and optionally written to.
///
/// Implementations exist for each platform (Linux, macOS, Windows) and
/// for testing via `MockDevice`.
pub trait Device: Send + Sync {
    /// System identifier (e.g., "/dev/sda1", "\\\\.\\PhysicalDrive1")
    fn id(&self) -> &str;

    /// Human-readable device name or model string.
    fn name(&self) -> &str;

    /// Total device size in bytes.
    fn size(&self) -> u64;

    /// Sector size in bytes (typically 512).
    fn sector_size(&self) -> u32 {
        512
    }

    /// Detected or cached filesystem type.
    fn fs_type(&self) -> Option<FsType>;

    /// Read raw bytes starting at `offset` into `buf`.
    /// Returns the number of bytes actually read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write raw bytes starting at `offset` from `buf`.
    /// Returns the number of bytes actually written.
    ///
    /// # Errors
    /// Returns `Error::PermissionDenied` if the device is opened read-only.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize>;

    /// Whether this device is open for writing.
    fn is_writable(&self) -> bool;
}

/// Extension trait for convenient device reading.
pub trait DeviceExt: Device {
    /// Read exactly `len` bytes from `offset`, or error.
    fn read_exact_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_at(offset, &mut buf)?;
        if n < len {
            return Err(crate::errors::Error::OutOfBounds {
                offset,
                requested: len,
                device_size: self.size(),
            });
        }
        Ok(buf)
    }

    /// Read one sector at the given sector number.
    fn read_sector(&self, sector: u64) -> Result<Vec<u8>> {
        let ss = self.sector_size() as u64;
        self.read_exact_at(sector * ss, ss as usize)
    }

    /// Total number of sectors on this device.
    fn sector_count(&self) -> u64 {
        self.size() / self.sector_size() as u64
    }
}

// Blanket implementation for all Device implementors.
impl<T: Device + ?Sized> DeviceExt for T {}
