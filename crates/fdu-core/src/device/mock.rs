//! Mock device for testing — backed by an in-memory buffer.

use crate::device::traits::Device;
use crate::errors::{Error, Result};
use crate::models::FsType;
use std::collections::HashSet;

/// An in-memory device for unit testing.
///
/// Supports injecting bad sectors that will return I/O errors on read,
/// and records all write operations for test assertions.
pub struct MockDevice {
    id: String,
    name: String,
    data: Vec<u8>,
    fs_type: Option<FsType>,
    writable: bool,
    bad_sectors: HashSet<u64>,
    sector_size: u32,
}

impl MockDevice {
    /// Create a new mock device filled with zeros.
    pub fn new(size: usize) -> Self {
        Self {
            id: "mock://test".into(),
            name: "Mock Device".into(),
            data: vec![0u8; size],
            fs_type: None,
            writable: true,
            bad_sectors: HashSet::new(),
            sector_size: 512,
        }
    }

    /// Create a mock device from existing data (e.g., a disk image loaded into memory).
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            id: "mock://test".into(),
            name: "Mock Device".into(),
            fs_type: None,
            writable: true,
            bad_sectors: HashSet::new(),
            sector_size: 512,
            data,
        }
    }

    /// Set the device identifier.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set the device name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the filesystem type.
    pub fn with_fs_type(mut self, fs_type: FsType) -> Self {
        self.fs_type = Some(fs_type);
        self
    }

    /// Make the device read-only.
    pub fn read_only(mut self) -> Self {
        self.writable = false;
        self
    }

    /// Inject a bad sector — reads at this sector will return an error.
    pub fn with_bad_sector(mut self, sector: u64) -> Self {
        self.bad_sectors.insert(sector);
        self
    }

    /// Write raw data into the mock device at a given offset.
    /// This is for test setup — does not check writable flag.
    pub fn set_data(&mut self, offset: usize, data: &[u8]) {
        let end = (offset + data.len()).min(self.data.len());
        self.data[offset..end].copy_from_slice(&data[..end - offset]);
    }

    /// Get the underlying data buffer (for test assertions).
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Device for MockDevice {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn fs_type(&self) -> Option<FsType> {
        self.fs_type
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }

        // Check for bad sectors
        let ss = self.sector_size as u64;
        let start_sector = offset as u64 / ss;
        let end_sector = (offset as u64 + buf.len() as u64).saturating_sub(1) / ss;
        for sector in start_sector..=end_sector {
            if self.bad_sectors.contains(&sector) {
                return Err(Error::BadSector {
                    offset: sector * ss,
                    sector,
                });
            }
        }

        let available = self.data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(Error::PermissionDenied);
        }

        let offset = offset as usize;
        if offset >= self.data.len() {
            return Err(Error::OutOfBounds {
                offset: offset as u64,
                requested: buf.len(),
                device_size: self.data.len() as u64,
            });
        }

        let available = self.data.len() - offset;
        let to_write = buf.len().min(available);
        self.data[offset..offset + to_write].copy_from_slice(&buf[..to_write]);
        Ok(to_write)
    }

    fn is_writable(&self) -> bool {
        self.writable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::traits::DeviceExt;

    #[test]
    fn test_mock_read_write() {
        let mut dev = MockDevice::new(4096);
        let data = b"Hello, flash drive!";
        dev.write_at(0, data).unwrap();

        let mut buf = vec![0u8; data.len()];
        dev.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_mock_read_only() {
        let mut dev = MockDevice::new(4096).read_only();
        let result = dev.write_at(0, b"test");
        assert!(matches!(result, Err(Error::PermissionDenied)));
    }

    #[test]
    fn test_mock_bad_sector() {
        let dev = MockDevice::new(4096).with_bad_sector(2);

        // Sector 0 should work fine
        let mut buf = vec![0u8; 512];
        assert!(dev.read_at(0, &mut buf).is_ok());

        // Sector 2 (offset 1024) should fail
        assert!(matches!(
            dev.read_at(1024, &mut buf),
            Err(Error::BadSector { sector: 2, .. })
        ));
    }

    #[test]
    fn test_read_sector() {
        let mut dev = MockDevice::new(4096);
        dev.set_data(512, &[0xAA; 512]); // Fill sector 1 with 0xAA

        let sector = dev.read_sector(1).unwrap();
        assert_eq!(sector.len(), 512);
        assert!(sector.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_sector_count() {
        let dev = MockDevice::new(4096);
        assert_eq!(dev.sector_count(), 8);
    }

    #[test]
    fn test_read_beyond_end() {
        let dev = MockDevice::new(1024);
        let result = dev.read_exact_at(512, 1024);
        assert!(result.is_err());
    }
}
